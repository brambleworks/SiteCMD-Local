//! Web-scan orchestration for fetch, checks, browser analysis, and scoring.

use crate::checks::{accessibility, compliance, config, performance, predeploy, security, seo};
use crate::checks::{
    AsyncCheck, Check, CheckContext, CheckResult, CheckStatus, ScanCategory, Severity,
};
use crate::core::localhost;
use crate::scoring::calculator;
use std::future::Future;

use crate::constants::{BODY_READ_TIMEOUT, MAX_BODY_SIZE};

mod finalize;
mod phases;
mod site_facts;
mod types;
pub mod verify;
mod webview_results;

pub use finalize::finalize_check_results;
use phases::{run_async_checks, run_sync_checks};
pub use types::{
    MultiScanProgress, MultiScanResult, PageScanSummary, ProgressFn, ScanError, ScanProgress,
    ScanResult, ScanType, ScheduledScanType, VerifyChecksResult,
};
pub use verify::verify_checks;
pub use webview_results::append_webview_results;

fn ensure_not_cancelled<C>(cancel_check: Option<&C>) -> Result<(), ScanError>
where
    C: Fn() -> bool + ?Sized,
{
    if cancel_check.is_some_and(|check| check()) {
        Err(ScanError::Cancelled)
    } else {
        Ok(())
    }
}

fn detector_crash_error(check_id: &str) -> ScanError {
    ScanError::ScanFailed(format!(
        "Web check '{}' crashed; scan aborted to avoid reporting incomplete results",
        check_id
    ))
}

async fn wait_for_cancellation<C>(cancel_check: &C)
where
    C: Fn() -> bool + ?Sized,
{
    loop {
        if cancel_check() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn await_or_cancel<T, Fut, C>(future: Fut, cancel_check: Option<&C>) -> Result<T, ScanError>
where
    Fut: Future<Output = T>,
    C: Fn() -> bool + ?Sized,
{
    if let Some(cancel_check) = cancel_check {
        tokio::pin!(future);
        tokio::select! {
            result = &mut future => Ok(result),
            _ = wait_for_cancellation(cancel_check) => Err(ScanError::Cancelled),
        }
    } else {
        Ok(future.await)
    }
}

/// Run all applicable checks against a URL, emitting progress events.
#[tracing::instrument(skip(progress, enabled_categories, cancel_check, url_str, stylesheet_cache), fields(timeout_secs, scan_type = %scan_type))]
pub async fn run_scan<C>(
    url_str: &str,
    progress: Option<&ProgressFn>,
    enabled_categories: Option<Vec<String>>,
    timeout_secs: Option<u64>,
    scan_type: ScanType,
    // Multi-page scans skip origin-wide checks after the entry page.
    skip_origin_checks: bool,
    cancel_check: Option<&C>,
    // Stylesheets already read by earlier pages of the same scan execution.
    stylesheet_cache: Option<&crate::checks::polish::StylesheetCache>,
) -> Result<ScanResult, ScanError>
where
    C: Fn() -> bool + ?Sized,
{
    let start = std::time::Instant::now();
    ensure_not_cancelled(cancel_check)?;

    let url = url::Url::parse(url_str).map_err(|e| ScanError::InvalidUrl(e.to_string()))?;
    // Every entry point reaches the scanner here, so the target is validated
    // here rather than at each command. The CLI calls this directly, and while
    // the connect-time resolver refused a hostname pointing into private
    // space, a bare private address literal never resolves and so was never
    // checked at all.
    crate::network_policy::validate_url_target(&url, crate::network_policy::UrlPolicy::ScanTarget)
        .await
        .map_err(ScanError::InvalidUrl)?;
    // The origin's reach picks the client, and the client carries that reach
    // into every redirect and subresource the page steers it to.
    let origin = crate::network_policy::LocalOrigin::classify_resolved(&url).await;
    let timeout = timeout_secs.unwrap_or(30);

    let (mut ctx, detected_stack) =
        fetch_page(&url, origin, timeout, progress, cancel_check).await?;
    ensure_not_cancelled(cancel_check)?;
    // Checks grade the response that was actually fetched. This matters when
    // the requested URL redirects to a different scheme, host, or local/live
    // context (for example, HSTS on an HTTPS destination).
    let is_local = ctx.is_localhost;
    let effective_url = ctx.url.to_string();
    let mode = if is_local { "predeploy" } else { "live" };

    // Force category subsets for focused scan types
    let effective_categories = match scan_type {
        ScanType::Security => Some(vec!["security".to_string()]),
        ScanType::Accessibility => {
            Some(vec!["accessibility".to_string(), "compliance".to_string()])
        }
        ScanType::Health => enabled_categories,
        // Polish bypasses the live-site registry and runs its dedicated phase.
        ScanType::Polish => Some(Vec::new()),
    };

    let (mut sync_checks, mut async_checks) = collect_checks(&effective_categories);
    if matches!(scan_type, ScanType::Polish) {
        // Remove self-filtering predeploy checks from Polish artifacts.
        sync_checks.clear();
    }
    if skip_origin_checks {
        async_checks.retain(|check| !check.origin_scoped());
    }
    let total = sync_checks.len() + async_checks.len();

    let mut all_results = Vec::new();
    let mut checks_done: usize = 0;

    run_sync_checks(
        &sync_checks,
        &ctx,
        is_local,
        progress,
        total,
        &mut checks_done,
        &mut all_results,
        cancel_check,
    )?;
    run_async_checks(
        &async_checks,
        &ctx,
        is_local,
        progress,
        total,
        &mut checks_done,
        &mut all_results,
        cancel_check,
    )
    .await?;
    ensure_not_cancelled(cancel_check)?;

    // Cross-page signals and the site baseline's observation, both read before
    // the polish phase takes the body (see `site_facts::read_before_polish`).
    let (page_signals, site_facts) =
        site_facts::read_before_polish(&ctx, &all_results, !skip_origin_checks).await;

    // Polish signals - fetch CSS and run quality heuristics (skip for security/accessibility scans)
    if !matches!(scan_type, ScanType::Security | ScanType::Accessibility) {
        run_polish_phase(
            &mut ctx,
            origin,
            progress,
            &mut all_results,
            cancel_check,
            stylesheet_cache,
        )
        .await?;
    }
    ensure_not_cancelled(cancel_check)?;

    // Layer 2: axe-core + Core Web Vitals (handled by caller via append_webview_results)
    // In CLI mode, webview analysis is unavailable. Desktop callers should call
    // webview::analyzer::analyze_url and then append_webview_results after this.
    ensure_not_cancelled(cancel_check)?;

    finalize_check_results(&mut all_results);

    // Score the defects, not the reports: a finding two checks both grade is
    // filed under one canonical id in the issue list, and costs one deduction.
    let (overall_score, categories) =
        calculator::calculate_scores_with_identity(&all_results, |result| {
            crate::core::correlation::web_scan_check_id(&result.check_id)
                .unwrap_or(result.check_id.as_str())
        });

    Ok(ScanResult {
        url: effective_url,
        mode: mode.to_string(),
        scan_type,
        overall_score,
        categories,
        issues: all_results,
        detected_stack,
        duration_ms: start.elapsed().as_millis() as u64,
        timestamp: chrono::Utc::now().to_rfc3339(),
        page_signals,
        site_facts,
    })
}

/// Fetch the page and build a CheckContext + detect tech stack
async fn fetch_page<C>(
    url: &url::Url,
    origin: crate::network_policy::LocalOrigin,
    timeout: u64,
    progress: Option<&ProgressFn>,
    cancel_check: Option<&C>,
) -> Result<(CheckContext, Option<serde_json::Value>), ScanError>
where
    C: Fn() -> bool + ?Sized,
{
    let client = crate::http_client::for_scan_origin(origin).clone();
    ensure_not_cancelled(cancel_check)?;

    emit_progress(
        progress,
        "fetch",
        ScanCategory::Security,
        "running",
        0,
        0,
        0,
    );

    let deadline = std::time::Duration::from_secs(timeout.max(1)); // allow-inline-duration: user-configurable per-scan timeout
    let response = await_or_cancel(
        client.get(url.as_str()).timeout(deadline).send(),
        cancel_check,
    )
    .await?
    .map_err(|e| ScanError::NetworkError(crate::http_client::fetch_failure(url, &e)))?;

    let effective_url = response.url().clone();
    let effective_is_local = localhost::is_localhost(&effective_url);
    let effective_is_strict_local = localhost::is_strict_localhost(&effective_url);
    let status_code = response.status().as_u16();
    let response_headers = response.headers().clone();
    let http_version = format_http_version(response.version());

    let body_bytes = await_or_cancel(
        crate::http_client::read_body_limited(response, MAX_BODY_SIZE, BODY_READ_TIMEOUT),
        cancel_check,
    )
    .await?
    .map_err(|error| match error {
        crate::http_client::BodyReadError::TooLarge { received_bytes, .. } => {
            ScanError::NetworkError(format!(
                "Response too large ({:.1}MB). Maximum is {}MB.",
                received_bytes as f64 / 1024.0 / 1024.0,
                MAX_BODY_SIZE / 1024 / 1024
            ))
        }
        crate::http_client::BodyReadError::TimedOut { .. } => {
            ScanError::NetworkError(format!("Timed out reading response body from {}", url))
        }
        crate::http_client::BodyReadError::Transport(error) => {
            ScanError::NetworkError(format!("Failed to read response body: {}", error))
        }
    })?;

    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    // One shared lowercase pass: detect_stack consumes it here and the checks
    // reuse the same copy through CheckContext::body_lower.
    let body_lower = body.to_ascii_lowercase();

    let detected = crate::core::detector::detect_stack(&response_headers, &body, &body_lower);
    let detected_stack = if detected.is_empty() {
        None
    } else {
        tracing::info!("Detected stack: {}", detected.summary());
        Some(detected.to_json())
    };

    let ctx = CheckContext::new(
        crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: effective_url,
            response_headers,
            status_code,
            body,
            is_localhost: effective_is_local,
            is_strict_localhost: effective_is_strict_local,
            http_version,
            body_lower_cache: body_lower.into(),
        },
        client,
    )
    .with_requested_url(url.clone())
    .with_origin(origin);

    Ok((ctx, detected_stack))
}

/// Collect sync and async checks from enabled categories.
///
/// `pub(crate)` so the severity-policy exhaustiveness test can enumerate the
/// registered check universe instead of pinning a hand-kept id list.
#[allow(clippy::type_complexity)]
pub(crate) fn collect_checks(
    enabled_categories: &Option<Vec<String>>,
) -> (Vec<Box<dyn Check>>, Vec<Box<dyn AsyncCheck>>) {
    let cat_enabled = |cat: &str| -> bool {
        match enabled_categories {
            None => true,
            Some(cats) => cats.iter().any(|c| c.eq_ignore_ascii_case(cat)),
        }
    };

    let mut sync_checks: Vec<Box<dyn Check>> = Vec::new();
    if cat_enabled("security") {
        sync_checks.extend(security::sync_checks());
    }
    if cat_enabled("seo") {
        sync_checks.extend(seo::sync_checks());
    }
    if cat_enabled("performance") {
        sync_checks.extend(performance::sync_checks());
    }
    if cat_enabled("accessibility") {
        sync_checks.extend(accessibility::sync_checks());
    }
    if cat_enabled("compliance") {
        sync_checks.extend(compliance::sync_checks());
    }
    if cat_enabled("config") {
        sync_checks.extend(config::sync_checks());
    }
    // Pre-deploy checks self-filter by is_localhost
    sync_checks.extend(predeploy::all_predeploy_checks());

    let mut async_checks: Vec<Box<dyn AsyncCheck>> = Vec::new();
    if cat_enabled("security") {
        async_checks.extend(security::async_checks());
    }
    if cat_enabled("seo") {
        async_checks.extend(seo::async_checks());
    }
    if cat_enabled("performance") {
        async_checks.extend(performance::async_checks());
    }
    if cat_enabled("compliance") {
        async_checks.extend(compliance::async_checks());
    }
    if cat_enabled("config") {
        async_checks.extend(config::async_checks());
    }

    (sync_checks, async_checks)
}

/// Run Polish quality heuristics using the already-fetched page body.
/// Fetches linked CSS stylesheets, then runs all polish signals and converts to CheckResults.
/// `stylesheet_cache` holds the stylesheets earlier pages of this scan
/// execution already read; it is `None` for a single-page scan.
async fn run_polish_phase<C>(
    ctx: &mut CheckContext,
    origin: crate::network_policy::LocalOrigin,
    progress: Option<&ProgressFn>,
    results: &mut Vec<CheckResult>,
    cancel_check: Option<&C>,
    stylesheet_cache: Option<&crate::checks::polish::StylesheetCache>,
) -> Result<(), ScanError>
where
    C: Fn() -> bool + ?Sized,
{
    use crate::checks::polish::{self, css_fetch, PolishContext};

    ensure_not_cancelled(cancel_check)?;
    emit_progress(
        progress,
        "polish-css",
        ScanCategory::Polish,
        "running",
        0,
        0,
        0,
    );

    // Fetch linked CSS for polish analysis. Coverage travels with the content:
    // a failed fetch must not turn an unobserved CSS pattern into a Pass.
    let css_fetch = await_or_cancel(
        css_fetch::fetch_stylesheets(&ctx.body, &ctx.url, &ctx.client, origin, stylesheet_cache),
        cancel_check,
    )
    .await?;
    let stylesheets_discovered = css_fetch.stylesheets_discovered;
    let stylesheets_fetched = css_fetch.stylesheets_fetched;
    ensure_not_cancelled(cancel_check)?;

    emit_progress(
        progress,
        "polish-css",
        ScanCategory::Polish,
        "complete",
        0,
        0,
        0,
    );
    emit_progress(
        progress,
        "polish-signals",
        ScanCategory::Polish,
        "running",
        0,
        0,
        0,
    );

    // Move the body into the final phase to avoid a MAX_BODY_SIZE clone. Build a
    // fresh lowercase cache because PolishContext uses Unicode lowercasing.
    let polish_ctx = PolishContext {
        url: ctx.url.clone(),
        html: std::mem::take(&mut ctx.body),
        css: css_fetch.css,
        html_lower_cache: std::sync::OnceLock::new(),
    };

    let signal_results = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        polish::run_all_signals(&polish_ctx)
    }))
    .map_err(|_| {
        tracing::error!("Polish signal evaluation panicked; aborting incomplete scan");
        detector_crash_error("polish-signals")
    })?;
    ensure_not_cancelled(cancel_check)?;
    let mut polish_issues: Vec<CheckResult> = signal_results
        .iter()
        .map(polish_result_to_check_result)
        .collect();
    mark_incomplete_polish_css_results(
        &mut polish_issues,
        stylesheets_discovered,
        stylesheets_fetched,
    );

    let count = polish_issues.len();
    results.extend(polish_issues);

    emit_progress(
        progress,
        "polish-signals",
        ScanCategory::Polish,
        "complete",
        count,
        0,
        0,
    );

    tracing::info!(
        "Polish: {}/{} signals fired",
        signal_results.iter().filter(|s| s.fired).count(),
        signal_results.len()
    );
    Ok(())
}

/// CSS-dependent Polish signals can still prove a finding from inline HTML or
/// the stylesheets that were fetched. They cannot prove a clean result when a
/// linked stylesheet was unavailable, so preserve that distinction as Skipped.
fn mark_incomplete_polish_css_results(
    results: &mut [CheckResult],
    stylesheets_discovered: usize,
    stylesheets_fetched: usize,
) {
    if stylesheets_fetched >= stylesheets_discovered {
        return;
    }
    const CSS_DEPENDENT_SIGNALS: &[&str] = &[
        "polish.gradient-backgrounds",
        "polish.glassmorphism",
        "polish.excessive-border-radius",
        "polish.glow-shadows",
        "polish.floating-blobs",
    ];
    for result in results.iter_mut().filter(|result| {
        result.status == CheckStatus::Pass
            && CSS_DEPENDENT_SIGNALS.contains(&result.check_id.as_str())
    }) {
        result.status = CheckStatus::Skipped;
        result.description = format!(
            "This signal could not be cleared because SiteCMD fetched {} of {} linked stylesheets. The unavailable stylesheet may contain matching CSS.",
            stylesheets_fetched, stylesheets_discovered
        );
        result.raw_data = Some(serde_json::json!({
            "stylesheets_discovered": stylesheets_discovered,
            "stylesheets_fetched": stylesheets_fetched,
            "coverage_complete": false,
        }));
        result.confidence = crate::checks::IssueConfidence::NeedsReview;
        result.confidence_reason = Some(
            "Linked stylesheet coverage was incomplete, so absence of the CSS pattern was not established."
                .to_string(),
        );
    }
}

/// Emit a scan-progress event via the progress callback
fn emit_progress(
    cb: Option<&ProgressFn>,
    check_id: &str,
    category: ScanCategory,
    status: &str,
    results_count: usize,
    checks_done: usize,
    checks_total: usize,
) {
    if let Some(cb) = cb {
        cb(&ScanProgress {
            check_id: check_id.into(),
            category,
            status: status.into(),
            results_count,
            checks_done,
            checks_total,
        });
    }
}

/// Format HTTP version enum to string
fn format_http_version(version: reqwest::Version) -> Option<String> {
    match version {
        reqwest::Version::HTTP_09 => Some("HTTP/0.9".into()),
        reqwest::Version::HTTP_10 => Some("HTTP/1.0".into()),
        reqwest::Version::HTTP_11 => Some("HTTP/1.1".into()),
        reqwest::Version::HTTP_2 => Some("HTTP/2".into()),
        reqwest::Version::HTTP_3 => Some("HTTP/3".into()),
        _ => None,
    }
}

/// Convert a PolishResult to a CheckResult for unified storage.
fn polish_result_to_check_result(r: &crate::checks::polish::PolishResult) -> CheckResult {
    // Preserve branch-specific signal severity unless policy overrides it.
    let (status, severity) = if r.fired {
        let weight_severity = match r.weight {
            crate::checks::polish::SignalWeight::High => Severity::High,
            crate::checks::polish::SignalWeight::Medium => Severity::Medium,
            crate::checks::polish::SignalWeight::LowMedium
            | crate::checks::polish::SignalWeight::Low => Severity::Low,
        };
        (CheckStatus::Fail, weight_severity)
    } else {
        (CheckStatus::Pass, Severity::Low)
    };

    // Polish signals are heuristics; grade confidence per-signal so the UI
    // (and the SiteCMD scoring) can deprioritize subjective aesthetic
    // matches relative to direct structural facts.
    let (confidence, confidence_reason) =
        crate::core::confidence_policy::polish_signal_confidence(&r.id);

    // Fired signals get a finding-style headline; the signal name stays the
    // identity for passing results.
    let title = if r.fired {
        crate::checks::polish::titles::polish_signal_fail_title(&r.id)
            .map(str::to_string)
            .unwrap_or_else(|| r.name.clone())
    } else {
        r.name.clone()
    };
    let guidance = if r.fired {
        crate::checks::polish::guidance::polish_signal_guidance(&r.id)
    } else {
        None
    };

    CheckResult {
        check_id: format!("polish.{}", r.id),
        category: ScanCategory::Polish,
        title,
        description: r.detail.clone(),
        status,
        severity,
        fix_prompt: guidance.map(|entry| entry.fix.to_string()),
        manual_fix: guidance.map(|entry| entry.fix.to_string()),
        raw_data: Some(r.data.clone()),
        confidence,
        confidence_reason: confidence_reason.map(|s| s.to_string()),
        why_it_matters: guidance.map(|entry| entry.why_it_matters.to_string()),
    }
}

#[cfg(test)]
mod tests;
