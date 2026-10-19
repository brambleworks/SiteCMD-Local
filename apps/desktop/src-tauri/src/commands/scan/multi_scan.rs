use crate::core::normalized_scan::{
    batch_outcomes_on_routes, covered_routes, normalize_multi_page_parent, normalize_web_scan,
    ClaimBasis, ScanCoverageKind, ScanCoverageManifest, ScanRunKind, ScanRunStatus,
};
use crate::core::scanner::{self, ScanType};
use crate::db::Database;
use std::collections::HashSet;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

use super::control::ScanControlState;
use super::page_loop::{
    run_page_loop, session_average, PageLoopOutcome, PageLoopStatus, PageScanOutput,
};
use crate::commands::{emit_event, sanitize_error, validate_url_async};

pub(crate) async fn scan_multi_for_execution(
    app: AppHandle,
    db: Arc<Database>,
    scan_control: &ScanControlState,
    urls: Vec<String>,
    environment_url: Option<String>,
    project_id: Option<i64>,
    enabled_categories: Option<Vec<String>>,
    timeout_secs: Option<u64>,
    axe_enabled: Option<bool>,
    scan_type: Option<ScanType>,
    scan_request_id: u64,
    execution_id: i64,
) -> Result<scanner::MultiScanResult, String> {
    if urls.is_empty() {
        return Err("No URLs to scan".into());
    }

    for url in &urls {
        validate_url_async(url).await?;
    }

    // Page selection order is not an environment boundary. The renderer sends
    // the active project environment explicitly; the first URL remains a
    // backward-compatible fallback for older callers.
    let environment_url = environment_url.unwrap_or_else(|| urls[0].clone());
    validate_url_async(&environment_url).await?;
    let base_url = &environment_url;
    let started_at = chrono::Utc::now().timestamp_millis();
    let start = std::time::Instant::now();
    let focus = scan_type.unwrap_or_default();
    // The session checks need the site's stored sitemap URL, which is read here
    // rather than at the point of use: it is one column off the row this
    // closure already resolves, and a separate read would be another blocking
    // database round trip for a value the scan can settle up front.
    let (site_id, multi_project_id, session_id, stored_sitemap_url) = {
        let db = db.clone();
        let base_url = base_url.clone();
        let selected_page_urls = urls.clone();
        let axe = axe_enabled.unwrap_or(false);
        crate::commands::run_blocking(move || -> Result<_, String> {
            let site_id = match project_id {
                Some(project_id) => db.get_or_create_site_for_project(project_id, &base_url),
                None => db.get_or_create_site(&base_url),
            }
            .map_err(sanitize_error)?;
            let stored_sitemap_url = db.get_sitemap_url(site_id).unwrap_or(None);
            let multi_project_id = match project_id {
                Some(project_id) => Some(project_id),
                None => db
                    .find_project_for_url_result(&base_url)
                    .map_err(sanitize_error)?,
            };
            let session_id = db
                .start_multi_page_scan_run(
                    execution_id,
                    multi_project_id,
                    site_id,
                    &base_url,
                    focus,
                    &selected_page_urls,
                    axe,
                    started_at,
                )
                .map_err(sanitize_error)?;
            Ok((site_id, multi_project_id, session_id, stored_sitemap_url))
        })
        .await??
    };
    let result: Result<scanner::MultiScanResult, String> = async {
        // Capture active groups before page persistence for lifecycle deltas.
        let pre_scan_active = match multi_project_id {
            Some(project_id) => {
                let db_before = db.clone();
                let environment_url = base_url.to_string();
                Some(
                    crate::commands::run_blocking(move || {
                        load_active_issue_group_ids(&db_before, project_id, &environment_url)
                    })
                    .await
                    .map_err(|error| format!("pre-scan issue snapshot task failed: {error}"))?
                    .map_err(|error| format!("failed to load pre-scan issue snapshot: {error}"))?,
                )
            }
            None => None,
        };

        // Sites link the same stylesheets from every page. One store per scan
        // execution, dropped with this future, turns twenty pages sharing four
        // stylesheets into four downloads instead of eighty.
        let stylesheet_cache = Arc::new(crate::checks::polish::StylesheetCache::new());

        let loop_outcome = run_page_loop(
            &urls,
            session_id,
            || scan_control.is_cancelled(scan_request_id),
            |_, url, skip_origin_checks| {
                let st = focus;
                let progress_app = app.clone();
                let browser_app = app.clone();
                let page_url = url.to_string();
                let progress_fn: std::sync::Arc<scanner::ProgressFn> =
                    std::sync::Arc::new(move |p| {
                        let _ = progress_app.emit("scan-progress", p);
                    });
                let scan_control_clone = scan_control.clone();
                let cancel_fn: std::sync::Arc<crate::scan_runtime::CancelFn> =
                    std::sync::Arc::new(move || scan_control_clone.is_cancelled(scan_request_id));
                let enabled_categories = enabled_categories.clone();
                let stylesheet_cache = stylesheet_cache.clone();
                async move {
                    let mut result = crate::scan_runtime::run_scan_low_priority(
                        page_url.clone(),
                        Some(progress_fn),
                        enabled_categories,
                        timeout_secs,
                        st,
                        skip_origin_checks,
                        Some(cancel_fn.clone()),
                        Some(stylesheet_cache),
                    )
                    .await?;
                    let browser_runtime = super::web_scan::apply_webview_layer(
                        &browser_app,
                        &mut result,
                        &page_url,
                        st,
                        axe_enabled,
                        cancel_fn.as_ref(),
                    )
                    .await?;
                    Ok(PageScanOutput {
                        result,
                        browser_runtime,
                    })
                }
            },
            |completed_pages, url, result, browser_runtime| {
                // Persist this page off the async-runtime worker threads: the
                // scan save + work-items upsert + session-progress update are
                // synchronous SQLite round-trips that would otherwise park a
                // runtime worker mid-scan.
                let db = db.clone();
                let page_url = url.to_string();
                let environment_url = base_url.to_string();
                let project_id = multi_project_id;
                async move {
                    match crate::commands::run_blocking(move || {
                        persist_multi_page_blocking(
                            &db,
                            execution_id,
                            session_id,
                            completed_pages,
                            &environment_url,
                            &page_url,
                            project_id,
                            site_id,
                            axe_enabled.unwrap_or(false),
                            &browser_runtime,
                            &result,
                        )
                    })
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => Err(format!("page persistence task failed: {error}")),
                    }
                }
            },
            |progress| emit_event(&app, "multi-scan-progress", progress),
        )
        .await?;
        let PageLoopOutcome {
            status: loop_status,
            page_results,
            completed_scores,
            session_signals,
            session_site_facts,
            browser_runtimes,
        } = loop_outcome;

        let duration_ms = start.elapsed().as_millis() as u64;
        // Persist no completed score as NULL, not zero.
        let session_score = session_average(&completed_scores);

        // One optional sitemap fetch feeds the orphan coverage gate and the
        // noindex-in-sitemap contradiction check over collected page signals;
        // no page is re-fetched.
        let mut site_issues: Vec<crate::checks::CheckResult> = Vec::new();
        let session_analyzed =
            should_analyze_session(loop_status, urls.len(), session_signals.len());
        if session_analyzed {
            let sitemap = session_sitemap(stored_sitemap_url.as_deref(), base_url).await;
            site_issues = crate::core::session_analysis::analyze_session(
                &session_signals,
                sitemap
                    .as_ref()
                    .map(|sitemap| crate::core::session_analysis::SessionSitemap {
                        urls: &sitemap.urls,
                        partial_because: sitemap.partial_because.as_deref(),
                    }),
            );
            scanner::finalize_check_results(&mut site_issues);
        }

        // The project was resolved strictly before the session began. Reuse
        // that exact scope for every page, site-wide finding, and final event.
        let finalize_project_id = multi_project_id;

        let successful_page_urls: Vec<String> = page_results
            .iter()
            .filter(|page| page.scan_id > 0)
            .map(|page| page.url.clone())
            .collect();
        let completed_at = chrono::Utc::now().timestamp_millis();
        let mut parent_batch = normalize_multi_page_parent(
            &site_issues,
            execution_id,
            finalize_project_id,
            site_id,
            base_url.to_string(),
            urls.clone(),
            successful_page_urls.clone(),
            urls.len(),
            session_score,
            duration_ms,
            started_at,
            completed_at,
            focus,
            axe_enabled.unwrap_or(false),
            session_analyzed,
        )
        .map_err(|error| format!("failed to normalize multi-page scan: {error}"))?;
        let browser_runtime =
            super::web_scan::BrowserRuntime::for_scope(&browser_runtimes, urls.len());
        let page_scope_detail = (successful_page_urls.len() < urls.len()).then(|| {
            format!(
                "{} of {} selected pages completed.",
                successful_page_urls.len(),
                urls.len()
            )
        });
        let incomplete_detail = match (page_scope_detail, browser_runtime.incomplete_detail()) {
            (Some(page), Some(browser)) => Some(format!("{page} {browser}")),
            (Some(detail), None) | (None, Some(detail)) => Some(detail),
            (None, None) => None,
        };
        parent_batch.diagnostics.browser_ran = Some(browser_runtime.ran);
        parent_batch.diagnostics.axe_ran = Some(browser_runtime.axe_ran);
        parent_batch.diagnostics.browser_build = browser_runtime.build;
        parent_batch.environment_scope_key = crate::db::normalize_env_url(Some(base_url));
        parent_batch.status = match loop_status {
            PageLoopStatus::Complete => ScanRunStatus::Complete,
            PageLoopStatus::Partial => ScanRunStatus::Failed,
            PageLoopStatus::Failed => ScanRunStatus::Failed,
            PageLoopStatus::Cancelled => ScanRunStatus::Cancelled,
        };
        if loop_status != PageLoopStatus::Complete {
            parent_batch.raw_score = None;
            parent_batch.coverage.successful = false;
            parent_batch.status_detail = Some(
                match loop_status {
                    PageLoopStatus::Partial => incomplete_detail
                        .as_deref()
                        .unwrap_or("The selected scan scope did not complete."),
                    PageLoopStatus::Failed => "all_selected_pages_failed",
                    PageLoopStatus::Cancelled => "cancelled_by_user",
                    PageLoopStatus::Complete => unreachable!(),
                }
                .to_string(),
            );
        }
        {
            let db_parent = db.clone();
            crate::commands::run_blocking(move || -> Result<(), crate::db::DbError> {
                db_parent.complete_multi_page_scan_run(session_id, parent_batch)?;
                if loop_status == PageLoopStatus::Complete {
                    super::baseline::record_baseline_observations(
                        &db_parent,
                        site_id,
                        Some(session_id),
                        &session_site_facts,
                    );
                }
                Ok(())
            })
            .await
            .map_err(|error| format!("multi-page run completion task failed: {error}"))?
            .map_err(|error| format!("failed to complete multi-page run: {error}"))?;
        }
        // Compare canonical issue groups after every session update is persisted.
        let (new_issue_count, resolved_issue_count) = match (finalize_project_id, pre_scan_active) {
            (Some(project_id), Some(before)) => {
                let db_after = db.clone();
                let environment_url = base_url.to_string();
                let after = crate::commands::run_blocking(move || {
                    load_active_issue_group_ids(&db_after, project_id, &environment_url)
                })
                .await
                .map_err(|error| format!("post-scan issue snapshot task failed: {error}"))?
                .map_err(|error| format!("failed to load post-scan issue snapshot: {error}"))?;
                let (new_count, resolved_count) = issue_group_change_counts(&before, &after);
                (Some(new_count), Some(resolved_count))
            }
            _ => (None, None),
        };

        match loop_status {
            PageLoopStatus::Cancelled => return Err("Multi-page scan cancelled".into()),
            PageLoopStatus::Failed => return Err("Every selected page failed to scan".into()),
            PageLoopStatus::Partial => {}
            PageLoopStatus::Complete => {}
        }

        tracing::info!(
            "Multi-scan complete: {} pages, avg score={}, duration={}ms",
            page_results.len(),
            session_score.map_or_else(|| "not scored".to_string(), |s| s.to_string()),
            duration_ms
        );

        Ok(scanner::MultiScanResult {
            session_id,
            total_pages: urls.len(),
            completed_pages: successful_page_urls.len(),
            // The live command uses zero when persistence records no score as NULL.
            overall_score: session_score.unwrap_or(0),
            duration_ms,
            incomplete_detail,
            page_results,
            new_issue_count,
            resolved_issue_count,
            site_issues,
        })
    }
    .await;

    // Mark an aborted parent failed while preserving the original error.
    if let Err(error) = &result {
        let db = db.clone();
        let detail = error.clone();
        let mark_result = crate::commands::run_blocking(move || {
            db.fail_scan_run(session_id, chrono::Utc::now().timestamp_millis(), &detail)
                .map_err(String::from)
        })
        .await
        .and_then(|inner| inner);
        if let Err(mark_error) = mark_result {
            tracing::error!(
                "failed to mark aborted scan session {} as errored: {}",
                session_id,
                mark_error
            );
        }
    }
    result
}

fn load_active_issue_group_ids(
    db: &Database,
    project_id: i64,
    env_url: &str,
) -> Result<HashSet<String>, crate::db::DbError> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    Ok(db
        .get_active_issue_groups(project_id, Some(env_url), now_ms)?
        .into_iter()
        .filter(|group| !group.status.is_inactive_for_scoring())
        .map(|group| group.check_id)
        .collect())
}

/// The sitemap the session checks compare against.
///
/// The site's stored sitemap URL is the one the app already showed the user in
/// Site Setup, so it is tried first; auto-discovery is the fallback for a site
/// that never had one configured, or whose configured URL no longer answers.
/// Returns `None` when no sitemap yielded URLs, which the session checks report
/// as Skipped rather than a clean pass.
///
/// The caller supplies the stored URL, read from the site row the scan already
/// resolves at startup, so this stays a pure network step. Reading it here
/// would be a second blocking database round trip for one column.
async fn session_sitemap(
    stored_sitemap_url: Option<&str>,
    base_url: &str,
) -> Option<crate::core::sitemap::SitemapResult> {
    let parsed = url::Url::parse(base_url).ok()?;
    let origin = crate::network_policy::LocalOrigin::classify_resolved(&parsed).await;
    let client = crate::http_client::for_scan_origin(origin);

    if let Some(sitemap_url) = stored_sitemap_url {
        if validate_url_async(sitemap_url).await.is_ok() {
            let result = crate::core::sitemap::fetch_sitemap_url(client, sitemap_url, origin).await;
            if !result.urls.is_empty() {
                return Some(result);
            }
        }
    }

    let discovered = crate::core::sitemap::discover_sitemap(client, base_url, origin).await;
    (!discovered.urls.is_empty()).then_some(discovered)
}

fn issue_group_change_counts(before: &HashSet<String>, after: &HashSet<String>) -> (usize, usize) {
    (
        after.difference(before).count(),
        before.difference(after).count(),
    )
}

fn should_analyze_session(
    loop_status: PageLoopStatus,
    selected_pages: usize,
    collected_signals: usize,
) -> bool {
    matches!(
        loop_status,
        PageLoopStatus::Complete | PageLoopStatus::Partial
    ) && selected_pages >= 2
        && collected_signals == selected_pages
}

/// Synchronous per-page persistence for a multi-page scan. The child run,
/// immutable findings, and coverage-scoped issue projection commit together.
/// Returns the canonical child run id.
fn persist_multi_page_blocking(
    db: &Arc<Database>,
    execution_id: i64,
    parent_run_id: i64,
    completed_pages: usize,
    environment_url: &str,
    page_url: &str,
    project_id: Option<i64>,
    site_id: i64,
    axe_enabled: bool,
    browser_runtime: &super::web_scan::BrowserRuntime,
    result: &scanner::ScanResult,
) -> Result<i64, String> {
    let completed_at = chrono::Utc::now().timestamp_millis();
    let started_at = completed_at.saturating_sub(result.duration_ms as i64);
    let mut batch = normalize_web_scan(
        result,
        execution_id,
        Some(parent_run_id),
        project_id,
        site_id,
        ScanRunKind::Page,
        started_at,
    )
    .map_err(|error| format!("failed to normalize page scan: {error}"))?;
    batch.environment_url = Some(environment_url.to_string());
    batch.environment_scope_key = crate::db::normalize_env_url(Some(environment_url));
    batch.diagnostics.page_url = Some(page_url.to_string());
    batch.diagnostics.axe_enabled = Some(axe_enabled);
    batch.diagnostics.browser_ran = Some(browser_runtime.ran);
    batch.diagnostics.axe_ran = Some(browser_runtime.axe_ran);
    batch.diagnostics.browser_build = browser_runtime.build.clone();
    // Claim authored and effective URLs: coverage exceptions use the authored
    // route, while findings and resolution use the post-redirect URL.
    let routes = covered_routes(page_url, &result.url);
    let outcomes = batch_outcomes_on_routes(&batch, &routes);
    batch.coverage = ScanCoverageManifest::derive(
        ScanCoverageKind::Page,
        routes.iter().map(|route| (*route).to_string()).collect(),
        &outcomes,
        ClaimBasis::PerRoute,
    );
    if let Some(detail) = browser_runtime.incomplete_detail() {
        batch.status = ScanRunStatus::Failed;
        batch.raw_score = None;
        batch.coverage.successful = false;
        batch.status_detail = Some(detail);
    }
    let run_id = db
        .persist_normalized_scan_run(batch)
        .map_err(|error| format!("failed to save canonical page run: {error}"))?;
    db.update_multi_page_scan_run_progress(parent_run_id, completed_pages)
        .map_err(|error| format!("failed to update multi-page run progress: {error}"))?;
    Ok(run_id)
}

#[cfg(test)]
mod tests {
    use super::{issue_group_change_counts, should_analyze_session, PageLoopStatus};
    use std::collections::HashSet;

    const SOURCE: &str = include_str!("multi_scan.rs");

    /// The body of `scan_multi_for_execution`, which runs from its signature
    /// to the next item in the file.
    fn scan_multi_for_execution_source() -> &'static str {
        let after_signature = SOURCE
            .split_once("pub(crate) async fn scan_multi_for_execution(")
            .expect("multi_scan.rs must define scan_multi_for_execution")
            .1;
        after_signature
            .split_once("\nfn load_active_issue_group_ids(")
            .expect("load_active_issue_group_ids must follow scan_multi_for_execution")
            .0
    }

    /// The body of `session_sitemap`, which runs from its signature to the
    /// next item in the file.
    fn session_sitemap_source() -> &'static str {
        let after_signature = SOURCE
            .split_once("async fn session_sitemap(")
            .expect("multi_scan.rs must define session_sitemap")
            .1;
        after_signature
            .split_once("\nfn issue_group_change_counts(")
            .expect("issue_group_change_counts must follow session_sitemap")
            .0
    }

    /// The stylesheet cache is pure wiring: every page of a multi-page scan
    /// reads the same linked stylesheets, and only the shared store keeps that
    /// from being one download per page. Nothing observable changes when the
    /// cache is dropped from the call, so no behavioral test can hold it. Pin
    /// the wiring itself: one store per execution, handed to every page scan.
    #[test]
    fn one_stylesheet_cache_per_execution_reaches_every_page_scan() {
        let body = scan_multi_for_execution_source();

        let created = body.find("StylesheetCache::new()").expect(
            "scan_multi_for_execution must create the execution's stylesheet cache itself; a \
             cache created per page would download every stylesheet on every page",
        );
        let page_loop = body
            .find("run_page_loop(")
            .expect("scan_multi_for_execution must drive its pages through run_page_loop");
        assert!(
            created < page_loop,
            "the stylesheet cache must be created before the page loop, so all pages share it"
        );

        let call_arguments = body
            .split_once("run_scan_low_priority(")
            .expect("the page scan must call run_scan_low_priority")
            .1
            .split_once(")\n")
            .expect("the run_scan_low_priority argument list must end on its own line")
            .0;
        assert!(
            call_arguments.contains("Some(stylesheet_cache)"),
            "run_scan_low_priority must receive the execution's stylesheet cache; passing None \
             silently re-downloads every page's stylesheets and no other test would notice"
        );
    }

    /// A site whose sitemap lives at a path SiteCMD does not guess is exactly
    /// the site whose sitemap URL the user configured by hand. Reaching for
    /// discovery first would report "no sitemap was found" while Site Setup
    /// shows the very sitemap the user saved. The ordering is what makes the
    /// session sitemap agree with the rest of the app, and only a live site
    /// with a non-default sitemap path would notice it changing, so pin it.
    #[test]
    fn the_session_sitemap_reads_the_sites_stored_url_before_auto_discovery() {
        let scan = scan_multi_for_execution_source();
        assert!(
            scan.contains("get_sitemap_url"),
            "the scan must read the site's stored sitemap URL; discovery alone reports no sitemap \
             for a site whose sitemap URL the user configured by hand",
        );
        assert!(
            scan.contains("session_sitemap(stored_sitemap_url.as_deref()"),
            "the stored sitemap URL the scan read must reach the session sitemap step",
        );

        let body = session_sitemap_source();
        let stored = body.find("stored_sitemap_url").expect(
            "session_sitemap must take the stored sitemap URL from its caller rather than reading \
             it itself; a read here is a second blocking database round trip",
        );
        let fetched = body
            .find("fetch_sitemap_url")
            .expect("session_sitemap must fetch the stored sitemap URL it was given");
        let discovered = body.find("discover_sitemap").expect(
            "session_sitemap must still auto-discover for a site with no stored sitemap URL",
        );

        assert!(
            stored < fetched && fetched < discovered,
            "the stored sitemap URL must be tried before auto-discovery"
        );
    }

    /// A truncated or first-of-several sitemap set must reach the session
    /// checks as such: `noindex_in_sitemap` reports Skipped instead of a clean
    /// Pass over a set it knows is incomplete, and it can only know that if the
    /// fetch's reason is carried through instead of dropped.
    #[test]
    fn a_partial_sitemap_read_reaches_session_analysis() {
        let body = scan_multi_for_execution_source();

        assert!(
            body.contains("partial_because"),
            "scan_multi_for_execution must hand the sitemap's partial-read reason to \
             analyze_session; without it a partial sitemap produces a clean Pass"
        );
    }

    #[test]
    fn issue_group_changes_count_unique_active_rows_in_both_directions() {
        let before = HashSet::from([
            "security.hsts".to_string(),
            "seo.meta-description".to_string(),
        ]);
        let after = HashSet::from([
            "security.hsts".to_string(),
            "performance.lcp".to_string(),
            "accessibility.alt-text".to_string(),
        ]);

        assert_eq!(issue_group_change_counts(&before, &after), (2, 1));
    }

    #[test]
    fn complete_signal_scope_is_analyzed_despite_partial_browser_coverage() {
        assert!(should_analyze_session(PageLoopStatus::Partial, 2, 2));
        assert!(!should_analyze_session(PageLoopStatus::Partial, 2, 1));
    }
}
