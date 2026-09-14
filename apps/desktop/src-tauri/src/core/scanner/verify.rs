use crate::checks::{accessibility, compliance, config, performance, security, seo};
use crate::checks::{AsyncCheck, Check, CheckContext};
use crate::core::localhost;
use futures_util::FutureExt;
use std::collections::BTreeSet;

use super::types::{ScanError, VerifyChecksResult};

fn run_sync_verification_check(
    check: &dyn Check,
    ctx: &CheckContext,
) -> Result<Vec<crate::checks::CheckResult>, ScanError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check.run(ctx))).map_err(|_| {
        tracing::error!(
            "Sync verification check {} panicked; aborting incomplete verification",
            check.id()
        );
        super::detector_crash_error(check.id())
    })
}

async fn run_async_verification_check(
    check: &dyn AsyncCheck,
    ctx: &CheckContext,
) -> Result<Vec<crate::checks::CheckResult>, ScanError> {
    match std::panic::AssertUnwindSafe(tokio::time::timeout(
        crate::constants::CHECK_TIMEOUT,
        check.run(ctx),
    ))
    .catch_unwind()
    .await
    {
        Ok(Ok(results)) => Ok(results),
        Ok(Err(_)) => Err(ScanError::ScanFailed(format!(
            "Web check '{}' timed out during verification; verification results are incomplete",
            check.id()
        ))),
        Err(_) => {
            tracing::error!(
                "Async verification check {} panicked; aborting incomplete verification",
                check.id()
            );
            Err(super::detector_crash_error(check.id()))
        }
    }
}

/// Re-run only the specified checks against a URL.
/// Used for inline issue verification and checklist item re-checks.
pub async fn verify_checks<F: Fn() -> bool>(
    url: &str,
    check_ids: &[String],
    is_cancelled: Option<&F>,
) -> Result<VerifyChecksResult, ScanError> {
    if let Some(f) = is_cancelled {
        if f() {
            return Err(ScanError::Cancelled);
        }
    }

    let parsed_url = url::Url::parse(url).map_err(|e| ScanError::NetworkError(e.to_string()))?;
    let requested_is_strict = localhost::is_strict_localhost(&parsed_url);

    let http = if requested_is_strict {
        crate::http_client::localhost_client().clone()
    } else {
        crate::http_client::client().clone()
    };

    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| ScanError::NetworkError(crate::http_client::fetch_failure(url, &e)))?;

    let effective_url = resp.url().clone();
    let is_local = localhost::is_localhost(&effective_url);
    let is_strict = localhost::is_strict_localhost(&effective_url);
    let status_code = resp.status().as_u16();
    let headers = resp.headers().clone();
    let http_version = Some(format!("{:?}", resp.version()));
    let body = crate::http_client::read_text_limited(
        resp,
        crate::constants::MAX_BODY_SIZE,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| ScanError::NetworkError(format!("Failed to read body: {}", e)))?;

    let ctx = CheckContext::new(
        crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: effective_url.clone(),
            response_headers: headers,
            status_code,
            body,
            is_localhost: is_local,
            is_strict_localhost: is_strict,
            http_version,
            body_lower_cache: std::sync::OnceLock::new(),
        },
        http.clone(),
    )
    .with_requested_url(parsed_url);
    let verification_ids = expand_web_verification_ids(check_ids);

    let all_sync: Vec<Box<dyn Check>> = [
        security::sync_checks(),
        seo::sync_checks(),
        performance::sync_checks(),
        accessibility::sync_checks(),
        compliance::sync_checks(),
        config::sync_checks(),
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut results = Vec::new();
    // Every producer family that re-ran to completion, with whether any of
    // its (unfiltered) results was Skipped. Feeds the synthesis of explicit
    // negative observations for emission-conditional producer IDs below.
    let mut family_runs: Vec<ProducerFamilyRun> = Vec::new();

    for check in &all_sync {
        if verification_ids
            .iter()
            .any(|id| check.id().starts_with(id) || id.starts_with(check.id()))
        {
            let emitted = run_sync_verification_check(check.as_ref(), &ctx)?;
            family_runs.push(ProducerFamilyRun {
                check_id: check.id().to_string(),
                category: check.category(),
                any_skipped: emitted
                    .iter()
                    .any(|cr| cr.status == crate::checks::CheckStatus::Skipped),
            });
            results.extend(
                emitted
                    .into_iter()
                    .filter(|cr| verification_ids.contains(&cr.check_id)),
            );
        }
    }

    let all_async: Vec<Box<dyn AsyncCheck>> = [
        security::async_checks(),
        seo::async_checks(),
        performance::async_checks(),
        compliance::async_checks(),
        config::async_checks(),
    ]
    .into_iter()
    .flatten()
    .collect();

    for check in &all_async {
        if verification_ids
            .iter()
            .any(|id| check.id().starts_with(id) || id.starts_with(check.id()))
        {
            if let Some(f) = is_cancelled {
                if f() {
                    return Err(ScanError::Cancelled);
                }
            }
            let emitted = run_async_verification_check(check.as_ref(), &ctx).await?;
            family_runs.push(ProducerFamilyRun {
                check_id: check.id().to_string(),
                category: check.category(),
                any_skipped: emitted
                    .iter()
                    .any(|cr| cr.status == crate::checks::CheckStatus::Skipped),
            });
            results.extend(
                emitted
                    .into_iter()
                    .filter(|cr| verification_ids.contains(&cr.check_id)),
            );
        }
    }

    // Rerun the bounded Polish signal set only for groups with a Polish
    // producer; those signals do not implement the Check traits.
    if verification_ids
        .iter()
        .any(|check_id| check_id.starts_with("polish."))
    {
        if let Some(f) = is_cancelled {
            if f() {
                return Err(ScanError::Cancelled);
            }
        }
        let css_fetch = crate::checks::polish::css_fetch::fetch_stylesheets(
            &ctx.body,
            &ctx.url,
            &ctx.client,
            crate::network_policy::LocalOrigin::classify(&ctx.url),
            // Verification re-reads the page under test; never reuse scan CSS.
            None,
        )
        .await;
        if let Some(f) = is_cancelled {
            if f() {
                return Err(ScanError::Cancelled);
            }
        }
        let polish_ctx = crate::checks::polish::PolishContext {
            url: ctx.url.clone(),
            html: ctx.body.clone(),
            css: css_fetch.css,
            html_lower_cache: std::sync::OnceLock::new(),
        };
        let signal_results = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::checks::polish::run_all_signals(&polish_ctx)
        }))
        .map_err(|_| {
            tracing::error!("Polish signal evaluation panicked; aborting incomplete verification");
            super::detector_crash_error("polish-signals")
        })?;
        let mut polish_results = signal_results
            .iter()
            .map(super::polish_result_to_check_result)
            .filter(|result| verification_ids.contains(&result.check_id))
            .collect::<Vec<_>>();
        super::mark_incomplete_polish_css_results(
            &mut polish_results,
            css_fetch.stylesheets_discovered,
            css_fetch.stylesheets_fetched,
        );
        results.extend(polish_results);
    }

    synthesize_unobserved_required_results(&mut results, check_ids, &family_runs);

    super::finalize_check_results(&mut results);

    Ok(VerifyChecksResult {
        effective_url: effective_url.to_string(),
        results,
    })
}

/// A producer family that re-ran to completion during this verification pass.
struct ProducerFamilyRun {
    check_id: String,
    category: crate::checks::ScanCategory,
    any_skipped: bool,
}

/// Synthesize negative observations for condition-only producers that ran to
/// completion. A skipped family remains skipped because absence is not proof.
fn synthesize_unobserved_required_results(
    results: &mut Vec<crate::checks::CheckResult>,
    check_ids: &[String],
    family_runs: &[ProducerFamilyRun],
) {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence};

    for required in required_web_verification_ids(check_ids) {
        if results.iter().any(|cr| cr.check_id == required) {
            continue;
        }
        // Longest matching family = the check that would have emitted this
        // ID. No match means the producer never ran; leave the ID missing so
        // the completeness gate reports it instead of inventing a result.
        let Some(family) = family_runs
            .iter()
            .filter(|run| {
                required == run.check_id || required.starts_with(&format!("{}.", run.check_id))
            })
            .max_by_key(|run| run.check_id.len())
        else {
            continue;
        };

        let (status, title, description, confidence, confidence_reason) = if family.any_skipped {
            (
                CheckStatus::Skipped,
                format!("`{required}` could not be re-proven"),
                format!(
                    "The `{}` check re-ran, but part of its coverage was skipped during this pass, so the absence of `{required}` is not proof the finding is resolved.",
                    family.check_id
                ),
                IssueConfidence::NeedsReview,
                Some(
                    "A related result in the same check family was skipped this pass; absence under incomplete coverage is not a negative observation.".to_string(),
                ),
            )
        } else {
            (
                CheckStatus::Pass,
                format!("`{required}` no longer observed"),
                format!(
                    "The `{}` check re-ran to completion and did not report `{required}`. This producer emits a result only while the condition it detects is present, so its absence on a completed pass is the negative observation.",
                    family.check_id
                ),
                IssueConfidence::High,
                Some(
                    "The producer family re-ran to completion without skips and did not emit this finding.".to_string(),
                ),
            )
        };

        results.push(CheckResult {
            check_id: required,
            category: family.category,
            title,
            description,
            status,
            severity: crate::checks::Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: Some(serde_json::json!({
                "synthesized_negative_observation": true,
                "producer_family": family.check_id,
                "family_had_skipped_results": family.any_skipped,
            })),
            confidence,
            confidence_reason,
            why_it_matters: None,
        });
    }
}

/// Expand canonical check IDs into live producer IDs required for verification.
/// Falls back to the canonical ID when no live mapping exists.
pub fn required_web_verification_ids(check_ids: &[String]) -> BTreeSet<String> {
    let mut required = BTreeSet::new();
    for check_id in check_ids {
        let producers =
            crate::core::correlation::live_source_signals_for_check_id("web_scan", check_id);
        if producers.is_empty() {
            required.insert(check_id.clone());
        } else {
            required.extend(producers.into_iter().map(str::to_string));
        }
    }
    required
}

fn expand_web_verification_ids(check_ids: &[String]) -> BTreeSet<String> {
    let mut expanded = BTreeSet::new();
    for check_id in check_ids {
        expanded.insert(check_id.clone());
        expanded.extend(
            crate::core::correlation::source_signals_for_check_id("web_scan", check_id)
                .into_iter()
                .map(str::to_string),
        );
    }
    expanded
}

#[cfg(test)]
mod tests {
    use super::{expand_web_verification_ids, verify_checks};
    use crate::checks::{AsyncCheck, Check, CheckContext, CheckResult, ScanCategory};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct PanickingSyncCheck;

    impl Check for PanickingSyncCheck {
        fn id(&self) -> &str {
            "test.verify_sync_panic"
        }

        fn category(&self) -> ScanCategory {
            ScanCategory::Seo
        }

        fn run(&self, _ctx: &crate::checks::PageContext) -> Vec<CheckResult> {
            panic!("intentional verification panic");
        }
    }

    struct PanickingAsyncCheck;

    #[async_trait::async_trait]
    impl AsyncCheck for PanickingAsyncCheck {
        fn id(&self) -> &str {
            "test.verify_async_panic"
        }

        fn category(&self) -> ScanCategory {
            ScanCategory::Seo
        }

        async fn run(&self, _ctx: &CheckContext) -> Vec<CheckResult> {
            panic!("intentional async verification panic");
        }
    }

    fn offline_ctx() -> CheckContext {
        CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse("https://example.com").unwrap(),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: "<!doctype html><html></html>".into(),
                is_localhost: false,
                is_strict_localhost: false,
                http_version: None,
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(false).clone(),
            probe_cache: Default::default(),
        }
    }

    async fn serve_once(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback fixture");
        let addr = listener.local_addr().expect("fixture address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fixture request");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write fixture response");
        });
        format!("http://{addr}")
    }

    async fn serve_redirect_once(body: &'static str) -> (String, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect fixture");
        let addr = listener.local_addr().expect("redirect fixture address");
        let final_url = format!("http://{addr}/final");
        let redirect_location = final_url.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept fixture request");
                let mut request = [0u8; 4096];
                let read = stream
                    .read(&mut request)
                    .await
                    .expect("read fixture request");
                let requested_final = String::from_utf8_lossy(&request[..read])
                    .lines()
                    .next()
                    .is_some_and(|line| line.contains(" /final "));
                let response = if requested_final {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {redirect_location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                };
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write fixture response");
            }
        });
        (format!("http://{addr}/start"), final_url)
    }

    #[test]
    fn canonical_verification_ids_expand_to_registered_web_producers() {
        let expanded = expand_web_verification_ids(&[
            "security.csp".to_string(),
            "security.source_maps".to_string(),
        ]);
        assert!(expanded.contains("security.csp"));
        assert!(expanded.contains("security.headers.csp"));
        assert!(expanded.contains("security.source_maps"));
        assert!(expanded.contains("polish.source-maps-production"));
    }

    #[test]
    fn raw_verification_id_is_preserved_without_inventing_an_alias() {
        let expanded = expand_web_verification_ids(&["performance.ttfb".to_string()]);
        assert_eq!(
            expanded.into_iter().collect::<Vec<_>>(),
            ["performance.ttfb"]
        );
    }

    #[tokio::test]
    async fn canonical_header_group_reruns_raw_header_producer() {
        let url = serve_once("<!doctype html><html><head></head><body></body></html>").await;
        let result = verify_checks::<fn() -> bool>(&url, &["security.csp".to_string()], None)
            .await
            .expect("verify canonical CSP group");

        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].check_id, "security.headers.csp");
        assert_ne!(result.results[0].status, crate::checks::CheckStatus::Pass);
    }

    #[tokio::test]
    async fn verification_reports_the_effective_response_url() {
        let (requested_url, effective_url) = serve_redirect_once(
            "<!doctype html><html><head></head><body><h1>Final</h1></body></html>",
        )
        .await;
        let result =
            verify_checks::<fn() -> bool>(&requested_url, &["security.csp".to_string()], None)
                .await
                .expect("verify redirected page");

        assert_eq!(result.effective_url, effective_url);
    }

    #[tokio::test]
    async fn canonical_polish_group_reruns_polish_producer() {
        let url = serve_once(
            "<!doctype html><html><body><script>//# sourceMappingURL=app.js.map</script></body></html>",
        )
        .await;
        let result =
            verify_checks::<fn() -> bool>(&url, &["security.source_maps".to_string()], None)
                .await
                .expect("verify canonical source-map group");

        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].check_id, "polish.source-maps-production");
        assert_ne!(result.results[0].status, crate::checks::CheckStatus::Pass);
    }

    #[test]
    fn image_alt_group_requires_its_live_identity_producer() {
        let required =
            super::required_web_verification_ids(&["accessibility.image_alt".to_string()]);
        assert_eq!(
            required.into_iter().collect::<Vec<_>>(),
            ["accessibility.image_alt"]
        );
    }

    #[tokio::test]
    async fn verifying_image_alt_reports_the_live_producer() {
        let url =
            serve_once(r#"<!doctype html><html><body><img src="/x.png"></body></html>"#).await;
        let result =
            verify_checks::<fn() -> bool>(&url, &["accessibility.image_alt".to_string()], None)
                .await
                .expect("image-alt verification must complete");
        let row = result
            .results
            .iter()
            .find(|r| r.check_id == "accessibility.image_alt")
            .expect("live producer result must be present");
        assert_ne!(
            row.status,
            crate::checks::CheckStatus::Pass,
            "an image without alt text must not verify as resolved"
        );
    }

    #[tokio::test]
    async fn fixed_by_removal_sub_id_synthesizes_an_explicit_negative_observation() {
        let url = serve_once("<!doctype html><html><head></head><body></body></html>").await;
        let result =
            verify_checks::<fn() -> bool>(&url, &["security.cookies.sessionid".to_string()], None)
                .await
                .expect("verifying a fixed-by-removal cookie must complete");
        let row = result
            .results
            .iter()
            .find(|r| r.check_id == "security.cookies.sessionid")
            .expect("synthesized negative observation must be present");
        assert_eq!(row.status, crate::checks::CheckStatus::Pass);
        assert!(
            row.raw_data
                .as_ref()
                .is_some_and(|raw| raw["synthesized_negative_observation"] == true),
            "the synthesized row must disclose it is a negative observation"
        );
    }

    #[test]
    fn synthesis_leaves_ids_missing_when_their_family_never_ran() {
        let mut results = Vec::new();
        super::synthesize_unobserved_required_results(
            &mut results,
            &["security.cookies.sessionid".to_string()],
            &[],
        );
        assert!(
            results.is_empty(),
            "no family ran; the completeness gate must report the gap, not an invented result"
        );
    }

    #[test]
    fn synthesis_is_skipped_grade_when_family_coverage_was_incomplete() {
        let mut results = Vec::new();
        super::synthesize_unobserved_required_results(
            &mut results,
            &["security.exposed_files.source_secrets".to_string()],
            &[super::ProducerFamilyRun {
                check_id: "security.exposed_files".to_string(),
                category: ScanCategory::Security,
                any_skipped: true,
            }],
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, crate::checks::CheckStatus::Skipped);
        assert_eq!(
            results[0].confidence,
            crate::checks::IssueConfidence::NeedsReview,
            "absence under incomplete coverage is not a negative observation"
        );
    }

    #[test]
    fn sync_verification_detector_panic_is_an_explicit_error() {
        let error = super::run_sync_verification_check(&PanickingSyncCheck, &offline_ctx())
            .expect_err("a crashed verifier must not look like a resolved issue");
        assert_eq!(
            error.to_string(),
            "Scan error: Web check 'test.verify_sync_panic' crashed; scan aborted to avoid reporting incomplete results"
        );
    }

    #[tokio::test]
    async fn async_verification_detector_panic_is_an_explicit_error() {
        let error = super::run_async_verification_check(&PanickingAsyncCheck, &offline_ctx())
            .await
            .expect_err("a crashed verifier must not look like a resolved issue");
        assert_eq!(
            error.to_string(),
            "Scan error: Web check 'test.verify_async_panic' crashed; scan aborted to avoid reporting incomplete results"
        );
    }
}
