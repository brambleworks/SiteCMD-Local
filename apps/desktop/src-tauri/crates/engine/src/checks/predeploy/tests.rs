use super::*;
use http::header::HeaderMap;

fn make_ctx(body: &str, is_localhost: bool) -> PageContext {
    PageContext {
        evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        url: url::Url::parse("http://localhost:3000").unwrap(),
        response_headers: HeaderMap::new(),
        status_code: 200,
        body: body.to_string(),
        is_localhost,
        is_strict_localhost: is_localhost,
        http_version: Some("HTTP/1.1".to_string()),
        body_lower_cache: std::sync::OnceLock::new(),
    }
}

#[test]
fn unsupported_predeploy_checks_fire_only_on_localhost() {
    use crate::manifest::{capability_manifest, HostedLane};

    let body = r#"<a href="http://127.0.0.1:3000/api">API</a>
        <script src="/vite/client"></script>
        <script>console.log("preview"); window.config = { debug: true,
            api_key: "not-a-real-test-secret" };
            //# sourceMappingURL=app.js.map
        </script>
        <!-- TODO: remove before launch -->
        <p>Lorem ipsum dolor sit amet</p>"#;
    let local_ctx = make_ctx(body, true);
    let hosted_ctx = make_ctx(body, false);
    let manifest = capability_manifest();
    let mut overclaimed = Vec::new();
    for check in all_predeploy_checks() {
        let local = check.run(&local_ctx);
        assert!(!local.is_empty(), "{} has no local verdict", check.id());
        assert!(
            local.iter().all(|row| row.check_id == check.id()
                && matches!(row.status, CheckStatus::Warn | CheckStatus::Fail)),
            "{} did not fire: {local:?}",
            check.id()
        );
        assert!(
            check.run(&hosted_ctx).is_empty(),
            "{} fires off localhost",
            check.id()
        );
        if manifest.entry(check.id()).unwrap().hosted != HostedLane::Unsupported {
            overclaimed.push(check.id().to_string());
        }
    }
    assert!(
        overclaimed.is_empty(),
        "localhost-only checks claim hosted lanes: {overclaimed:?}"
    );
}

#[test]
fn test_localhost_refs_detected() {
    let body = r#"<a href="http://localhost:3000/api">Link</a>"#;
    let ctx = make_ctx(body, true);
    let results = LocalhostRefsCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::Medium);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("local preview"));
    assert!(results[0].description.contains("does not establish"));
}

#[test]
fn localhost_reference_check_uses_real_url_context_and_safe_evidence() {
    let inert = make_ctx(
        r#"<!-- <img src="http://localhost:3000/fake.png"> -->
            <pre>Example: http://localhost:3000/docs</pre>
            <script>// http://localhost:3000/commented
              const docs = "https://localhost.evil.example/not-loopback";
            </script>"#,
        true,
    );
    assert_eq!(LocalhostRefsCheck.run(&inert)[0].status, CheckStatus::Pass);

    let real = make_ctx(
        r#"<img src=http://localhost:3000/account/reset/short-token?token=secret>
            <style>.hero { background: url(http://127.0.0.1:4000/assets/hero.png) }</style>
            <script>const api = "http://[::1]:5000/api";</script>"#,
        true,
    );
    let result = &LocalhostRefsCheck.run(&real)[0];
    assert_eq!(result.status, CheckStatus::Warn);
    let serialized = serde_json::to_string(result).unwrap();
    assert!(
        serialized.contains("/account/reset/[redacted]"),
        "{serialized}"
    );
    assert!(serialized.contains("/assets/hero.png"), "{serialized}");
    assert!(serialized.contains("/api"), "{serialized}");
    assert!(!serialized.contains("short-token"), "{serialized}");
    assert!(!serialized.contains("token=secret"), "{serialized}");
}

#[test]
fn test_localhost_refs_skipped_for_live() {
    let body = r#"<a href="http://localhost:3000/api">Link</a>"#;
    let ctx = make_ctx(body, false);
    let results = LocalhostRefsCheck.run(&ctx);
    assert!(results.is_empty());
}

#[test]
fn test_source_maps_detected() {
    let body = r#"<script>var x = 1; //# sourceMappingURL=app.js.map</script>"#;
    let ctx = make_ctx(body, true);
    let results = SourceMapsCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn source_map_pass_does_not_claim_unreferenced_maps_are_absent() {
    let ctx = make_ctx("<script src=app.js></script>", true);
    let result = &SourceMapsCheck.run(&ctx)[0];
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(result.title, "No source map references found");
    assert!(result
        .description
        .contains("does not enumerate unreferenced files"));
}

#[test]
fn test_source_maps_title_is_hedged_and_needs_review() {
    let body = r#"<script>var x = 1; //# sourceMappingURL=app.js.map</script>"#;
    let ctx = make_ctx(body, true);
    let results = SourceMapsCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(
        !results[0].title.contains("will be exposed"),
        "{}",
        results[0].title
    );
    assert!(results[0].title.contains("Source map reference"));
    assert!(results[0].title.contains("local preview"));
    assert_eq!(results[0].severity, Severity::Low);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].confidence_reason.is_some());
    assert!(
        results[0].description.contains("did not fetch"),
        "{}",
        results[0].description
    );
}

#[test]
fn source_map_check_ignores_inert_examples_and_sanitizes_real_references() {
    let inert = make_ctx(
        r#"<!-- <script src="/assets/fake.js.map"></script> -->
            <pre>&lt;script src="/assets/docs.js.map"&gt;</pre>"#,
        true,
    );
    assert_eq!(SourceMapsCheck.run(&inert)[0].status, CheckStatus::Pass);

    let real = make_ctx(
        r#"<script src=/assets/app.js.map?token=secret></script>
            <script>//# sourceMappingURL=/maps/chunk.js.map?api_key=secret</script>"#,
        true,
    );
    let result = &SourceMapsCheck.run(&real)[0];
    assert_eq!(result.status, CheckStatus::Warn);
    let serialized = serde_json::to_string(result).unwrap();
    assert!(serialized.contains("/assets/app.js.map"), "{serialized}");
    assert!(serialized.contains("/maps/chunk.js.map"), "{serialized}");
    assert!(!serialized.contains("token=secret"), "{serialized}");
    assert!(!serialized.contains("api_key=secret"), "{serialized}");
}

#[test]
fn test_console_log_detected() {
    let body = r#"<script>console.log("hello"); var x = 1;</script>"#;
    let ctx = make_ctx(body, true);
    let results = ConsoleLogCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("local preview"));
}

#[test]
fn console_check_ignores_inert_script_examples_and_non_javascript_data() {
    let body = r#"<!-- <script>console.log('commented')</script> -->
        <script type="application/ld+json">{"example":"console.log("}</script>
        <script>
          const example = "console.log('string')";
          // console.warn('line comment')
          /* console.error('block comment') */
        </script>"#;
    let result = &ConsoleLogCheck.run(&make_ctx(body, true))[0];
    assert_eq!(result.status, CheckStatus::Pass, "{}", result.description);
}

#[test]
fn test_console_log_multibyte_context_does_not_panic() {
    let body = "<script>\
        const 説明 = \"これはとても長い日本語のコメントです\"; \
        console.log(説明); \
        const 続き = \"さらに長い日本語のテキストが続きます\";\
        </script>";
    let ctx = make_ctx(body, true);
    let results = ConsoleLogCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn captured_predeploy_samples_do_not_persist_personal_or_secret_values() {
    let localhost = make_ctx(
        r#"<a href="http://localhost:3000/reset/short-token?token=secret&email=person@example.com">Link</a>"#,
        true,
    );
    let localhost_raw = LocalhostRefsCheck.run(&localhost)[0]
        .raw_data
        .as_ref()
        .unwrap()
        .to_string();
    assert!(!localhost_raw.contains("short-token"), "{localhost_raw}");
    assert!(
        !localhost_raw.contains("person@example.com"),
        "{localhost_raw}"
    );
    assert!(!localhost_raw.contains("secret"), "{localhost_raw}");

    let console = make_ctx(
        r#"<script>console.log("person@example.com", "password=hunter2");</script>"#,
        true,
    );
    let console_raw = ConsoleLogCheck.run(&console)[0]
        .raw_data
        .as_ref()
        .unwrap()
        .to_string();
    assert!(!console_raw.contains("person@example.com"), "{console_raw}");
    assert!(!console_raw.contains("hunter2"), "{console_raw}");

    let todo = make_ctx(
        "<!-- TODO: reset person@example.com with password=hunter2 -->",
        true,
    );
    let todo_raw = TodoCommentsCheck.run(&todo)[0]
        .raw_data
        .as_ref()
        .unwrap()
        .to_string();
    assert!(!todo_raw.contains("person@example.com"), "{todo_raw}");
    assert!(!todo_raw.contains("hunter2"), "{todo_raw}");
}

#[test]
fn test_todo_comments_detected() {
    let body = r#"<div>Content</div><!-- TODO: Fix this layout --><p>More</p>"#;
    let ctx = make_ctx(body, true);
    let results = TodoCommentsCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(!results[0]
        .why_it_matters
        .as_deref()
        .unwrap_or_default()
        .contains("unprofessional"));
}

#[test]
fn test_todo_comments_long_multibyte_does_not_panic() {
    // A TODO comment longer than 80 bytes with a multibyte char straddling byte
    // 77, so the truncation slice would panic on a raw byte cut.
    let body = "<div>Content</div>\
        <!-- TODO: このレイアウトの問題を修正する必要があります。とても重要な作業です。 -->\
        <p>More</p>";
    let ctx = make_ctx(body, true);
    let results = TodoCommentsCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn test_placeholder_detected() {
    let body = r#"<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>"#;
    let ctx = make_ctx(body, true);
    let results = PlaceholderContentCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].title.contains("Possible"));
}

#[test]
fn test_env_leak_detected() {
    let body = r#"<script>var config = { api_key: "not-a-real-test-secret" };</script>"#;
    let ctx = make_ctx(body, true);
    let results = EnvLeakCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert_eq!(results[0].severity, Severity::High);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].title.contains("credential-shaped"));
    assert!(results[0].description.contains("does not verify"));
}

#[test]
fn test_env_leak_refs_only_is_a_reference_warn_not_a_leak() {
    let body = r#"<script>var url = process.env.API_BASE_URL;</script>"#;
    let ctx = make_ctx(body, true);
    let results = EnvLeakCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::Medium);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert_eq!(
        results[0].title,
        "Environment variable references in page HTML"
    );
    assert!(
        results[0].description.contains("No secret value was seen"),
        "{}",
        results[0].description
    );
}

#[test]
fn test_env_leak_ignores_i18n_password_prose() {
    let body = r#"<script>var messages = { password: "Forgot your password?" };</script>"#;
    let ctx = make_ctx(body, true);
    let results = EnvLeakCheck.run(&ctx);
    assert_eq!(
        results[0].status,
        CheckStatus::Pass,
        "{}",
        results[0].description
    );
}

#[test]
fn test_env_leak_ignores_masked_values() {
    let body = r#"<script>var cfg = { password: "********" };</script>"#;
    let ctx = make_ctx(body, true);
    let results = EnvLeakCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_debug_mode_ignores_production_angular_and_false_flags() {
    let body = r#"<html ng-version="17.3.0"><script>var cfg = {debug: false};</script><body>My todo list app</body></html>"#;
    let ctx = make_ctx(body, true);
    let results = DebugModeCheck.run(&ctx);
    assert_eq!(
        results[0].status,
        CheckStatus::Pass,
        "{}",
        results[0].description
    );
}

#[test]
fn test_debug_mode_flags_truthy_debug_and_debug_comments() {
    let body =
        r#"<script>window.config = { debug: true };</script><!-- TODO: remove before launch -->"#;
    let ctx = make_ctx(body, true);
    let results = DebugModeCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::Low);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("local preview"));
    let raw = results[0].raw_data.as_ref().unwrap().to_string();
    assert!(raw.contains("Debug flag in HTML") && raw.contains("Debug/TODO HTML comments"));
}

#[test]
fn test_debug_mode_ignores_stack_trace_in_marketing_copy() {
    let body = r#"<h1>Debugging tools</h1><p>See the full stack trace for every error your users hit.</p>"#;
    let ctx = make_ctx(body, true);
    let results = DebugModeCheck.run(&ctx);
    assert_eq!(
        results[0].status,
        CheckStatus::Pass,
        "{}",
        results[0].description
    );
}

#[test]
fn test_debug_mode_flags_real_error_dumps() {
    for dump in [
        "<pre>Traceback (most recent call last):\n  File \"app.py\", line 3</pre>",
        "<pre>Fatal error: Uncaught Exception\nStack trace:\n#0 {main}</pre>",
        "<pre>TypeError: x is undefined\n    at render (app.js:10:5)</pre>",
    ] {
        let ctx = make_ctx(dump, true);
        let results = DebugModeCheck.run(&ctx);
        assert_eq!(results[0].status, CheckStatus::Warn, "{dump}");
    }
}

#[test]
fn test_placeholder_ignores_names_inside_scripts_and_comments() {
    let body = r#"<script>var demoUser = "John Doe"; var t = "lorem ipsum";</script><!-- placeholder text --><p>Real launch copy.</p>"#;
    let ctx = make_ctx(body, true);
    let results = PlaceholderContentCheck.run(&ctx);
    assert_eq!(
        results[0].status,
        CheckStatus::Pass,
        "{}",
        results[0].description
    );
}

#[test]
fn test_debug_mode_comment_words_must_be_inside_comments() {
    // A commented page whose visible copy mentions a to-do list is not
    // in debug mode.
    let body = r#"<!-- header start --><h1>The best todo app</h1><!-- header end -->"#;
    let ctx = make_ctx(body, true);
    let results = DebugModeCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_dev_deps_detected() {
    let body = r#"<script src="/@vite/client"></script><div id="app"></div>"#;
    let ctx = make_ctx(body, true);
    let results = DevDependenciesCheck.run(&ctx);
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::Low);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("expected"));
    assert!(results[0].description.contains("does not establish"));
}

#[test]
fn one_runtime_matched_by_two_patterns_is_labeled_once() {
    for body in [
        r#"<script src="/@vite/client"></script>"#,
        r#"<script src="/browser-sync/browser-sync-client.js"></script><script>window.___browserSync___={}</script>"#,
    ] {
        let ctx = make_ctx(body, true);
        let results = DevDependenciesCheck.run(&ctx);
        let found = results[0].raw_data.as_ref().expect("evidence")["found"]
            .as_array()
            .expect("found list")
            .clone();
        assert_eq!(found.len(), 1, "{body}: {found:?}");
    }
}

#[test]
fn the_vite_client_label_is_not_repeated_in_the_description() {
    let ctx = make_ctx(r#"<script src="/@vite/client"></script>"#, true);
    let results = DevDependenciesCheck.run(&ctx);
    assert!(
        results[0]
            .description
            .contains("local preview: Vite HMR client."),
        "{}",
        results[0].description
    );
}
