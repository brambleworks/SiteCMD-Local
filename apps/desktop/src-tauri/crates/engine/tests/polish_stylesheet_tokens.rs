// Compiled utility selectors and custom properties must not become extra markup uses.

use sitecmd_engine::checks::polish::{css_signal_counts, CssSignalCounts};
use sitecmd_engine::evaluation::{ExecutedProbe, PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::probe::{decode_probe_body, BodyLimit, ProbeOutcome, ProbeResponse};
use sitecmd_engine::CheckStatus;

fn glassmorphism_status(css: &str) -> CheckStatus {
    let html = r#"<link rel="stylesheet" href="/site.css"><header class="sticky top-0 backdrop-blur-md"></header>"#;
    let mut route = RouteSession::open(
        serde_json::from_value::<PageArtifact>(serde_json::json!({
            "url": "https://example.com/", "status_code": 200, "headers": [],
            "body": html, "evaluation_time": "2026-10-30T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
    for probe in route
        .plan()
        .probes
        .into_iter()
        .filter(|p| p.request.limit == BodyLimit::Stylesheet)
    {
        route.record(Some(vec![ExecutedProbe::new(
            probe.key,
            ProbeOutcome::Response(ProbeResponse {
                status: 200,
                final_url: probe.request.url,
                content_type: Some("text/css".into()),
                content_length: None,
                headers: vec![],
                body: Some(decode_probe_body(css.as_bytes().to_vec())),
            }),
        )]));
    }
    route
        .evaluate(&RouteFacts::default())
        .results
        .into_iter()
        .find(|row| row.check_id == "polish.glassmorphism")
        .unwrap()
        .status
}

#[test]
fn one_blur_utility_with_tailwind_v3_compiled_css_stays_clear() {
    // One HTML use must not be multiplied by selectors, defaults and var reads in compiled CSS.
    let css = r#"*,::before,::after{--tw-backdrop-blur: ;}::backdrop{--tw-backdrop-blur: ;}
        .backdrop-blur-md{--tw-backdrop-blur:blur(12px);-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness)}"#;
    assert_eq!(glassmorphism_status(css), CheckStatus::Pass);
}

#[test]
fn one_blur_utility_with_tailwind_v4_property_css_stays_clear() {
    // A compiled @property registration must not turn one backdrop-blur use into a finding.
    let css = r#".backdrop-blur-md{--tw-backdrop-blur:blur(var(--blur-md));-webkit-backdrop-filter:var(--tw-backdrop-blur);backdrop-filter:var(--tw-backdrop-blur)}
        @property --tw-backdrop-blur{syntax:"*";inherits:false;initial-value: ;}"#;
    assert_eq!(glassmorphism_status(css), CheckStatus::Pass);
}

#[test]
fn stylesheet_counts_ignore_markup_but_preserve_css_declarations() {
    // Markup tokens in stylesheet selectors or text must not inflate declaration counts.
    let css = r#".backdrop-blur-md,.rounded-full,.shadow-blue-500,.bg-gradient-to-r,.from-purple-500{}
        /* <i class="blob absolute rounded-full from-purple-500 to-orange-500"></i> */
        a{background:linear-gradient(red,blue);backdrop-filter:blur(2px);border-radius:24px;box-shadow:0 0 8px #ff0000;}"#;
    let counts = css_signal_counts(css, sitecmd_engine::checks::polish::CssTextKind::Stylesheet);
    let page_counts = css_signal_counts(css, sitecmd_engine::checks::polish::CssTextKind::Page);
    assert_eq!(page_counts.tailwind_blur, 1);
    assert_eq!(page_counts.tailwind_radius, 2);
    assert_eq!(page_counts.tailwind_shadows, 1);
    assert_eq!(page_counts.blob_classes, 1);
    assert_eq!(page_counts.absolute_rounded, 1);
    assert_eq!(page_counts.multi_hue_gradients, 2);
    assert_eq!(counts.multi_hue_gradients, 1);
    assert_eq!(
        counts,
        CssSignalCounts {
            multi_hue_gradients: 1,
            any_gradient: true,
            css_blur: 1,
            css_radius: 1,
            css_shadows: 1,
            ..Default::default()
        }
    );
}
