// The CLI and a hosted scan grade one page's stylesheets differently, a stylesheet the scan could not read lets a CSS signal pass, or stylesheets are read on every page.

use sitecmd_engine::evaluation::{
    ExecutedProbe, NotEvaluatedReason, PageArtifact, RouteFacts, RouteSession,
    EXCLUDED_PROBE_CHECKS,
};
use sitecmd_engine::probe::{
    decode_probe_body, BodyLimit, BodyPolicy, ProbeFailure, ProbeFailureClass, ProbeMethod,
    ProbeOutcome, ProbeResponse, RedirectPolicy,
};
use sitecmd_engine::{CheckResult, CheckStatus};

fn html() -> String {
    (0..12)
        .map(|i| {
            let href = match i {
                2 => "http://127.0.0.1/private.css".to_string(),
                3..=5 => format!("https://cdn.example.com/s{i}.css"),
                _ => format!("/s{i}.css"),
            };
            format!(r#"<link rel="stylesheet" href="{href}">"#)
        })
        .collect()
}

fn route(body: &str) -> RouteSession {
    let mut route = RouteSession::open(
        serde_json::from_value::<PageArtifact>(serde_json::json!({
            "url": "https://example.com/page", "status_code": 200, "headers": [],
            "body": body, "evaluation_time": "2026-10-30T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
    route.record(Some(vec![]));
    route
}

fn outcome(index: usize) -> ProbeOutcome {
    match index {
        1 | 2 => ProbeOutcome::Failure(ProbeFailure {
            class: if index == 1 {
                ProbeFailureClass::BodyCapExceeded
            } else {
                ProbeFailureClass::Transport
            },
            detail: if index == 1 {
                "body exceeds 2097152 bytes"
            } else {
                "address refused"
            }
            .into(),
        }),
        _ => ProbeOutcome::Response(ProbeResponse {
            status: if index == 0 { 404 } else { 200 },
            final_url: "https://example.com/style.css".into(),
            content_type: Some("text/css".into()),
            content_length: None,
            headers: vec![],
            body: Some(decode_probe_body(
                b".x{background:linear-gradient(red,blue);color:#6366f1}".to_vec(),
            )),
        }),
    }
}

fn row<'a>(rows: &'a [CheckResult], id: &str) -> &'a CheckResult {
    rows.iter()
        .find(|row| row.check_id == id)
        .unwrap_or_else(|| panic!("missing {id}"))
}

#[test]
fn cli_and_hosted_paths_count_multi_hue_page_and_stylesheet_gradients_together() {
    // A stylesheet-only or page-only count can make the CLI and hosted gradient verdicts disagree.
    use sitecmd_engine::checks::polish::{
        css_signal_counts, grade_stylesheet_signals, CssTextKind, PolishContext,
    };
    let html = r#"<link rel="stylesheet" href="/site.css"><style>a{background:linear-gradient(red, blue)}</style><i class="from-green-500 to-orange-500"></i>"#;
    let css = "a{background:linear-gradient(rgb(255,0,0),rgb(0,0,255))}".repeat(3);
    let mut hosted = route(html);
    for probe in hosted
        .plan()
        .probes
        .into_iter()
        .filter(|p| p.request.limit == BodyLimit::Stylesheet)
    {
        let mut answer = outcome(3);
        if let ProbeOutcome::Response(response) = &mut answer {
            response.body = Some(decode_probe_body(css.as_bytes().to_vec()));
        }
        hosted.record(Some(vec![ExecutedProbe::new(probe.key, answer)]));
    }
    let hosted_results = hosted.evaluate(&RouteFacts::default()).results;
    let context = PolishContext::new(
        url::Url::parse("https://example.com/page").unwrap(),
        html.into(),
        css_signal_counts(&css, CssTextKind::Stylesheet),
    );
    let cli_results = grade_stylesheet_signals(&context, 1, 1);
    for results in [&cli_results, &hosted_results] {
        let gradient = row(results, "polish.gradient-backgrounds");
        assert_eq!(gradient.status, CheckStatus::Fail);
        assert_eq!(
            gradient.raw_data.as_ref().unwrap()["multi_hue_gradients"],
            5
        );
    }
    assert_eq!(
        serde_json::to_value(row(&cli_results, "polish.gradient-backgrounds")).unwrap(),
        serde_json::to_value(row(&hosted_results, "polish.gradient-backgrounds")).unwrap()
    );
}

#[test]
fn first_eight_stylesheets_are_planned_together_in_document_order() {
    // Sampling in later rounds or URL order would inspect a different stylesheet set.
    let mut route = route(&html());
    let probes: Vec<_> = route
        .plan()
        .probes
        .into_iter()
        .filter(|probe| probe.request.limit == BodyLimit::Stylesheet)
        .collect();
    assert_eq!(probes.len(), 8);
    for (i, probe) in probes.iter().enumerate() {
        let expected = match i {
            2 => "http://127.0.0.1/private.css".into(),
            3..=5 => format!("https://cdn.example.com/s{i}.css"),
            _ => format!("https://example.com/s{i}.css"),
        };
        assert_eq!(probe.request.url, expected);
        assert_eq!(probe.request.method, ProbeMethod::Get);
        assert_eq!(probe.request.body, BodyPolicy::SuccessOnly);
        assert_eq!(probe.request.redirects, RedirectPolicy::Follow);
        assert_eq!(probe.checks.len(), 6);
        route.record(Some(vec![ExecutedProbe::new(
            probe.key.clone(),
            outcome(i),
        )]));
    }
    assert!(!route
        .plan()
        .probes
        .iter()
        .any(|p| p.request.limit == BodyLimit::Stylesheet));
}

#[test]
fn missing_stylesheets_skip_absence_but_preserve_positive_findings() {
    // A 404, oversized body or refused address must not let hosted gradient text or other CSS patterns pass.
    let mut route = route(&html());
    let probes: Vec<_> = route
        .plan()
        .probes
        .into_iter()
        .filter(|probe| probe.request.limit == BodyLimit::Stylesheet)
        .collect();
    assert_eq!(probes.len(), 8);
    for (i, probe) in probes.into_iter().enumerate() {
        route.record(Some(vec![ExecutedProbe::new(probe.key, outcome(i))]));
    }
    let results = route.evaluate(&RouteFacts::default()).results;
    assert_eq!(
        row(&results, "polish.gradient-backgrounds").status,
        CheckStatus::Fail
    );
    for id in [
        "glassmorphism",
        "glow-shadows",
        "excessive-border-radius",
        "floating-blobs",
        "gradient-text",
    ] {
        let row = row(&results, &format!("polish.{id}"));
        assert_eq!(row.status, CheckStatus::Skipped);
        assert!(row.description.contains("5 of 12 linked stylesheets"));
        assert_eq!(row.raw_data.as_ref().unwrap()["stylesheets_fetched"], 5);
        assert_eq!(row.raw_data.as_ref().unwrap()["stylesheets_discovered"], 12);
    }
}

#[test]
fn every_probe_check_has_a_runner_and_no_exclusions_remain() {
    // An exclusion or no_runner entry would silently omit a stylesheet verdict.
    assert!(EXCLUDED_PROBE_CHECKS.is_empty());
    let route = route("");
    assert!(!route
        .plan()
        .not_planned
        .iter()
        .any(|r| r.reason == NotEvaluatedReason::NoRunner));
    let manifest = sitecmd_engine::manifest::capability_manifest();
    let no_runner: Vec<_> = route
        .evaluate(&RouteFacts::default())
        .not_evaluated
        .into_iter()
        .filter(|row| row.reason == NotEvaluatedReason::NoRunner)
        .filter(|row| {
            manifest.entries.iter().any(|entry| {
                entry.check == row.check
                    && entry.hosted == sitecmd_engine::manifest::HostedLane::ProbeAdapter
            })
        })
        .map(|row| row.check)
        .collect();
    assert!(
        no_runner.is_empty(),
        "probe checks without a runner: {no_runner:?}"
    );
}

#[test]
fn complete_declarations_add_but_a_gradient_cannot_span_stylesheets() {
    // Concatenation can invent a gradient declaration across independently read files.
    use sitecmd_engine::checks::polish::{css_signal_counts, CssSignalCounts};
    let sheets = [
        "a{background:linear-gradient(#6366f1,red);backdrop-filter:blur(2px);}",
        "b{border-radius:24px;box-shadow:0 0 8px #ff0000;position: absolute;border-radius: 50%;filter: blur(8px);}",
        "c{position: absolute;border-radius: 50%;filter: blur(8px);}",
    ];
    let sum = sheets
        .iter()
        .fold(CssSignalCounts::default(), |sum, sheet| {
            sum + css_signal_counts(
                sheet,
                sitecmd_engine::checks::polish::CssTextKind::Stylesheet,
            )
        });
    assert_eq!(
        sum,
        css_signal_counts(
            &sheets.join("\n"),
            sitecmd_engine::checks::polish::CssTextKind::Stylesheet
        )
    );
    let left = "a{background:linear-gradient(";
    let right = "#6366f1,red);}";
    assert_eq!(
        (css_signal_counts(
            left,
            sitecmd_engine::checks::polish::CssTextKind::Stylesheet
        ) + css_signal_counts(
            right,
            sitecmd_engine::checks::polish::CssTextKind::Stylesheet
        ))
        .multi_hue_gradients,
        0
    );
    assert_eq!(
        css_signal_counts(
            &format!("{left}\n{right}"),
            sitecmd_engine::checks::polish::CssTextKind::Stylesheet
        )
        .multi_hue_gradients,
        1
    );
}

#[test]
fn absent_empty_and_duplicate_stylesheets_keep_honest_coverage() {
    // An unexecuted read is not a fetched body, while a successful empty body is.
    let mut route =
        route(r#"<link rel="stylesheet" href="/a.css"><link rel="stylesheet" href="/a.css">"#);
    let plan = route.plan();
    let probes: Vec<_> = plan
        .probes
        .into_iter()
        .filter(|p| p.request.limit == BodyLimit::Stylesheet)
        .collect();
    assert_eq!(probes.len(), 1);
    let missing = route.evaluate(&RouteFacts::default()).results;
    assert!(row(&missing, "polish.glassmorphism")
        .description
        .contains("0 of 2 linked stylesheets"));
    let mut empty = outcome(3);
    if let ProbeOutcome::Response(response) = &mut empty {
        response.body = Some(decode_probe_body(vec![]));
    }
    route.record(Some(vec![ExecutedProbe::new(probes[0].key.clone(), empty)]));
    let results = route.evaluate(&RouteFacts::default()).results;
    assert_eq!(
        row(&results, "polish.glassmorphism").status,
        CheckStatus::Pass
    );
    assert_eq!(
        row(
            &route.evaluate(&RouteFacts::default()).results,
            "polish.glassmorphism"
        )
        .status,
        CheckStatus::Pass
    );
}

#[test]
fn all_stylesheet_signals_read_the_sum_of_html_and_separate_stylesheets() {
    // Grading files separately loses findings that need page markup plus stylesheet counts or facts.
    let html = format!(
        "{}{}<i class=\"blob\"></i>",
        (0..3)
            .map(|i| format!(r#"<link rel="stylesheet" href="/s{i}.css">"#))
            .collect::<String>(),
        r#"<i class="bg-gradient-to-r from-purple-500 to-orange-500"></i>"#.repeat(2)
    );
    let mut route = route(&html);
    let text = format!("a{{background:linear-gradient(#6366f1,red);backdrop-filter:blur(2px);box-shadow:0 0 8px #ff0000;position: absolute;border-radius: 50%;filter: blur(2px);background-clip:text;color:transparent;{}}}", "border-radius:24px;".repeat(7));
    for probe in route
        .plan()
        .probes
        .into_iter()
        .filter(|p| p.request.limit == BodyLimit::Stylesheet)
    {
        let mut answer = outcome(3);
        if let ProbeOutcome::Response(response) = &mut answer {
            response.body = Some(decode_probe_body(text.as_bytes().to_vec()));
        }
        route.record(Some(vec![ExecutedProbe::new(probe.key, answer)]));
    }
    let results = route.evaluate(&RouteFacts::default()).results;
    assert_eq!(
        sitecmd_engine::checks::polish::POLISH_SIGNALS
            .iter()
            .filter(|s| s.reads_stylesheets)
            .count(),
        6
    );
    for signal in sitecmd_engine::checks::polish::POLISH_SIGNALS
        .iter()
        .filter(|s| s.reads_stylesheets)
    {
        assert_eq!(
            row(&results, &format!("polish.{}", signal.id)).status,
            CheckStatus::Fail,
            "{}",
            signal.id
        );
    }
}

#[test]
fn cli_and_hosted_paths_agree_on_gradient_text() {
    // Reading gradient text only in inline HTML would miss the hosted stylesheet verdict.
    use sitecmd_engine::checks::polish::{
        css_signal_counts, grade_stylesheet_signals, CssTextKind, PolishContext,
    };
    let html =
        "<link rel='stylesheet' href='/site.css'><h1 style='background-clip:text'>Title</h1>";
    let css = "h1{color:transparent;background:linear-gradient(blue,lightblue)}";
    let mut hosted = route(html);
    for probe in hosted
        .plan()
        .probes
        .into_iter()
        .filter(|p| p.request.limit == BodyLimit::Stylesheet)
    {
        let mut answer = outcome(3);
        if let ProbeOutcome::Response(response) = &mut answer {
            response.body = Some(decode_probe_body(css.as_bytes().to_vec()));
        }
        hosted.record(Some(vec![ExecutedProbe::new(probe.key, answer)]));
    }
    let ctx = PolishContext::new(
        url::Url::parse("https://example.com/page").unwrap(),
        html.into(),
        css_signal_counts(css, CssTextKind::Stylesheet),
    );
    let cli = grade_stylesheet_signals(&ctx, 1, 1);
    let hosted = hosted.evaluate(&RouteFacts::default()).results;
    let expected = row(&cli, "polish.gradient-text");
    assert_eq!(expected.status, CheckStatus::Fail);
    assert_eq!(
        serde_json::to_value(expected).unwrap(),
        serde_json::to_value(row(&hosted, "polish.gradient-text")).unwrap()
    );
}
