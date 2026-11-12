use super::*;
use crate::checks::polish::{grade_stylesheet_signals, PolishContext};
use sitecmd_engine::evaluation::{ExecutedProbe, PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::probe::{
    decode_probe_body, BodyLimit, ProbeFailure, ProbeFailureClass, ProbeOutcome, ProbeResponse,
};

#[derive(Clone, Copy)]
enum Fixture {
    SplitGradient,
    MissingStylesheets,
    TailwindV3,
}

fn answer(url: &str, fixture: Fixture) -> ProbeOutcome {
    let incomplete = matches!(fixture, Fixture::MissingStylesheets);
    let index = url
        .rsplit('/')
        .next()
        .unwrap()
        .trim_start_matches('s')
        .trim_end_matches(".css")
        .parse::<usize>()
        .unwrap();
    if incomplete && matches!(index, 1 | 2) {
        return ProbeOutcome::Failure(ProbeFailure {
            class: if index == 1 {
                ProbeFailureClass::BodyCapExceeded
            } else {
                ProbeFailureClass::Transport
            },
            detail: "stylesheet unavailable".into(),
        });
    }
    let text = if matches!(fixture, Fixture::TailwindV3) {
        r#"*,::before,::after{--tw-backdrop-blur: ;}::backdrop{--tw-backdrop-blur: ;}
        .backdrop-blur-md{--tw-backdrop-blur:blur(12px);-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness)}"#
    } else if !incomplete && index == 0 {
        "a{background:linear-gradient("
    } else if !incomplete && index == 1 {
        "#6366f1,red);}"
    } else {
        "a{background:linear-gradient(#6366f1,red);}"
    };
    ProbeOutcome::Response(ProbeResponse {
        status: if incomplete && index == 0 { 404 } else { 200 },
        final_url: url.into(),
        content_type: Some("text/css".into()),
        content_length: None,
        headers: vec![],
        body: Some(decode_probe_body(text.as_bytes().to_vec())),
    })
}

#[tokio::test]
async fn cli_transport_and_hosted_readings_grade_identically() {
    // Compiled stylesheet tokens, joined declarations or unread CSS must not change parity.
    for fixture in [
        Fixture::SplitGradient,
        Fixture::MissingStylesheets,
        Fixture::TailwindV3,
    ] {
        let incomplete = matches!(fixture, Fixture::MissingStylesheets);
        let tailwind = matches!(fixture, Fixture::TailwindV3);
        let linked = if tailwind {
            1
        } else if incomplete {
            12
        } else {
            8
        };
        let fetched_count = if tailwind {
            1
        } else if incomplete {
            5
        } else {
            8
        };
        let base = url::Url::parse("https://example.com/page").unwrap();
        let mut html: String = (0..linked)
            .map(|i| {
                let host = match i {
                    2 if incomplete => "http://127.0.0.1",
                    3..=5 => "https://cdn.example.com",
                    _ => "",
                };
                format!(r#"<link rel="stylesheet" href="{host}/s{i}.css">"#)
            })
            .collect();
        if tailwind {
            html.push_str(r#"<header class="sticky top-0 backdrop-blur-md"></header>"#);
        }
        let requested = std::sync::Mutex::new(Vec::new());
        let fetched = fetch_stylesheets_with(
            &html,
            &base,
            crate::network_policy::LocalOrigin::Public,
            |url| {
                requested.lock().unwrap().push(url.clone());
                async move {
                    match answer(&url, fixture) {
                        ProbeOutcome::Response(response) if response.status == 200 => {
                            Some(response.body.unwrap().text)
                        }
                        _ => None,
                    }
                }
            },
        )
        .await;
        let requested = requested.into_inner().unwrap();
        assert_eq!(requested.len(), if incomplete { 7 } else { linked });
        assert!(!requested.iter().any(|url| url.contains("127.0.0.1")));
        assert_eq!(fetched.stylesheets_fetched, fetched_count);
        let ctx = PolishContext::new(base, html.clone().into(), fetched.counts);
        let cli = grade_stylesheet_signals(
            &ctx,
            fetched.stylesheets_discovered,
            fetched.stylesheets_fetched,
        );
        let mut route = RouteSession::open(
            serde_json::from_value::<PageArtifact>(serde_json::json!({
                "url": "https://example.com/page", "status_code": 200, "headers": [],
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
                answer(&probe.request.url, fixture),
            )]));
        }
        let hosted: Vec<_> = route
            .evaluate(&RouteFacts::default())
            .results
            .into_iter()
            .filter(|r| cli.iter().any(|c| c.check_id == r.check_id))
            .collect();
        if tailwind {
            for (lane, rows) in [("CLI", &cli), ("hosted", &hosted)] {
                let blur = rows
                    .iter()
                    .find(|row| row.check_id == "polish.glassmorphism")
                    .unwrap();
                assert_eq!(
                    blur.status,
                    crate::checks::CheckStatus::Pass,
                    "{lane} must clear one HTML blur utility with its compiled stylesheet"
                );
            }
        }
        assert_eq!(
            serde_json::to_value(&cli).unwrap(),
            serde_json::to_value(&hosted).unwrap()
        );
        if !tailwind {
            assert_eq!(
                cli[0].raw_data.as_ref().unwrap()["multi_hue_gradients"],
                if incomplete { 5 } else { 6 }
            );
        }
        if incomplete {
            assert!(cli[1].description.contains("5 of 12 linked stylesheets"));
        }
    }
}
