// A page's facts report a title length or outcome the title check disagrees with, a hash and a length of two different titles, or a length from an error page.

use serde_json::{json, Value};
use sitecmd_engine::evaluation::{PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::CheckStatus;

fn route(body: &str, status: u16) -> RouteSession {
    RouteSession::open(PageArtifact {
        url: "https://example.com/".into(),
        requested_url: None,
        status_code: status,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: Vec::new(),
        body: body.into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    })
    .expect("route")
}

fn facts(route: &RouteSession) -> Value {
    serde_json::to_value(route.session_page(&[]).expect("facts").expect("named")).expect("JSON")
}

fn assert_grade(body: &str, field: &str, check: &str, length: Option<u32>, outcome: &str) {
    let route = route(body, 200);
    let facts = facts(&route);
    assert_eq!(facts[format!("{field}_chars")], json!(length), "{body}");
    assert_eq!(facts[format!("{field}_outcome")], outcome, "{body}");
    let result = route
        .evaluate(&RouteFacts::default())
        .results
        .into_iter()
        .find(|result| result.check_id == check)
        .expect("check ran");
    let status = match outcome {
        "missing" => CheckStatus::Fail,
        "ok" => CheckStatus::Pass,
        _ => CheckStatus::Warn,
    };
    assert_eq!(result.status, status);
    if let Some(length) = length {
        assert_eq!(result.raw_data.expect("length evidence")["length"], length);
        if outcome == "short" || outcome == "long" {
            assert!(result.title.to_ascii_lowercase().starts_with(outcome));
        }
    } else {
        assert!(result.raw_data.is_none());
    }
}

#[test]
fn title_lengths_and_outcomes_agree_with_the_check_at_every_boundary() {
    for (length, outcome) in [(19, "short"), (20, "ok"), (70, "ok"), (71, "long")] {
        assert_grade(
            &format!("<title>{}</title>", "t".repeat(length)),
            "title",
            "seo.title",
            Some(length as u32),
            outcome,
        );
    }
    assert_grade(
        &format!("<title>{}</title>", "界".repeat(30)),
        "title",
        "seo.title",
        Some(30),
        "ok",
    );
    for body in [
        "",
        "<title>   </title>",
        "<svg><title>Graphic label</title></svg>",
    ] {
        assert_grade(body, "title", "seo.title", None, "missing");
    }
}

#[test]
fn description_lengths_and_outcomes_agree_with_the_untrimmed_check_value() {
    for (length, outcome) in [(49, "short"), (50, "ok"), (170, "ok"), (171, "long")] {
        assert_grade(
            &format!("<meta name='description' content='{}'>", "d".repeat(length)),
            "description",
            "seo.meta_description",
            Some(length as u32),
            outcome,
        );
    }
    for length in [49, 50] {
        assert_grade(
            &format!(
                "<meta name='description' content=' {} '>",
                "d".repeat(length)
            ),
            "description",
            "seo.meta_description",
            Some(length as u32 + 2),
            "ok",
        );
    }
    for body in ["", "<meta name='description' content='   '>"] {
        assert_grade(body, "description", "seo.meta_description", None, "missing");
    }
}

#[test]
fn an_svg_title_cannot_supply_the_digest_or_length() {
    let document = "<title>A real document title</title>";
    let with_svg = format!("<svg><title>{}</title></svg>{document}", "x".repeat(71));
    assert_grade(&with_svg, "title", "seo.title", Some(21), "ok");
    assert_eq!(
        facts(&route(&with_svg, 200))["title"],
        facts(&route(document, 200))["title"]
    );
    assert!(facts(&route("<svg><title>Graphic</title></svg>", 200))["title"].is_null());
}

#[test]
fn title_length_grades_the_raw_title_while_its_digest_compares_collapsed_spaces() {
    let title = format!("{}   {}", "t".repeat(34), "t".repeat(34));
    let body = format!("<title> {title} </title>");
    assert_grade(&body, "title", "seo.title", Some(71), "long");
    let collapsed = format!("<title>{}</title>", title.replace("   ", " "));
    assert_eq!(
        facts(&route(&body, 200))["title"],
        facts(&route(&collapsed, 200))["title"]
    );
    assert_grade(&collapsed, "title", "seo.title", Some(69), "ok");
}

#[test]
fn heading_counts_use_the_check_outline_and_h1_length_uses_the_compared_value() {
    let body = "<h1>  First   <em>heading</em> </h1><h1>Second</h1><h2>Section</h2><script><h3>Example</h3></script><style><h4>Example</h4></style><!-- <h5>Example</h5> -->";
    let facts = facts(&route(body, 200));
    assert_eq!(facts["heading_counts"], json!([2, 1, 0, 0, 0, 0]));
    assert_eq!(facts["h1_chars"], 13);
    assert_eq!(facts["h1"], facts_of_heading("First heading")["h1"]);
    let absent = facts_of_heading("");
    assert_eq!(absent["h1_chars"], Value::Null);
}

fn facts_of_heading(heading: &str) -> Value {
    facts(&route(&format!("<h1>{heading}</h1>"), 200))
}

#[test]
fn a_long_description_reports_the_fact_bound_and_its_original_grade() {
    // An oversized description makes the hosted projection refuse the step.
    for length in [100_000, 100_001] {
        let route = route(
            &format!("<meta name='description' content='{}'>", "d".repeat(length)),
            200,
        );
        let facts = facts(&route);
        assert_eq!(facts["description_chars"], 100_000);
        assert_eq!(facts["description_outcome"], "long");
        let result = route
            .evaluate(&RouteFacts::default())
            .results
            .into_iter()
            .find(|result| result.check_id == "seo.meta_description")
            .expect("description check");
        assert_eq!(result.raw_data.expect("length")["length"], length);
        assert_eq!(result.status, CheckStatus::Warn);
    }
}

#[test]
fn a_long_title_reports_the_fact_bound_and_its_original_grade() {
    // An oversized title exceeds the bound even when its outcome is correctly long.
    let route = route(&format!("<title>{}</title>", "t".repeat(100_001)), 200);
    let facts = facts(&route);
    assert_eq!(facts["title_chars"], 100_000);
    assert_eq!(facts["title_outcome"], "long");
    let result = route
        .evaluate(&RouteFacts::default())
        .results
        .into_iter()
        .find(|result| result.check_id == "seo.title")
        .expect("title check");
    assert_eq!(result.raw_data.expect("length")["length"], 100_001);
    assert_eq!(result.status, CheckStatus::Warn);
}

#[test]
fn a_long_compared_heading_reports_the_fact_bound() {
    // An oversized compared H1 exceeds the hosted field bound.
    let facts = facts_of_heading(&"h".repeat(100_001));
    assert_eq!(facts["h1_chars"], 100_000);
    assert_eq!(facts["heading_counts"], json!([1, 0, 0, 0, 0, 0]));
}

#[test]
fn heading_counts_saturate_instead_of_wrapping() {
    let body = "<h6>Section</h6>".repeat(65_536);
    assert_eq!(
        facts(&route(&body, 200))["heading_counts"],
        json!([0, 0, 0, 0, 0, 65_535])
    );
}

#[test]
fn error_status_keeps_no_lengths_outcomes_or_heading_counts_from_the_body() {
    let facts = facts(&route(
        "<title>Not found</title><meta name='description' content='Error'><h1>Gone</h1>",
        404,
    ));
    for field in ["title_chars", "description_chars", "h1_chars"] {
        assert_eq!(facts.get(field), Some(&Value::Null), "{field}");
    }
    for field in ["title_outcome", "description_outcome"] {
        assert_eq!(facts[field], "missing");
    }
    assert_eq!(facts["heading_counts"], json!([0, 0, 0, 0, 0, 0]));
}
