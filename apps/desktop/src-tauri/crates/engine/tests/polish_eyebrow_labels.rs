use sitecmd_engine::checks::polish::{
    polish_check_result, polish_signal_confidence, run_all_signals, PolishContext, PolishResult,
};
use sitecmd_engine::severity_policy::{web_policy_severity, WebSeverityInput};
use sitecmd_engine::{CheckStatus, IssueConfidence, Severity};

fn signal(html: &str) -> PolishResult {
    run_all_signals(&PolishContext::new(
        url::Url::parse("https://example.com/").unwrap(),
        html.into(),
        Default::default(),
    ))
    .into_iter()
    .find(|r| r.id == "eyebrow-labels")
    .expect("missing eyebrow-labels")
}

#[test]
fn repeated_labels_fire_at_three_but_two_clear() {
    // Labels stacked above every section heading go unreported, or a single kicker is reported.
    let pair = "<p class='uppercase tracking-wide'>Our product</p>\n<h2>Shipping tools</h2>";
    assert!(!signal(&pair.repeat(2)).fired);
    let result = signal(&pair.repeat(3));
    assert!(result.fired);
    assert_eq!(result.data, serde_json::json!({"count":3}));
    assert_eq!(result.detail, "3 short labels sit directly above headings");
}

#[test]
fn labels_must_be_short_text_only_and_adjacent_to_a_heading() {
    // Long labels, nested markup, and intervening content must not count as short heading labels.
    for html in [
        format!("<p class='eyebrow'>{}</p><h2>Heading</h2>", "a".repeat(41)),
        "<p class='eyebrow'>A label</p><p>Body copy</p><h2>Heading</h2>".to_string(),
        "<p class='eyebrow'><b>Label</b></p><h2>Heading</h2>".to_string(),
        "<p>ONE TWO THREE FOUR FIVE SIX</p><h2>Heading</h2>".to_string(),
        "<p class='eyebrow'>Label</p><h4>Heading</h4>".to_string(),
    ] {
        assert_eq!(signal(&html.repeat(3)).data["count"], 0, "{html}");
    }
}

#[test]
fn capitals_and_each_label_element_count_without_css() {
    // Capitalized short kickers must be detected for every supported label element.
    for tag in ["p", "span", "div", "small", "h6"] {
        let html = format!("<{tag}>OUR TOOLS</{tag}><h3>Heading</h3>");
        assert!(signal(&html.repeat(3)).fired, "{tag}");
    }
    assert_eq!(
        signal(&"<p>123</p><h2>Heading</h2>".repeat(3)).data["count"],
        0
    );
}

#[test]
fn attribute_markers_and_entity_decoded_character_limits_are_respected() {
    // Class markers and character limits must be read from a label without counting surrounding markup.
    for class in [
        "uppercase",
        "tracking-wide",
        "tracking-wider",
        "tracking-widest",
        "overline",
        "eyebrow",
        "kicker",
    ] {
        assert!(
            signal(&format!("<small class='{class}'>Our tools</small><h1>Heading</h1>").repeat(3))
                .fired,
            "{class}"
        );
    }
    assert!(
        signal(
            &format!(
                "<span class='kicker'>{}</span><h2>Heading</h2>",
                "&#233;".repeat(40)
            )
            .repeat(3)
        )
        .fired
    );
    let hidden="<!-- <p class='eyebrow'>Label</p><h2>Heading</h2> --><script><p class='eyebrow'>Label</p><h2>Heading</h2></script>";
    assert_eq!(signal(&hidden.repeat(3)).data["count"], 0);
}

#[test]
fn eyebrow_policy_and_confidence_remain_subjective() {
    // Label findings must normalize from Medium to Low and keep the signed aesthetic confidence reason.
    let row = polish_check_result(&signal(&"<p>OUR TOOLS</p><h2>Heading</h2>".repeat(3)));
    assert_eq!(row.status, CheckStatus::Fail);
    assert_eq!(row.severity, Severity::Medium);
    assert_eq!(
        web_policy_severity(&WebSeverityInput::of(&row)),
        Some(Severity::Low)
    );
    assert_eq!(
        polish_signal_confidence("eyebrow-labels"),
        (
            IssueConfidence::NeedsReview,
            Some("Subjective aesthetic signal; legitimate modern designs often match.")
        )
    );
}

#[test]
fn quoted_greater_than_signs_do_not_truncate_label_attributes() {
    // A greater-than sign inside a quoted class must not hide a short heading label.
    let html = r#"<p class="[&>svg]:size-4 uppercase tracking-wide">Our tools</p><h2>Heading</h2>"#
        .repeat(3);
    let result = signal(&html);
    assert!(result.fired);
    assert_eq!(result.data["count"], 3);
}
