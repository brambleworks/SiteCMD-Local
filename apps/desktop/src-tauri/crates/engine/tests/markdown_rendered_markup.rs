use sitecmd_engine::evaluation::{evaluate, EvaluationRequest, PageArtifact};
use sitecmd_engine::{CheckResult, CheckStatus};

fn rows(html: String) -> Vec<CheckResult> {
    evaluate(&EvaluationRequest {
        page: PageArtifact {
            url: "https://example.com/article".into(),
            requested_url: Some("https://example.com/article".into()),
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: html,
            evaluation_time: "2026-10-30T00:00:00Z".parse().expect("static time"),
        },
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        negotiated_protocol: None,
        probe_outcomes: None,
        browser_facts: None,
    })
    .expect("fixture evaluates")
    .results
}

fn row<'a>(rows: &'a [CheckResult], id: &str) -> &'a CheckResult {
    rows.iter()
        .find(|row| row.check_id == id)
        .expect("check ran")
}

fn task_list(markers: &str) -> String {
    format!(
        "<ul>{}</ul>",
        format!("<li><input type=\"checkbox\" {markers}> item</li>").repeat(8)
    )
}

#[test]
fn disabled_hidden_task_list_checkboxes_need_no_label() {
    // Markdown task-list checkboxes are reported as form fields with no label.
    let rows = rows(task_list("disabled aria-hidden=\"true\""));
    assert_eq!(
        row(&rows, "accessibility.form_labels").status,
        CheckStatus::Pass
    );
    assert_eq!(
        row(&rows, "polish.form-accessibility").status,
        CheckStatus::Pass
    );
}

#[test]
fn disabled_checkboxes_assistive_technology_still_reads_need_a_label() {
    // Markdown task-list checkboxes are reported as form fields with no label.
    let rows = rows(task_list("disabled"));
    let labels = row(&rows, "accessibility.form_labels");
    assert_eq!(labels.status, CheckStatus::Fail);
    assert_eq!(labels.raw_data.as_ref().expect("counts")["unlabeled"], 8);
    assert_eq!(
        row(&rows, "polish.form-accessibility").status,
        CheckStatus::Fail
    );
}

#[test]
fn an_unlabeled_text_input_beside_a_task_list_still_fails() {
    // Markdown task-list checkboxes are reported as form fields with no label.
    let rows = rows(task_list("disabled aria-hidden=\"true\"") + "<input type=\"text\">");
    let labels = row(&rows, "accessibility.form_labels");
    assert_eq!(labels.status, CheckStatus::Fail);
    let counts = labels.raw_data.as_ref().expect("counts");
    assert_eq!(counts["inputs"], 1);
    assert_eq!(counts["unlabeled"], 1);
    assert_eq!(
        row(&rows, "polish.form-accessibility").status,
        CheckStatus::Fail
    );
}

#[test]
fn only_both_markers_together_skip_a_control() {
    // Markdown task-list checkboxes are reported as form fields with no label.
    for (markers, skipped) in [
        ("disabled aria-hidden=\"false\"", false),
        ("aria-hidden=\"true\"", false),
        ("disabled aria-hidden=\"TRUE\"", true),
        ("DISABLED ARIA-HIDDEN='TrUe'", true),
        ("disabled aria-hidden=true", true),
        ("data-disabled aria-hidden=true", false),
        ("disabled data-aria-hidden=true", false),
        ("data-note='disabled' aria-hidden=true", false),
        ("disabled aria-hidden=trueish", false),
    ] {
        let rows = rows(task_list(markers));
        for id in ["accessibility.form_labels", "polish.form-accessibility"] {
            assert_eq!(
                row(&rows, id).status == CheckStatus::Fail,
                !skipped,
                "{markers}: {id}"
            );
        }
        if !skipped {
            let counts = row(&rows, "accessibility.form_labels")
                .raw_data
                .as_ref()
                .expect("counts");
            assert_eq!(counts["inputs"], 8);
            assert_eq!(counts["unlabeled"], 8);
        }
    }
}

#[test]
fn code_block_spans_are_not_inline_styles() {
    // A highlighted code block's colored spans are counted as hand-written inline styles.
    let html = format!(
        "{}<pre class=\"astro-code\">{}</pre>",
        "<p>text</p>".repeat(249),
        "<span style=\"color: red\">code</span>".repeat(50)
    );
    let rows = rows(html);
    assert_eq!(
        row(&rows, "polish.inline-style-density").status,
        CheckStatus::Pass
    );
}

#[test]
fn the_same_styles_outside_a_code_block_still_fire() {
    // A highlighted code block's colored spans are counted as hand-written inline styles.
    let html = "<p>text</p>".repeat(250) + &"<div style=\"color: red\">text</div>".repeat(50);
    let rows = rows(html);
    let density = row(&rows, "polish.inline-style-density");
    assert_eq!(density.status, CheckStatus::Fail);
    let counts = density.raw_data.as_ref().expect("counts");
    assert_eq!(counts["inline_style_count"], 50);
    assert_eq!(counts["total_elements"], 300);
}

#[test]
fn an_unclosed_code_block_still_returns_a_verdict() {
    // An unclosed pre must not hang or hide the rest of the page.
    let span = "<span style=\"color: red\">code</span>";
    let html = "<pre>".to_string() + &span.repeat((1024_usize * 1024).div_ceil(span.len()));
    let rows = rows(html);
    assert_eq!(
        row(&rows, "polish.inline-style-density").status,
        CheckStatus::Fail
    );
}

#[test]
fn code_block_elements_do_not_dilute_styles_elsewhere() {
    // A highlighted code block's colored spans are counted as hand-written inline styles.
    let html = format!(
        "<PRE class='astro-code'>{}</PRE>{}{}",
        "<span>code</span>".repeat(300),
        "<p>text</p>".repeat(250),
        "<div style=\"color: red\">text</div>".repeat(50)
    );
    let rows = rows(html);
    let density = row(&rows, "polish.inline-style-density");
    assert_eq!(density.status, CheckStatus::Fail);
    assert_eq!(
        density.raw_data.as_ref().expect("counts")["total_elements"],
        300
    );
}

#[test]
fn similarly_named_elements_keep_their_inline_styles() {
    // A highlighted code block's colored spans are counted as hand-written inline styles.
    let html = format!(
        "{}<pre-view>{}</pre-view><pre>x</pre>",
        "<p>text</p>".repeat(249),
        "<span style=\"color: red\">text</span>".repeat(50)
    );
    let rows = rows(html);
    assert_eq!(
        row(&rows, "polish.inline-style-density").status,
        CheckStatus::Fail
    );
}
