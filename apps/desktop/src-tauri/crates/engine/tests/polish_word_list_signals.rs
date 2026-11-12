use sitecmd_engine::checks::polish::{
    copy_content::{ai_buzzword_dictionary, ai_header_formulas},
    framework_defaults::{boilerplate_html, default_deployment_subdomain, default_error_page},
    meta_infra::{default_favicon, default_page_title},
    word_lists::word_lists,
    PolishContext,
};
use std::collections::BTreeSet;

fn context(html: &str, url: &str) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse(url).unwrap(),
        html.to_string().into(),
        Default::default(),
    )
}

fn page(html: &str) -> PolishContext<'static> {
    context(html, "https://fixture.invalid/")
}

fn term_page(term: &str) -> PolishContext<'static> {
    page(&format!("<h1>{}</h1>", format!("{term} ").repeat(16)))
}

#[test]
fn half_point_buzzword_scores_use_the_same_rounding_in_detail_and_data() {
    let html = format!("<p>{}</p>", "revolutionary ".repeat(11));
    let result = ai_buzzword_dictionary(&page(&html));
    assert!(result.fired);
    assert_eq!(result.data["total_score"], 17);
    assert_eq!(result.detail, "Buzzword score 17 (\"revolutionary\" x11)");
}

#[test]
fn database_constraint_documentation_clears_the_buzzword_signal() {
    let html = format!(
        "<article><p>{}The transaction was successful.</p></article>",
        "A unique constraint prevents duplicate values. ".repeat(10)
    );
    assert!(!ai_buzzword_dictionary(&page(&html)).fired);
}

#[test]
fn added_ai_marketing_words_fire_with_their_recorded_weights() {
    let result = ai_buzzword_dictionary(&page(
        "<h1>Delve into intricate possibilities with meticulous care, underscoring pivotal ideas and profound possibilities.</h1>",
    ));
    assert!(result.fired);
    assert_eq!(result.data["total_score"], 18);
    assert_eq!(result.data["words_found"], 6);
    for word in result.data["top_words"].as_array().unwrap() {
        assert_eq!(word["count"], 1);
        assert_eq!(word["weight"], 3);
    }
}

#[test]
fn ordinary_technical_copy_using_dropped_words_clears() {
    let html = format!(
        "<article><p>{}</p></article>",
        "A robust parser reads a comprehensive list. It is crucial to escape input. Leverage multiple processors. ".repeat(10)
    );
    assert!(!ai_buzzword_dictionary(&page(&html)).fired);
}

#[test]
fn pricing_faq_headings_clear_the_formula_signal() {
    assert!(
        !ai_header_formulas(&page(
            "<h3>What happens when my trial ends?</h3><h3>What happens when I cancel?</h3>",
        ))
        .fired
    );
}

#[test]
fn ordinary_faq_questions_match_no_recorded_formula() {
    for heading in [
        "What happens when I cancel?",
        "How do I reset my password?",
        "Which plan is right for me?",
    ] {
        let html = format!("<h2>{heading}</h2><h2>{heading}</h2>");
        assert!(!ai_header_formulas(&page(&html)).fired, "{heading}");
    }
}

#[test]
fn new_headline_formulas_fire_with_editorial_detail() {
    let result = ai_header_formulas(&page(
        "<h2>Not only zephyr teams but solo builders</h2><h2>Future Outlook for zephyr</h2>",
    ));
    assert!(result.fired);
    assert_eq!(result.detail, "2 headings use common headline formulas");
    assert_eq!(result.data["matched_count"], 2);
    assert_eq!(
        result.data["matched_formulas"],
        serde_json::json!(["Not only ... but ...", "Future Outlook"])
    );
    assert!(!result.data.to_string().contains("zephyr"));
    assert!(result.data.get("matched_headers").is_none());
}

#[test]
fn headline_data_records_formula_examples_without_page_copy() {
    let result = ai_header_formulas(&page(
        "<h2>You won't believe zephyr</h2><h2>This will blow your mind about zephyr</h2>",
    ));
    assert!(result.fired);
    assert!(!result.data.to_string().contains("zephyr"));
    assert!(result.data.get("matched_headers").is_none());
    let formulas = result.data["matched_formulas"].as_array().unwrap();
    for formula in word_lists().headline_formulas.iter().take(2) {
        assert!(formulas.iter().any(|example| example == &formula.example));
    }
}

#[test]
fn headline_formula_examples_are_deduplicated_and_capped() {
    let formulas = &word_lists().headline_formulas;
    let html = formulas
        .iter()
        .chain(formulas.iter().take(1))
        .map(|formula| format!("<h2>{}</h2>", formula.example))
        .collect::<String>();
    let result = ai_header_formulas(&page(&html));
    assert_eq!(result.data["matched_count"], formulas.len() + 1);
    assert_eq!(
        result.data["matched_formulas"],
        serde_json::json!(formulas
            .iter()
            .take(5)
            .map(|f| &f.example)
            .collect::<Vec<_>>())
    );
}

#[test]
fn every_marketing_term_fires_the_buzzword_signal() {
    // A signal still reads a deleted list, or misses an entry the recorded list holds.
    for term in &word_lists().marketing_terms {
        let result = ai_buzzword_dictionary(&term_page(&term.value));
        assert!(result.fired, "{}: {}", term.value, result.detail);
        assert!(
            result.data["top_words"]
                .as_array()
                .unwrap()
                .iter()
                .any(|word| word["word"] == term.value),
            "{}",
            term.value
        );
    }
}

#[test]
fn every_term_weighs_as_owner_question_two_answers() {
    // A term can retain its old tier weight instead of its distinct source count.
    for term in &word_lists().marketing_terms {
        let expected = term
            .cites
            .iter()
            .map(|cite| &cite.source)
            .collect::<BTreeSet<_>>()
            .len()
            .min(3) as u32;
        let result = ai_buzzword_dictionary(&term_page(&term.value));
        let word = result.data["top_words"]
            .as_array()
            .unwrap()
            .iter()
            .find(|word| word["word"] == term.value)
            .expect("recorded term counted");
        assert_eq!(word["weight"], expected, "{}", term.value);
        assert_eq!(word["tier"], 4 - expected, "{}", term.value);
    }
}

fn formula_fires(example: &str) {
    let result = ai_header_formulas(&page(&format!("<h2>{example}</h2><h2>{example}</h2>")));
    assert!(result.fired, "{example}: {}", result.detail);
}

#[test]
fn every_formula_example_fires_the_formula_signal() {
    // A headline example or a sourced slot word can be absent from the compiled formulas.
    for formula in &word_lists().headline_formulas {
        formula_fires(&formula.example);
        for (name, words) in &word_lists().headline_word_slots {
            if !formula.pattern.contains(&format!("{{{name}}}")) {
                continue;
            }
            let existing = words
                .iter()
                .find_map(|word| {
                    let pattern =
                        regex::Regex::new(&format!(r"(?i)\b{}\b", regex::escape(&word.value)))
                            .unwrap();
                    pattern
                        .find(&formula.example)
                        .map(|matched| matched.range())
                })
                .expect("the cited example contains its slot word");
            for word in words {
                let mut example = formula.example.clone();
                example.replace_range(existing.clone(), &word.value);
                formula_fires(&example);
            }
        }
    }
}

#[test]
fn every_scaffold_and_placeholder_title_fires_the_title_signal() {
    // Recorded default titles can be missing from the title check.
    for (kind, titles) in [
        ("framework_default", &word_lists().scaffold_titles),
        ("generic_placeholder", &word_lists().placeholder_titles),
    ] {
        for title in titles {
            let result = default_page_title(&page(&format!("<title>{}</title>", title.value)));
            assert!(result.fired, "{}", title.value);
            assert_eq!(result.data["match_kind"], kind, "{}", title.value);
        }
    }
}

#[test]
fn every_scaffold_favicon_fires_the_favicon_signal() {
    // A recorded scaffold icon can be absent from favicon matching.
    for icon in &word_lists().scaffold_favicons {
        let result = default_favicon(&page(&format!(
            r#"<link rel="icon" href="{}">"#,
            icon.value
        )));
        assert!(result.fired, "{}", icon.value);
        assert_eq!(result.data["marker"], icon.value);
    }
}

#[test]
fn two_scaffold_markers_fire_the_boilerplate_signal_and_name_each_marker() {
    // Boilerplate matching can omit recorded markers or replace them with unsourced labels.
    let markers = &word_lists().scaffold_markers;
    for (index, first) in markers.iter().enumerate() {
        for second in &markers[index + 1..] {
            let result = boilerplate_html(&page(&format!("{} {}", first.value, second.value)));
            assert!(result.fired, "{} + {}", first.value, second.value);
            for marker in [&first.value, &second.value] {
                assert!(
                    result.data["markers"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|m| m == marker),
                    "{marker}"
                );
                assert!(result.detail.contains(marker), "{marker}");
            }
        }
    }
}

#[test]
fn every_scaffold_root_id_reads_as_an_empty_root() {
    // An empty recorded scaffold root can be missed by the structural rule.
    for root in &word_lists().scaffold_root_ids {
        let html = format!(
            r#"<meta name="viewport" content="width=device-width, initial-scale=1.0"><div id="{}"></div>"#,
            root.value
        );
        let result = boilerplate_html(&page(&html));
        assert!(result.fired, "{}", root.value);
        assert!(result.data["markers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "Empty root div (SPA scaffold)"));
    }
}

#[test]
fn every_error_page_marker_fires_the_error_page_signal() {
    // A recorded framework error marker can be absent from the error check.
    for marker in &word_lists().error_page_markers {
        let result = default_error_page(&page(&marker.value));
        assert!(result.fired, "{}", marker.value);
        assert_eq!(result.data["marker"], marker.value);
    }
}

#[test]
fn ordinary_help_copy_is_not_a_framework_error_page() {
    // Case-insensitive error markers can report ordinary help copy as a framework error.
    assert!(!default_error_page(&page("<p>You cannot get a refund.</p>")).fired);
}

#[test]
fn every_hosting_suffix_fires_the_subdomain_signal() {
    // A recorded hosting suffix can be missing from shared-subdomain detection.
    for suffix in &word_lists().hosting_suffixes {
        let result =
            default_deployment_subdomain(&context("", &format!("https://site{}/", suffix.value)));
        assert!(result.fired, "{}", suffix.value);
        assert_eq!(
            result.data["platform"],
            suffix.value.trim_start_matches('.')
        );
    }
}

#[test]
fn dropped_defaults_and_unrecorded_terms_do_not_fire() {
    // Removed starter hints and unsourced marketing words can survive in an old dictionary.
    assert!(!ai_buzzword_dictionary(&term_page("robust")).fired);
    for icon in ["/react.svg", "/next.svg"] {
        assert!(!default_favicon(&page(&format!(r#"<link rel="icon" href="{icon}">"#))).fired);
    }
    assert!(!default_page_title(&page("<title>Home</title>")).fired);
    assert!(!default_error_page(&page("<h1>Unhandled Runtime Error</h1>")).fired);
}
