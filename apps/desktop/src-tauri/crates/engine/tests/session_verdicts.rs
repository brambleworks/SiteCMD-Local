//! Cross-page verdicts name the pages they are about, by their position in
//! the input, so a runtime that keeps no addresses can still file each
//! finding on its page.

use sitecmd_engine::session::{analyze_session, SessionPage, SESSION_CHECK_IDS};
use sitecmd_engine::CheckStatus;

fn page(url: &str) -> SessionPage {
    SessionPage {
        url: url.into(),
        requested_url: url.into(),
        status_code: 200,
        title: None,
        meta_description: None,
        h1: None,
        canonical: None,
        noindex: Some(false),
        hreflang: Vec::new(),
        hreflang_truncated: false,
        internal_links: Vec::new(),
        internal_links_truncated: false,
    }
}

fn verdict<'a>(
    analysis: &'a sitecmd_engine::session::SessionAnalysis,
    id: &str,
) -> &'a sitecmd_engine::session::SessionVerdict {
    analysis
        .verdicts
        .iter()
        .find(|verdict| verdict.result.check_id == id)
        .unwrap_or_else(|| panic!("{id} is reported"))
}

#[test]
fn a_shared_title_names_the_pages_that_share_it() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/menu"),
        page("https://example.com/hours"),
    ];
    pages[1].title = Some("Welcome".into());
    pages[2].title = Some("welcome ".into());
    let analysis = analyze_session(&pages, None);
    assert_eq!(analysis.compared, vec![0, 1, 2]);
    let shared = verdict(&analysis, "seo.duplicate_title_across_pages");
    assert_eq!(shared.result.status, CheckStatus::Warn);
    assert_eq!(shared.pages, vec![1, 2]);
}

#[test]
fn a_shared_h1_is_titled_with_the_engine_label() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/menu"),
    ];
    pages[0].h1 = Some("Menu".into());
    pages[1].h1 = Some("Menu".into());
    let analysis = analyze_session(&pages, None);
    assert_eq!(
        verdict(&analysis, "seo.duplicate_h1").result.title,
        "2 pages share the same H1 heading"
    );
}

#[test]
fn a_page_that_answered_an_error_is_left_out_of_the_comparison() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/gone"),
        page("https://example.com/menu"),
    ];
    pages[1].status_code = 404;
    assert_eq!(analyze_session(&pages, None).compared, vec![0, 2]);
}

#[test]
fn one_page_has_nothing_to_compare() {
    let analysis = analyze_session(&[page("https://example.com/")], None);
    assert!(analysis.verdicts.is_empty());
    assert_eq!(analysis.compared, vec![0]);
}

#[test]
fn every_cross_page_check_states_an_outcome_over_two_pages() {
    let pages = vec![
        page("https://example.com/"),
        page("https://example.com/menu"),
    ];
    let analysis = analyze_session(&pages, None);
    for id in SESSION_CHECK_IDS {
        assert!(
            analysis
                .verdicts
                .iter()
                .any(|verdict| verdict.result.check_id == *id),
            "{id} states an outcome"
        );
    }
}

#[test]
fn a_one_way_hreflang_pair_names_both_pages() {
    let mut pages = vec![page("https://example.com/"), page("https://example.com/de")];
    pages[0].hreflang = vec!["https://example.com/de".into()];
    let analysis = analyze_session(&pages, None);
    let one_way = verdict(&analysis, "seo.hreflang_reciprocity");
    assert_eq!(one_way.result.status, CheckStatus::Warn);
    assert_eq!(one_way.pages, vec![0, 1]);
}

#[test]
fn more_alternates_than_a_page_keeps_skips_reciprocity() {
    let mut pages = vec![page("https://example.com/"), page("https://example.com/de")];
    pages[0].hreflang = vec!["https://example.com/de".into()];
    pages[0].hreflang_truncated = true;
    let analysis = analyze_session(&pages, None);
    assert_eq!(
        verdict(&analysis, "seo.hreflang_reciprocity").result.status,
        CheckStatus::Skipped
    );
}

#[test]
fn a_truncated_hreflang_set_on_an_error_page_does_not_withhold_a_one_way_pair() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/de"),
        page("https://example.com/gone"),
    ];
    pages[0].hreflang = vec![pages[1].url.clone()];
    pages[2].status_code = 404;
    pages[2].hreflang_truncated = true;
    let analysis = analyze_session(&pages, None);
    assert_eq!(analysis.compared, vec![0, 1]);
    let one_way = verdict(&analysis, "seo.hreflang_reciprocity");
    assert_eq!(one_way.result.status, CheckStatus::Warn);
    assert_eq!(one_way.pages, vec![0, 1]);
}

#[test]
fn titles_that_differ_only_in_a_replaced_byte_are_not_shared() {
    let mut pages = vec![page("https://example.com/"), page("https://example.com/a")];
    pages[0].title = Some("Caf\u{FFFD} menu".into());
    pages[1].title = Some("Caf\u{FFFD} menu".into());
    let analysis = analyze_session(&pages, None);
    assert_eq!(
        verdict(&analysis, "seo.duplicate_title_across_pages")
            .result
            .status,
        CheckStatus::Pass
    );
}

#[test]
fn a_shared_description_names_input_positions_after_excluded_pages() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/gone"),
        page("https://example.com/menu"),
        page("https://example.com/"),
        page("https://example.com/hours"),
    ];
    pages[1].status_code = 404;
    pages[2].meta_description = Some("Cafe hours".into());
    pages[4].meta_description = Some("Cafe hours".into());
    let analysis = analyze_session(&pages, None);
    assert_eq!(analysis.compared, vec![0, 2, 4]);
    let shared = verdict(&analysis, "seo.duplicate_description_across_pages");
    assert_eq!(shared.result.status, CheckStatus::Warn);
    assert_eq!(shared.pages, vec![2, 4]);
}

#[test]
fn an_orphan_verdict_names_only_the_unlinked_page() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/menu"),
        page("https://example.com/hours"),
        page("https://example.com/about"),
        page("https://example.com/contact"),
    ];
    pages[0].internal_links = pages[2..].iter().map(|page| page.url.clone()).collect();
    let analysis = analyze_session(&pages, None);
    let orphan = verdict(&analysis, "seo.orphan_pages");
    assert_eq!(orphan.result.status, CheckStatus::Warn);
    assert_eq!(orphan.pages, vec![1]);
}

#[test]
fn a_sitemap_contradiction_names_only_the_successful_noindex_page() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/gone"),
        page("https://example.com/menu"),
    ];
    pages[1].status_code = 404;
    pages[1].noindex = Some(true);
    pages[2].noindex = Some(true);
    let urls: Vec<_> = pages.iter().map(|page| page.url.clone()).collect();
    let analysis = analyze_session(
        &pages,
        Some(sitecmd_engine::session::SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    );
    let contradiction = verdict(&analysis, "seo.noindex_in_sitemap");
    assert_eq!(contradiction.result.status, CheckStatus::Warn);
    assert_eq!(contradiction.pages, vec![2]);
}

#[test]
fn a_canonical_cycle_names_each_page_once_before_evidence_redaction() {
    let mut pages = vec![
        page("https://example.com/menu?language=en"),
        page("https://example.com/menu?language=de"),
    ];
    pages[0].canonical = Some(pages[1].url.clone());
    pages[1].canonical = Some(pages[0].url.clone());
    let analysis = analyze_session(&pages, None);
    let cycle = verdict(&analysis, "seo.canonical_loop");
    assert_eq!(cycle.result.status, CheckStatus::Fail);
    assert_eq!(cycle.pages, vec![0, 1]);
}

#[test]
fn a_canonical_chain_names_its_scanned_members_and_leaves_out_its_unscanned_end() {
    let mut pages = vec![
        page("https://example.com/"),
        page("https://example.com/menu"),
    ];
    pages[0].canonical = Some(pages[1].url.clone());
    pages[1].canonical = Some("https://example.com/outside".into());
    let analysis = analyze_session(&pages, None);
    let chain = verdict(&analysis, "seo.canonical_loop");
    assert_eq!(chain.result.status, CheckStatus::Warn);
    assert_eq!(chain.pages, vec![0, 1]);
}
