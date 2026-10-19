//! Cross-page session analysis tests.

use super::*;

fn page(url: &str) -> PageSignals {
    PageSignals {
        url: url.to_string(),
        requested_url: url.to_string(),
        status_code: 200,
        title: None,
        meta_description: None,
        h1: None,
        canonical: None,
        noindex: Some(false),
        hreflang: Vec::new(),
        internal_links: Vec::new(),
        internal_links_truncated: false,
    }
}

/// A page the scan asked for at one URL and reached at another.
fn redirected_page(requested_url: &str, url: &str) -> PageSignals {
    PageSignals {
        requested_url: requested_url.to_string(),
        ..page(url)
    }
}

/// A selected URL that answered with an error status.
fn error_page(url: &str, status_code: u16) -> PageSignals {
    PageSignals {
        status_code,
        ..page(url)
    }
}

/// A sitemap URL set SiteCMD read in full.
fn whole_sitemap(urls: &[String]) -> SessionSitemap<'_> {
    SessionSitemap {
        urls,
        partial_because: None,
    }
}

fn compare_with_whole_sitemap(pages: &[PageSignals]) -> Vec<CheckResult> {
    let urls: Vec<_> = pages.iter().map(|page| page.url.clone()).collect();
    analyze_session(pages, Some(whole_sitemap(&urls)))
}

#[test]
fn single_page_sessions_emit_nothing() {
    let pages = vec![page("https://a.com")];
    assert!(analyze_session(&pages, None).is_empty());
}

#[test]
fn duplicate_titles_grouped_case_insensitively() {
    let mut a = page("https://a.com/1");
    a.title = Some("Welcome".into());
    let mut b = page("https://a.com/2");
    b.title = Some("welcome".into());
    let mut c = page("https://a.com/3");
    c.title = Some("Unique".into());
    let results = analyze_session(&[a, b, c], None);
    let dup = results
        .iter()
        .find(|r| r.check_id == "seo.duplicate_title_across_pages")
        .expect("duplicate title finding");
    assert_eq!(dup.status, CheckStatus::Warn);
    assert!(dup.description.contains("welcome"));
    assert_eq!(dup.confidence, IssueConfidence::NeedsReview);
    assert!(!dup.description.contains("compete with each other"));
    assert_eq!(
        outcome(&results, "seo.duplicate_h1").status,
        CheckStatus::Pass
    );
}

#[test]
fn duplicate_descriptions_use_a_cross_page_identity() {
    let mut a = page("https://a.com/1");
    a.meta_description = Some("Shared summary".into());
    let mut b = page("https://a.com/2");
    b.meta_description = Some("shared summary".into());

    let results = analyze_session(&[a, b], None);

    assert!(results
        .iter()
        .any(|result| result.check_id == "seo.duplicate_description_across_pages"));
    assert!(!results
        .iter()
        .any(|result| result.check_id == "seo.duplicate_description"));
}

#[test]
fn duplicate_h1_copy_does_not_claim_the_heading_is_a_search_snippet() {
    let mut a = page("https://a.com/1");
    a.h1 = Some("Documentation".into());
    let mut b = page("https://a.com/2");
    b.h1 = Some("documentation".into());
    let finding = analyze_session(&[a, b], None)
        .into_iter()
        .find(|result| result.check_id == "seo.duplicate_h1")
        .expect("duplicate H1 finding");
    assert!(finding.description.contains("initial HTML"));
    assert!(!finding.description.contains("search results"));
}

#[test]
fn orphans_need_minimum_pages_and_skip_entry_page() {
    let mut home = page("https://a.com/");
    home.internal_links = vec![
        "https://a.com/x".into(),
        "https://a.com/y".into(),
        "https://a.com/z".into(),
    ];
    let x = page("https://a.com/x");
    let y = page("https://a.com/y");
    let z = page("https://a.com/z");
    let orphan = page("https://a.com/lost");
    let results = compare_with_whole_sitemap(&[home, x, y, z, orphan]);
    let finding = results
        .iter()
        .find(|r| r.check_id == "seo.orphan_pages")
        .expect("orphan finding");
    assert!(finding.description.contains("https://a.com/lost"));
    assert_eq!(finding.confidence, IssueConfidence::NeedsReview);
    assert!(!finding
        .description
        .contains("only reachable through the sitemap"));
    assert!(!finding
        .why_it_matters
        .as_deref()
        .unwrap_or("")
        .contains("entirely"));
}

#[test]
fn noindex_in_sitemap_contradiction_detected() {
    let mut a = page("https://a.com/private");
    a.noindex = Some(true);
    let b = page("https://a.com/public");
    let sitemap = vec![
        "https://a.com/private/".to_string(),
        "https://a.com/public".to_string(),
    ];
    let results = analyze_session(&[a, b], Some(whole_sitemap(&sitemap)));
    let finding = results
        .iter()
        .find(|r| r.check_id == "seo.noindex_in_sitemap")
        .expect("noindex finding");
    assert!(finding.description.contains("/private"));
    assert!(finding.description.contains("intent needs review"));
    assert!(!finding.description.contains("wastes crawl attention"));
}

#[test]
fn canonical_two_page_loop_reported_once() {
    let mut a = page("https://a.com/a");
    a.canonical = Some("https://a.com/b".into());
    let mut b = page("https://a.com/b");
    b.canonical = Some("https://a.com/a".into());
    let results = analyze_session(&[a, b], None);
    let finding = results
        .iter()
        .find(|r| r.check_id == "seo.canonical_loop")
        .expect("canonical loop finding");
    assert_eq!(finding.status, CheckStatus::Fail);
    assert!(finding.description.contains("initial-HTML canonical"));
    assert!(!finding.description.contains("unpredictably"));
    assert_eq!(
        finding.raw_data.as_ref().unwrap()["loops"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn indirect_canonical_chain_is_a_review_warning_not_a_loop_failure() {
    let mut a = page("https://a.com/a");
    a.canonical = Some("https://a.com/b".into());
    let mut b = page("https://a.com/b");
    b.canonical = Some("https://a.com/c".into());
    let c = page("https://a.com/c");
    let finding = analyze_session(&[a, b, c], None)
        .into_iter()
        .find(|result| result.check_id == "seo.canonical_loop")
        .expect("canonical chain finding");
    assert_eq!(finding.status, CheckStatus::Warn);
    assert!(finding.title.contains("chain"));
    assert!(finding.description.contains("can still settle"));
}

#[test]
fn three_page_canonical_cycle_is_classified_as_a_cycle() {
    let mut a = page("https://a.com/a");
    a.canonical = Some("https://a.com/b".into());
    let mut b = page("https://a.com/b");
    b.canonical = Some("https://a.com/c".into());
    let mut c = page("https://a.com/c");
    c.canonical = Some("https://a.com/a".into());
    let finding = analyze_session(&[a, b, c], None)
        .into_iter()
        .find(|result| result.check_id == "seo.canonical_loop")
        .expect("canonical cycle finding");
    assert_eq!(finding.status, CheckStatus::Fail);
    assert!(finding.title.contains("cycle"));
    assert_eq!(
        finding.raw_data.as_ref().unwrap()["loops"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn session_evidence_removes_query_values_but_keeps_useful_page_paths() {
    let mut home = page("https://a.com/");
    home.internal_links = vec![
        "https://a.com/x".into(),
        "https://a.com/y".into(),
        "https://a.com/z".into(),
    ];
    let x = page("https://a.com/x");
    let y = page("https://a.com/y");
    let z = page("https://a.com/z");
    let orphan = page("https://a.com/lost?token=secret#fragment");
    let finding = compare_with_whole_sitemap(&[home, x, y, z, orphan])
        .into_iter()
        .find(|result| result.check_id == "seo.orphan_pages")
        .expect("orphan finding");
    let serialized = serde_json::to_string(&finding).unwrap();
    assert!(serialized.contains("/lost"));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("fragment"));
}

#[test]
fn hreflang_missing_return_link_flagged_only_for_scanned_targets() {
    let mut en = page("https://a.com/en");
    en.hreflang = vec![
        ("de".into(), "https://a.com/de".into()),
        ("fr".into(), "https://a.com/fr".into()),
    ];
    let de = page("https://a.com/de"); // scanned, no return link
    let results = analyze_session(&[en, de], None);
    let finding = results
        .iter()
        .find(|r| r.check_id == "seo.hreflang_reciprocity")
        .expect("hreflang finding");
    // The fr target was not scanned, so only the de pair is reported.
    let missing = finding.raw_data.as_ref().unwrap()["missing_return_links"]
        .as_array()
        .unwrap();
    assert_eq!(missing.len(), 1);
    assert!(missing[0].as_str().unwrap().contains("/de"));
    assert_eq!(finding.confidence, IssueConfidence::NeedsReview);
    assert!(finding.description.contains("initial-HTML"));
    assert!(!finding.description.contains("silently does nothing"));
}

#[test]
fn self_referencing_canonicals_and_reciprocal_hreflang_pass() {
    let mut a = page("https://a.com/a");
    a.canonical = Some("https://a.com/a".into());
    a.hreflang = vec![
        ("en".into(), "https://a.com/a".into()),
        ("de".into(), "https://a.com/b".into()),
    ];
    let mut b = page("https://a.com/b");
    b.hreflang = vec![
        ("de".into(), "https://a.com/b".into()),
        ("en".into(), "https://a.com/a".into()),
    ];
    let results = analyze_session(&[a, b], None);
    assert_eq!(
        outcome(&results, "seo.canonical_loop").status,
        CheckStatus::Pass
    );
    assert_eq!(
        outcome(&results, "seo.hreflang_reciprocity").status,
        CheckStatus::Pass
    );
}

// The one row for a check. Every session check reports exactly one
// outcome per run, which is what makes coverage derivable from them.
fn outcome<'a>(results: &'a [CheckResult], check_id: &str) -> &'a CheckResult {
    let mut matching = results.iter().filter(|r| r.check_id == check_id);
    let found = matching
        .next()
        .unwrap_or_else(|| panic!("{check_id} reported no outcome"));
    assert!(
        matching.next().is_none(),
        "{check_id} reported more than one outcome"
    );
    found
}

#[test]
fn an_outcome_row_names_what_it_checked_not_its_check_id() {
    let mut a = page("https://a.com/1");
    a.title = Some("One".into());
    let mut b = page("https://a.com/2");
    b.title = Some("Two".into());

    let results = analyze_session(&[a, b], None);
    let clean = outcome(&results, "seo.duplicate_h1");

    assert_eq!(
        clean.title,
        "No shared H1 headings across the scanned pages"
    );
    assert!(!clean.description.contains("seo."));
}

#[test]
fn every_session_check_reports_an_outcome() {
    let mut a = page("https://a.com/1");
    a.title = Some("One".into());
    let mut b = page("https://a.com/2");
    b.title = Some("Two".into());

    let results = analyze_session(&[a, b], None);

    for check_id in SESSION_CHECK_IDS {
        let result = outcome(&results, check_id);
        assert!(
            matches!(result.status, CheckStatus::Pass | CheckStatus::Skipped),
            "{check_id} reported {:?} on a clean two-page set",
            result.status
        );
    }
}

#[test]
fn a_check_whose_inputs_were_missing_reports_skipped_not_pass() {
    let mut a = page("https://a.com/1");
    a.title = Some("One".into());
    let mut b = page("https://a.com/2");
    b.title = Some("Two".into());

    let results = analyze_session(&[a, b], None);

    assert_eq!(
        outcome(&results, "seo.orphan_pages").status,
        CheckStatus::Skipped
    );
    assert_eq!(
        outcome(&results, "seo.noindex_in_sitemap").status,
        CheckStatus::Skipped
    );
}

#[test]
fn a_supplied_sitemap_with_no_contradiction_reports_pass() {
    let mut a = page("https://a.com/1");
    a.title = Some("One".into());
    let b = page("https://a.com/2");

    let sitemap = ["https://a.com/1".to_string()];
    let results = analyze_session(&[a, b], Some(whole_sitemap(&sitemap)));

    assert_eq!(
        outcome(&results, "seo.noindex_in_sitemap").status,
        CheckStatus::Pass
    );
}

// Session signals preserve page identity and observed HTML navigation.

fn signals_for(url: &str, body: &str) -> PageSignals {
    crate::core::page_signals::extract_page_signals(&url::Url::parse(url).unwrap(), body)
}

fn raw_strings(result: &CheckResult, key: &str) -> Vec<String> {
    result.raw_data.as_ref().unwrap()[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn review_normalize_page_url_collapses_only_fragment_host_case_default_port_and_trailing_slash() {
    // Collapsed into one identity.
    assert_eq!(normalize_page_url("https://A.com/x/"), "https://a.com/x");
    assert_eq!(normalize_page_url("https://a.com/x#top"), "https://a.com/x");
    assert_eq!(normalize_page_url("https://a.com:443/x"), "https://a.com/x");
    // Kept as distinct identities by every session check.
    let distinct = [
        ("https://a.com/blog?page=2", "https://a.com/blog"),
        ("https://a.com/blog/?page=2", "https://a.com/blog?page=2"),
        ("https://a.com/x?utm_source=mail", "https://a.com/x"),
        ("http://a.com/x", "https://a.com/x"),
        ("https://www.a.com/x", "https://a.com/x"),
        ("https://a.com/X", "https://a.com/x"),
    ];
    for (left, right) in distinct {
        assert_ne!(
            normalize_page_url(left),
            normalize_page_url(right),
            "{left} vs {right}"
        );
    }
}

#[test]
fn review_defect_one_page_reached_twice_is_reported_as_its_own_duplicate() {
    // The scope keeps `/about` and `/about/` as two routes (the engine's
    // canonical_path preserves a trailing slash), and a stale sitemap keeps
    // `/old` beside `/new` after `/old` starts redirecting. Both selections
    // arrive here with the same post-redirect normalized url and identical
    // metadata, so every duplicate check should see one page, not two.
    let mut home = page("https://a.com/");
    home.title = Some("Acme".into());
    let mut about = page("https://a.com/about");
    about.title = Some("About Acme".into());
    about.meta_description = Some("Who we are".into());
    about.h1 = Some("About".into());
    let about_again = about.clone();

    let results = analyze_session(&[home, about, about_again], None);

    for check_id in [
        "seo.duplicate_title_across_pages",
        "seo.duplicate_description_across_pages",
        "seo.duplicate_h1",
    ] {
        assert_eq!(
            outcome(&results, check_id).status,
            CheckStatus::Pass,
            "{check_id} reported one page as a duplicate of itself"
        );
    }
}

#[test]
fn review_site_wide_title_suffix_and_blank_titles_are_not_duplicates() {
    let mut a = page("https://a.com/1");
    a.title = Some("Home | Acme".into());
    let mut b = page("https://a.com/2");
    b.title = Some("About | Acme".into());
    let mut c = page("https://a.com/3");
    c.title = Some("   ".into());
    let d = page("https://a.com/4");
    let mut e = page("https://a.com/5");
    e.title = Some(String::new());

    let results = analyze_session(&[a, b, c, d, e], None);

    assert_eq!(
        outcome(&results, "seo.duplicate_title_across_pages").status,
        CheckStatus::Pass
    );
}

#[test]
fn review_noindex_and_canonicalized_pages_are_left_out_of_duplicate_groups() {
    // A print view that canonicalizes to the product page has already named
    // its representative, and a noindex thank-you page is not competing for
    // the title. Neither is a duplicate-title defect, so the group holding
    // only the product page is not a group at all.
    let mut product = page("https://a.com/product");
    product.title = Some("Widget".into());
    product.canonical = Some("https://a.com/product".into());
    let mut print_view = page("https://a.com/product/print");
    print_view.title = Some("Widget".into());
    print_view.canonical = Some("https://a.com/product".into());
    let mut thank_you = page("https://a.com/thank-you");
    thank_you.title = Some("Widget".into());
    thank_you.noindex = Some(true);

    let results = analyze_session(&[product, print_view, thank_you], None);
    let finding = outcome(&results, "seo.duplicate_title_across_pages");

    assert_eq!(finding.status, CheckStatus::Pass, "{}", finding.description);
}

#[test]
fn two_indexable_pages_that_do_not_canonicalize_to_each_other_still_group() {
    // The exclusions above must not swallow the case the check exists for: a
    // page whose canonical points outside its group, and a page with no
    // canonical at all, are both still competing for the same title.
    let mut a = page("https://a.com/a");
    a.title = Some("Widget".into());
    a.canonical = Some("https://a.com/elsewhere".into());
    let mut b = page("https://a.com/b");
    b.title = Some("Widget".into());

    let results = analyze_session(&[a, b], None);
    let finding = outcome(&results, "seo.duplicate_title_across_pages");

    assert_eq!(finding.status, CheckStatus::Warn);
    assert!(finding.title.starts_with("2 pages"), "{}", finding.title);
    assert_eq!(
        finding.raw_data.as_ref().unwrap()["canonical_relationships_considered"],
        serde_json::json!(true)
    );
}

#[test]
fn review_inbound_links_count_nofollow_template_noscript_and_same_site_scheme_or_host_twins() {
    // A site reached at https://a.com links to itself as http://a.com/... and
    // https://www.a.com/... . Those are the same pages, so the twins are folded
    // onto the scanned origin and the pages they point at are linked pages. An
    // anchor written inside a script is a markup example, not navigation, and a
    // genuinely different host is still foreign.
    let home = signals_for(
        "https://a.com/",
        r#"<nav><a href="/nav" rel="nofollow">nav</a></nav>
           <template><a href="/in-template">t</a></template>
           <noscript><a href="/in-noscript">n</a></noscript>
           <script>document.write('<a href="/in-script">s</a>')</script>
           <a href="http://a.com/http-twin">h</a>
           <a href="https://www.a.com/www-twin">w</a>
           <a href="https://other.com/elsewhere">o</a>
           <a href="https://a.com.evil.test/lookalike">e</a>
           <footer><a href="/footer/">f</a></footer>"#,
    );
    // Links written on the scanned origin come first; folded twins follow, so a
    // twin can never take a slot under the per-page cap from a real link.
    assert_eq!(
        home.internal_links,
        vec![
            "https://a.com/nav",
            "https://a.com/in-template",
            "https://a.com/in-noscript",
            "https://a.com/footer",
            "https://a.com/http-twin",
            "https://a.com/www-twin",
        ]
    );

    let pages = vec![
        home,
        page("https://a.com/nav"),
        page("https://a.com/in-template"),
        page("https://a.com/http-twin"),
        page("https://a.com/www-twin"),
        page("https://a.com/footer"),
    ];
    let results = compare_with_whole_sitemap(&pages);

    assert_eq!(
        outcome(&results, "seo.orphan_pages").status,
        CheckStatus::Pass
    );
}

#[test]
fn review_a_page_listed_only_in_the_sitemap_is_still_an_orphan() {
    let mut home = page("https://a.com/");
    home.internal_links = vec![
        "https://a.com/x".into(),
        "https://a.com/y".into(),
        "https://a.com/z".into(),
    ];
    let pages = vec![
        home,
        page("https://a.com/x"),
        page("https://a.com/y"),
        page("https://a.com/z"),
        page("https://a.com/lonely"),
    ];
    let sitemap = vec!["https://a.com/lonely".to_string()];

    let results = analyze_session(&pages, Some(whole_sitemap(&sitemap)));

    assert_eq!(
        raw_strings(
            outcome(&results, "seo.orphan_pages"),
            "pages_without_observed_inbound_link"
        ),
        vec!["https://a.com/lonely"]
    );
    assert_eq!(
        outcome(&results, "seo.noindex_in_sitemap").status,
        CheckStatus::Pass
    );
}

#[test]
fn review_a_redirected_page_no_scanned_page_links_to_is_still_an_orphan() {
    // /old redirects to /new and the scan reached the page at /new. A redirect
    // alone does not make a page linked: no scanned page publishes a link to
    // either URL, so it is a genuine orphan. The case where a scanned page does
    // link to the pre-redirect URL is
    // `a_page_linked_only_through_the_url_the_scan_requested_is_not_an_orphan`.
    let mut home = page("https://a.com/");
    home.internal_links = vec![
        "https://a.com/x".into(),
        "https://a.com/y".into(),
        "https://a.com/z".into(),
    ];
    let pages = vec![
        home,
        page("https://a.com/x"),
        page("https://a.com/y"),
        page("https://a.com/z"),
        redirected_page("https://a.com/old", "https://a.com/new"),
    ];

    let finding = compare_with_whole_sitemap(&pages)
        .into_iter()
        .find(|result| result.check_id == "seo.orphan_pages")
        .expect("orphan finding");

    assert_eq!(
        raw_strings(&finding, "pages_without_observed_inbound_link"),
        vec!["https://a.com/new"]
    );
}

#[test]
fn review_relative_canonicals_resolve_against_the_page_before_loop_detection() {
    let a = signals_for("https://a.com/docs/a", r#"<link rel="canonical" href="b">"#);
    let b = signals_for(
        "https://a.com/docs/b/",
        r#"<link rel="canonical" href="../a/">"#,
    );
    assert_eq!(a.canonical.as_deref(), Some("https://a.com/docs/b"));
    assert_eq!(b.canonical.as_deref(), Some("https://a.com/docs/a"));

    let results = analyze_session(&[a, b], None);

    assert_eq!(
        outcome(&results, "seo.canonical_loop").status,
        CheckStatus::Fail
    );
}

#[test]
fn review_canonicals_leaving_the_scanned_set_produce_a_bounded_pass() {
    let mut a = page("https://a.com/a");
    a.canonical = Some("https://a.com/unscanned".into());
    let mut b = page("https://a.com/b");
    b.canonical = Some("https://www.a.com/b".into());

    let results = analyze_session(&[a, b], None);
    let finding = outcome(&results, "seo.canonical_loop");

    assert_eq!(finding.status, CheckStatus::Pass);
    assert!(
        finding.description.contains("all 2 scanned pages"),
        "{}",
        finding.description
    );
}

#[test]
fn review_hreflang_reciprocity_ignores_language_code_and_resolves_relative_hrefs() {
    let en = signals_for(
        "https://a.com/en/",
        r#"<link rel="alternate" hreflang="EN-us" href="/en/">
           <link rel="alternate" hreflang="de-DE" href="../de/">
           <link rel="alternate" hreflang="x-default" href="../">"#,
    );
    assert_eq!(
        en.hreflang,
        vec![
            ("en-us".to_string(), "https://a.com/en".to_string()),
            ("de-de".to_string(), "https://a.com/de".to_string()),
            ("x-default".to_string(), "https://a.com/".to_string()),
        ]
    );
    // Points back under the wrong language code: still counts as a return link.
    let de = signals_for(
        "https://a.com/de/",
        r#"<link rel="alternate" hreflang="fr" href="https://a.com/en/">"#,
    );
    // The x-default target lists nothing.
    let root = signals_for("https://a.com/", "<title>Acme</title>");

    let results = analyze_session(&[en, de, root], None);
    let finding = outcome(&results, "seo.hreflang_reciprocity");

    assert_eq!(finding.status, CheckStatus::Warn);
    assert_eq!(
        raw_strings(finding, "missing_return_links"),
        vec!["https://a.com/en -> https://a.com/"]
    );
}

#[test]
fn review_noindex_sources_cover_comma_lists_googlebot_meta_and_x_robots_headers() {
    use crate::core::page_signals::extract_page_signals_with_headers;

    fn with_header(url: &str, value: &'static str) -> PageSignals {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static("x-robots-tag"),
            reqwest::header::HeaderValue::from_static(value),
        );
        let parsed = url::Url::parse(url).unwrap();
        extract_page_signals_with_headers(&parsed, &parsed, 200, "<html></html>", &headers)
    }

    let comma_list = signals_for(
        "https://a.com/a",
        r#"<meta name="robots" content="max-snippet:-1, NOINDEX, follow">"#,
    );
    let googlebot_none = signals_for(
        "https://a.com/b",
        r#"<meta name="googlebot" content="none">"#,
    );
    let bingbot_only = signals_for(
        "https://a.com/c",
        r#"<meta name="bingbot" content="noindex">"#,
    );
    let header = with_header("https://a.com/d", "noindex, nofollow");
    let other_bot_header = with_header("https://a.com/e", "otherbot: noindex");
    let mut host_twin = page("https://a.com/f");
    host_twin.noindex = Some(true);

    assert_eq!(comma_list.noindex, Some(true));
    assert_eq!(googlebot_none.noindex, Some(true));
    assert_eq!(bingbot_only.noindex, Some(false));
    assert_eq!(header.noindex, Some(true));
    assert_eq!(other_bot_header.noindex, Some(false));

    let sitemap = vec![
        "https://a.com/a/".to_string(),
        "https://a.com/b#top".to_string(),
        "https://a.com/c".to_string(),
        "https://a.com/d".to_string(),
        "https://a.com/e".to_string(),
        // The www listing identifies the same noindex page.
        "https://www.a.com/f".to_string(),
    ];
    let results = analyze_session(
        &[
            comma_list,
            googlebot_none,
            bingbot_only,
            header,
            other_bot_header,
            host_twin,
        ],
        Some(whole_sitemap(&sitemap)),
    );
    let finding = outcome(&results, "seo.noindex_in_sitemap");

    assert_eq!(finding.status, CheckStatus::Warn);
    assert_eq!(
        raw_strings(finding, "pages"),
        vec![
            "https://a.com/a",
            "https://a.com/b",
            "https://a.com/d",
            "https://a.com/f"
        ]
    );
}

#[test]
fn review_defect_an_inline_svg_title_is_not_the_document_title() {
    let body = r#"<html><head></head><body>
        <svg viewBox="0 0 24 24"><title>Menu icon</title><path d="M0 0h24v24H0z"/></svg>
        <h1>Page</h1></body></html>"#;
    // The page-level title check already treats an SVG title as no title.
    assert_eq!(
        sitecmd_engine::checks::seo::parsing::extract_document_title(body),
        None
    );
    // The session signals should agree instead of grouping every page that
    // shares the icon under the title "Menu icon".
    assert_eq!(signals_for("https://a.com/x", body).title, None);
}

// Error responses and repeated selections are excluded from page comparisons.

#[test]
fn an_error_status_page_is_not_compared_against_the_pages_that_answered() {
    // Two dead sitemap entries render the site's error template, so they share
    // a title, a description, an H1, and no inbound links. None of that is a
    // fact about the site's pages.
    let mut home = page("https://a.com/");
    home.title = Some("Acme".into());
    home.internal_links = vec!["https://a.com/live".into()];
    let mut live = page("https://a.com/live");
    live.title = Some("Live".into());
    let mut gone = error_page("https://a.com/gone", 404);
    gone.title = Some("Page not found".into());
    gone.meta_description = Some("Sorry, nothing here".into());
    gone.h1 = Some("Page not found".into());
    let mut also_gone = error_page("https://a.com/also-gone", 410);
    also_gone.title = Some("Page not found".into());
    also_gone.meta_description = Some("Sorry, nothing here".into());
    also_gone.h1 = Some("Page not found".into());
    let mut broken = error_page("https://a.com/broken", 500);
    broken.title = Some("Page not found".into());

    let results = analyze_session(&[home, live, gone, also_gone, broken], None);

    for check_id in [
        "seo.duplicate_title_across_pages",
        "seo.duplicate_description_across_pages",
        "seo.duplicate_h1",
    ] {
        let finding = outcome(&results, check_id);
        assert_eq!(
            finding.status,
            CheckStatus::Pass,
            "{check_id} graded the site's error template: {}",
            finding.description
        );
        assert!(
            finding
                .description
                .contains("Not compared: 3 with no successful page response."),
            "{check_id} did not say what it left out and why: {}",
            finding.description
        );
    }
    // Five selected URLs, two comparable pages: orphan analysis has too few.
    assert_eq!(
        outcome(&results, "seo.orphan_pages").status,
        CheckStatus::Skipped
    );
}

#[test]
fn an_error_status_page_is_not_a_noindex_contradiction_in_the_sitemap() {
    let mut gone = error_page("https://a.com/gone", 404);
    gone.noindex = Some(true);
    let live = page("https://a.com/live");
    let sitemap = vec![
        "https://a.com/gone".to_string(),
        "https://a.com/live".to_string(),
    ];

    let results = analyze_session(&[gone, live], Some(whole_sitemap(&sitemap)));

    // One comparable page is not a cross-page comparison at all.
    let finding = outcome(&results, "seo.noindex_in_sitemap");
    assert_eq!(finding.status, CheckStatus::Skipped);
    assert!(
        finding
            .description
            .contains("needs at least two comparable pages"),
        "{}",
        finding.description
    );
}

#[test]
fn a_scan_left_with_one_comparable_page_reports_no_cross_page_verdict() {
    // No sitemap is supplied on purpose: `seo.noindex_in_sitemap` compares a
    // page against a sitemap rather than against another page, so it can still
    // report a contradiction it observed on the single page that answered.
    // Everything that genuinely needs a second page must report Skipped.
    let mut home = page("https://a.com/");
    home.title = Some("Acme".into());
    let gone = error_page("https://a.com/gone", 503);

    let results = analyze_session(&[home, gone], None);

    for check_id in SESSION_CHECK_IDS {
        let finding = outcome(&results, check_id);
        assert_eq!(
            finding.status,
            CheckStatus::Skipped,
            "{check_id} claimed a verdict from one page"
        );
        assert!(
            finding
                .description
                .contains("Not compared: 1 with no successful page response."),
            "{check_id}: {}",
            finding.description
        );
    }
}

#[test]
fn a_trailing_slash_twin_is_one_page_and_is_counted_once() {
    let mut home = page("https://a.com/");
    home.title = Some("Acme".into());
    let mut about = page("https://a.com/about");
    about.title = Some("About Acme".into());
    // The scope keeps `/about` and `/about/` as two routes. Extraction
    // normalizes the trailing slash away, so both selections reach analysis as
    // the same page, differing only in the URL that was requested.
    let mut about_slash = redirected_page("https://a.com/about/", "https://a.com/about");
    about_slash.title = Some("About Acme".into());

    let results = analyze_session(&[home, about, about_slash], None);
    let finding = outcome(&results, "seo.duplicate_title_across_pages");

    assert_eq!(finding.status, CheckStatus::Pass, "{}", finding.description);
    assert!(
        finding
            .description
            .contains("SiteCMD compared 2 of the 3 selected URLs"),
        "{}",
        finding.description
    );
    assert!(
        finding
            .description
            .contains("Not compared: 1 that resolved to a page already compared."),
        "{}",
        finding.description
    );
}

#[test]
fn a_page_linked_only_through_the_url_the_scan_requested_is_not_an_orphan() {
    // The home page links to /old, /old redirects to /new, and the scan
    // reached the page at /new. The link is real, so the page is not an orphan.
    let mut home = page("https://a.com/");
    home.internal_links = vec![
        "https://a.com/old".into(),
        "https://a.com/x".into(),
        "https://a.com/y".into(),
        "https://a.com/z".into(),
    ];
    let pages = vec![
        home,
        page("https://a.com/x"),
        page("https://a.com/y"),
        page("https://a.com/z"),
        redirected_page("https://a.com/old", "https://a.com/new"),
    ];

    let results = compare_with_whole_sitemap(&pages);

    assert_eq!(
        outcome(&results, "seo.orphan_pages").status,
        CheckStatus::Pass
    );
}

#[test]
fn a_partial_sitemap_read_skips_the_noindex_contradiction_instead_of_passing_it() {
    let a = page("https://a.com/1");
    let b = page("https://a.com/2");
    let urls = vec!["https://a.com/1".to_string()];
    let partial = SessionSitemap {
        urls: &urls,
        partial_because: Some("the sitemap lists 9000 URLs and SiteCMD read the first 5000"),
    };

    let results = analyze_session(&[a, b], Some(partial));
    let finding = outcome(&results, "seo.noindex_in_sitemap");

    assert_eq!(finding.status, CheckStatus::Skipped);
    assert!(
        finding
            .description
            .contains("the sitemap lists 9000 URLs and SiteCMD read the first 5000"),
        "{}",
        finding.description
    );
}

#[test]
fn a_partial_sitemap_still_reports_the_contradictions_it_did_observe() {
    let mut private = page("https://a.com/private");
    private.noindex = Some(true);
    let public = page("https://a.com/public");
    let urls = vec!["https://a.com/private".to_string()];
    let partial = SessionSitemap {
        urls: &urls,
        partial_because: Some(
            "robots.txt lists 3 sitemaps and only the first one that answered was read",
        ),
    };

    let results = analyze_session(&[private, public], Some(partial));
    let finding = outcome(&results, "seo.noindex_in_sitemap");

    assert_eq!(finding.status, CheckStatus::Warn);
    assert!(
        finding.description.contains("so there may be more"),
        "{}",
        finding.description
    );
    assert_eq!(
        finding.raw_data.as_ref().unwrap()["sitemap_url_set_complete"],
        serde_json::json!(false)
    );
}

// Redirect aliases and the scan entry determine inbound-link coverage.

#[test]
fn a_repeated_selection_keeps_the_url_it_was_reached_through() {
    // Defect 2's own motivating shape: a stale sitemap still lists /old beside
    // /new, /old now redirects onto /new, and the home page still links to
    // /old. Collapsing the two selections into one page must not throw away
    // the /old alias, or the page the site does link to becomes an orphan.
    let mut home = page("https://a.com/");
    home.internal_links = vec![
        "https://a.com/old".into(),
        "https://a.com/x".into(),
        "https://a.com/y".into(),
        "https://a.com/z".into(),
    ];
    let pages = vec![
        home,
        page("https://a.com/x"),
        page("https://a.com/y"),
        page("https://a.com/z"),
        // /new selected first, so the surviving page is the one with no alias.
        page("https://a.com/new"),
        redirected_page("https://a.com/old", "https://a.com/new"),
    ];

    let results = compare_with_whole_sitemap(&pages);
    let finding = outcome(&results, "seo.orphan_pages");

    assert_eq!(finding.status, CheckStatus::Pass, "{}", finding.description);
    assert!(
        finding
            .description
            .contains("Not compared: 1 that resolved to a page already compared."),
        "{}",
        finding.description
    );
}

#[test]
fn orphan_analysis_is_skipped_when_the_scan_entry_page_did_not_answer() {
    // The entry page publishes the navigation most pages hang off. Without it
    // the graph is missing those links, and the page that happens to sort
    // first is not the entry page, so exempting it would be arbitrary.
    let entry = error_page("https://a.com/", 500);
    let pages = vec![
        entry,
        page("https://a.com/v"),
        page("https://a.com/w"),
        page("https://a.com/x"),
        page("https://a.com/y"),
        page("https://a.com/z"),
    ];

    let results = analyze_session(&pages, None);
    let finding = outcome(&results, "seo.orphan_pages");

    assert_eq!(
        finding.status,
        CheckStatus::Skipped,
        "{}",
        finding.description
    );
    assert!(
        finding
            .description
            .contains("The page this scan started from did not return a successful page response"),
        "{}",
        finding.description
    );
}

#[test]
fn the_scan_entry_page_is_the_one_exempted_from_orphan_reporting() {
    // The entry page needs no inbound link; every other page does. This is the
    // companion to the test above: when the entry page did answer, it is
    // exempted by identity rather than by position in the compared set.
    let home = page("https://a.com/");
    let pages = vec![
        home,
        page("https://a.com/v"),
        page("https://a.com/w"),
        page("https://a.com/x"),
        page("https://a.com/y"),
    ];

    let results = compare_with_whole_sitemap(&pages);
    let finding = outcome(&results, "seo.orphan_pages");

    assert_eq!(finding.status, CheckStatus::Warn);
    assert_eq!(
        raw_strings(finding, "pages_without_observed_inbound_link"),
        vec![
            "https://a.com/v",
            "https://a.com/w",
            "https://a.com/x",
            "https://a.com/y",
        ]
    );
}
