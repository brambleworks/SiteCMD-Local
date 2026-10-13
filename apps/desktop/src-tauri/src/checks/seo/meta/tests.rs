use super::*;
use crate::checks::{Check, CheckContext, CheckStatus, Severity};
use reqwest::header::{HeaderMap, HeaderValue};

fn ctx(body: &str) -> CheckContext {
    ctx_with_headers(body, HeaderMap::new())
}

fn ctx_with_headers(body: &str, headers: HeaderMap) -> CheckContext {
    CheckContext {
        page: crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: headers,
            status_code: 200,
            body: body.to_string(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: Some("HTTP/2.0".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        },
        client: crate::http_client::for_url(false).clone(),
        probe_cache: Default::default(),
    }
}

#[test]
fn test_title_present_good_length_pass() {
    let html = "<html><head><title>My Great Website - Quality Products</title></head></html>";
    let check = TitleTagCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_title_missing_fail() {
    let html = "<html><head></head><body>No title here</body></html>";
    let check = TitleTagCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert_eq!(results[0].severity, Severity::High);
}

#[test]
fn test_title_too_short_warn() {
    let html = "<html><head><title>Hi</title></head></html>";
    let check = TitleTagCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn test_title_too_long_warn() {
    let long_title = "A".repeat(80);
    let html = format!("<html><head><title>{}</title></head></html>", long_title);
    let check = TitleTagCheck;
    let results = check.run(&ctx(&html));
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn cjk_title_is_measured_in_characters_not_bytes() {
    let title: String = "あ".repeat(40); // 40 chars, 120 bytes
    assert_eq!(title.len(), 120);
    let html = format!("<html><head><title>{title}</title></head></html>");
    let check = TitleTagCheck;
    let results = check.run(&ctx(&html));
    assert_eq!(
        results[0].status,
        CheckStatus::Pass,
        "a 40-character CJK title must not be flagged as too long"
    );
}

#[test]
fn test_meta_description_present_pass() {
    let html = r#"<html><head><meta name="description" content="This is a well-written meta description that provides a concise summary of the page content for search engines and users alike in a nice length."></head></html>"#;
    let check = MetaDescriptionCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_meta_description_missing_fail() {
    let html = "<html><head><title>Page</title></head></html>";
    let check = MetaDescriptionCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Fail);
}

#[test]
fn metadata_examples_in_scripts_and_comments_do_not_satisfy_page_checks() {
    let html = r#"
        <!-- <title>Comment title</title><meta name="description" content="comment"> -->
        <script>
          const title = '<title>Template title</title>';
          const meta = '<meta name="description" content="template">';
        </script>
        <svg><title>Logo title</title></svg>
    "#;
    assert_eq!(TitleTagCheck.run(&ctx(html))[0].status, CheckStatus::Fail);
    assert_eq!(
        MetaDescriptionCheck.run(&ctx(html))[0].status,
        CheckStatus::Fail
    );
}

#[test]
fn metadata_parser_handles_html_whitespace_around_equals_and_gt_in_values() {
    let html = r#"<title>Actual page title for this route</title>
        <meta name = "description" content = "A useful comparison: 5 > 3, with enough specific context to describe this page clearly.">"#;
    assert_eq!(TitleTagCheck.run(&ctx(html))[0].status, CheckStatus::Pass);
    assert_eq!(
        MetaDescriptionCheck.run(&ctx(html))[0].status,
        CheckStatus::Pass
    );
}

#[test]
fn longer_tag_names_do_not_count_as_document_titles() {
    assert_eq!(
        TitleTagCheck.run(&ctx("<titlefoo>Not a title</titlefoo>"))[0].status,
        CheckStatus::Fail
    );
}

#[test]
fn blank_title_and_description_are_missing_not_length_advisories() {
    let html =
        r#"<html><head><title>   </title><meta name="description" content=" "></head></html>"#;
    let title = &TitleTagCheck.run(&ctx(html))[0];
    let description = &MetaDescriptionCheck.run(&ctx(html))[0];
    assert_eq!(title.status, CheckStatus::Fail);
    assert_eq!(title.title, "Missing title tag");
    assert_eq!(description.status, CheckStatus::Fail);
    assert_eq!(description.title, "Missing meta description");
}

#[test]
fn test_meta_description_too_long_warn() {
    let long_desc = "A".repeat(200);
    let html = format!(
        r#"<html><head><meta name="description" content="{}"></head></html>"#,
        long_desc
    );
    let check = MetaDescriptionCheck;
    let results = check.run(&ctx(&html));
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn test_meta_description_ignores_neighboring_viewport_content() {
    let html = r#"
            <html>
                <head>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="description" content="A real product description that should win over viewport noise.">
                </head>
            </html>
        "#;
    let check = MetaDescriptionCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert_eq!(
        results[0].raw_data,
        Some(serde_json::json!({
            "description": "A real product description that should win over viewport noise.",
            "description_evidence_truncated": false,
            "length": 63,
            "rendered_head_inspected": false,
            "source": "initial_html"
        }))
    );
}

#[test]
fn test_viewport_present_pass() {
    let html = r#"<html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head></html>"#;
    let check = ViewportCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_viewport_missing_warns_contextually() {
    let html = "<html><head><title>No viewport</title></head></html>";
    let check = ViewportCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::Medium);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("does not prove"));
}

#[test]
fn present_but_fixed_viewport_warns_without_claiming_the_page_is_broken() {
    let html = r#"<html><head><meta name="viewport" content="width=980"></head></html>"#;
    let result = &ViewportCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(
        result.confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(result.description.contains("may be intentional"));
    assert!(!result.description.contains("not mobile-friendly"));
}

#[test]
fn viewport_presence_does_not_claim_mobile_friendliness() {
    let html = r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#;
    let result = &ViewportCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Pass);
    assert!(result.description.contains("does not prove"));
}

#[test]
fn minified_unquoted_viewport_is_detected() {
    // html-minifier removeAttributeQuotes output false-failed "Missing
    // viewport meta tag" at effective High.
    let html =
        "<html><head><meta name=viewport content=width=device-width,initial-scale=1></head></html>";
    let results = ViewportCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn minified_unquoted_canonical_is_detected() {
    let html = "<html><head><link rel=canonical href=https://example.com/page></head></html>";
    let results = CanonicalCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn missing_canonical_is_contextual_advice_not_a_duplicate_content_failure() {
    let result = &CanonicalCheck.run(&ctx("<html><head></head></html>"))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.severity, Severity::Low);
    assert_eq!(
        result.confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(result.description.contains("can infer a canonical"));
}

#[test]
fn data_rel_canonical_does_not_satisfy_the_canonical_check() {
    let html = r#"<link data-rel="canonical" href="https://example.com/">"#;
    assert_eq!(CanonicalCheck.run(&ctx(html))[0].status, CheckStatus::Warn);
}

#[test]
fn canonical_markup_example_inside_script_does_not_satisfy_presence_check() {
    let html =
        r#"<script>const example = '<link rel=canonical href=https://wrong.test/>';</script>"#;
    assert_eq!(CanonicalCheck.run(&ctx(html))[0].status, CheckStatus::Warn);
}

#[test]
fn metadata_length_findings_are_explicitly_heuristic() {
    let long_title = "W".repeat(90);
    let title_html = format!("<title>{long_title}</title>");
    let title = &TitleTagCheck.run(&ctx(&title_html))[0];
    assert_eq!(title.status, CheckStatus::Warn);
    assert_eq!(
        title.confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(title.description.contains("does not prove truncation"));

    let missing_description = &MetaDescriptionCheck.run(&ctx("<html></html>"))[0];
    assert!(missing_description
        .description
        .contains("may generate a query-dependent snippet"));
    assert!(!missing_description
        .why_it_matters
        .as_deref()
        .unwrap_or_default()
        .contains("hurt click-through"));
}

#[test]
fn minified_unquoted_open_graph_and_twitter_are_detected() {
    let html = "<html><head>\
        <meta property=og:title content=SiteCMD>\
        <meta property=og:description content=Take-command>\
        <meta property=og:image content=https://example.com/card.png>\
        <meta name=twitter:card content=summary_large_image>\
        </head></html>";
    assert_eq!(OpenGraphCheck.run(&ctx(html))[0].status, CheckStatus::Pass);
    assert_eq!(
        TwitterCardCheck.run(&ctx(html))[0].status,
        CheckStatus::Pass
    );
}

#[test]
fn data_name_attribute_does_not_satisfy_name_matching() {
    // The unquoted-attribute support must not loosen matching so far that
    // data-name= counts as name=.
    let html = r#"<html><head><meta data-name="viewport" content="x"></head></html>"#;
    let results = ViewportCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn duplicate_viewport_tags_need_review_even_when_one_has_device_width() {
    let html = r#"<meta name="viewport" content="width=device-width"><meta name=viewport content=width=980>"#;
    let result = &ViewportCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert!(result.description.contains("2 viewport"));
    assert_eq!(result.raw_data.as_ref().unwrap()["viewport_tag_count"], 2);
}

#[test]
fn duplicate_viewport_copy_does_not_invent_a_device_width_directive() {
    let html =
        r#"<meta name="viewport" content="width=980"><meta name=viewport content=initial-scale=1>"#;
    let result = &ViewportCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert!(result
        .description
        .contains("neither includes width=device-width"));
    assert!(!result
        .description
        .contains("At least one includes width=device-width"));
    assert_eq!(result.raw_data.as_ref().unwrap()["has_device_width"], false);
}

#[test]
fn single_missing_open_graph_tag_uses_singular_title() {
    let html = r#"<html><head>
        <meta property="og:title" content="SiteCMD">
        <meta property="og:description" content="Take command.">
    </head></html>"#;
    let results = OpenGraphCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::Low);
    assert_eq!(results[0].title, "Missing Open Graph tag");
    assert!(results[0]
        .description
        .contains("Missing Open Graph tag: og:image"));
}

#[test]
fn empty_open_graph_values_count_as_missing() {
    let html = r#"<meta property="og:title" content=""><meta property="og:description" content="Summary"><meta property="og:image" content=" ">"#;
    let result = &OpenGraphCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert!(result.description.contains("og:title"));
    assert!(result.description.contains("og:image"));
}

#[test]
fn twitter_cards_why_it_matters_has_no_engagement_stat_claim() {
    let html = "<html><head><title>x</title></head></html>";
    let results = TwitterCardCheck.run(&ctx(html));
    let why = results[0].why_it_matters.as_deref().unwrap_or("");
    assert!(
        !why.contains("significantly less engagement"),
        "unsourced stat-shaped claim must stay removed: {why}"
    );
}

#[test]
fn open_graph_presence_does_not_guarantee_a_rendered_preview() {
    let html = r#"<meta property="og:title" content="T"><meta property="og:description" content="D"><meta property="og:image" content="https://example.com/card.png">"#;
    let result = &OpenGraphCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Pass);
    assert!(!result.description.contains("will display"));
}

#[test]
fn twitter_card_check_requires_a_card_type_even_when_og_fields_exist() {
    let html = r#"<meta property="og:title" content="T"><meta property="og:description" content="D"><meta property="og:image" content="https://example.com/card.png">"#;
    let result = &TwitterCardCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert!(result.description.contains("fallback values"));
}

#[test]
fn twitter_card_pass_describes_only_the_observed_type_marker() {
    let result = &TwitterCardCheck.run(&ctx(
        r#"<meta name="twitter:card" content="summary_large_image">"#,
    ))[0];
    assert_eq!(result.status, CheckStatus::Pass);
    assert!(result.description.contains("card-type request only"));
    assert!(!result.description.contains("meta tags are present"));
    assert_eq!(
        result.raw_data.as_ref().unwrap()["twitter_card"],
        "summary_large_image"
    );
}

#[test]
fn empty_twitter_card_value_is_not_treated_as_a_type() {
    let result = &TwitterCardCheck.run(&ctx(r#"<meta name="twitter:card" content="   ">"#))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.title, "Missing Twitter Card type");
}

#[test]
fn test_noindex_check_does_not_trigger_from_visible_copy() {
    let html = r#"
            <html>
                <head>
                    <title>SiteCMD</title>
                </head>
                <body>
                    <h1>Noindex audit</h1>
                    <p>We help teams catch accidental noindex directives before launch.</p>
                </body>
            </html>
        "#;
    let check = NoindexCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
    let raw = results[0].raw_data.as_ref().unwrap();
    assert_eq!(raw["noindex"], false);
    assert_eq!(raw["nofollow"], false);
    assert_eq!(raw["general_noindex"], false);
}

#[test]
fn test_noindex_check_triggers_for_meta_directive() {
    let html = r#"
            <html>
                <head>
                    <meta name="robots" content="index, noindex, nofollow">
                </head>
                <body>Meta directive test</body>
            </html>
        "#;
    let check = NoindexCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(results[0].severity, Severity::High);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("after they can crawl"));
    let raw = results[0].raw_data.as_ref().unwrap();
    assert_eq!(raw["noindex"], true);
    assert_eq!(raw["nofollow"], true);
    assert_eq!(raw["general_noindex"], true);
}

#[test]
fn interior_noindex_is_medium_until_page_intent_is_known() {
    let mut context = ctx(r#"<meta name="robots" content="noindex">"#);
    context.url = url::Url::parse("https://example.com/account/receipt").unwrap();
    let result = &NoindexCheck.run(&context)[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.severity, Severity::Medium);
    assert_eq!(
        result.confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
}

#[test]
fn test_noindex_check_triggers_for_x_robots_tag_header() {
    let html = "<html><head><title>Header noindex</title></head><body>Header test</body></html>";
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    let check = NoindexCheck;
    let results = check.run(&ctx_with_headers(html, headers));
    assert_eq!(results[0].status, CheckStatus::Warn);
    let raw = results[0].raw_data.as_ref().unwrap();
    assert_eq!(raw["noindex"], true);
    assert_eq!(raw["nofollow"], true);
    assert_eq!(raw["general_noindex"], true);
}

#[test]
fn test_noindex_check_recognizes_content_none() {
    let html = r#"<html><head><meta name="robots" content="none"></head></html>"#;
    let results = NoindexCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    let raw = results[0].raw_data.as_ref().unwrap();
    assert_eq!(raw["noindex"], true);
    assert_eq!(raw["nofollow"], true);
    assert_eq!(raw["general_noindex"], true);
}

#[test]
fn test_noindex_check_reads_every_robots_meta() {
    let html = r#"<html><head>
        <meta name="robots" content="max-snippet: 20">
        <meta name="robots" content="noindex">
    </head></html>"#;
    let results = NoindexCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn test_noindex_check_reads_ua_scoped_and_repeated_x_robots_tag() {
    let html = "<html><head><title>t</title></head></html>";
    let mut headers = HeaderMap::new();
    headers.append("x-robots-tag", HeaderValue::from_static("max-snippet: 20"));
    headers.append(
        "x-robots-tag",
        HeaderValue::from_static("googlebot: noindex"),
    );
    let results = NoindexCheck.run(&ctx_with_headers(html, headers));
    assert_eq!(results[0].status, CheckStatus::Warn);
}

#[test]
fn googlebot_meta_noindex_is_detected_as_google_scoped() {
    let html = r#"<meta name="googlebot" content="noindex, follow">"#;
    let result = &NoindexCheck.run(&ctx(html))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.title, "Googlebot-specific noindex directive");
    assert_eq!(result.raw_data.as_ref().unwrap()["general_noindex"], false);
    assert_eq!(
        result.raw_data.as_ref().unwrap()["scoped_noindex_agents"],
        serde_json::json!(["googlebot"])
    );
}

#[test]
fn googlebot_news_header_is_not_reported_as_a_page_wide_noindex() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-robots-tag",
        HeaderValue::from_static("googlebot-news: noindex"),
    );
    let result = &NoindexCheck.run(&ctx_with_headers("<title>News</title>", headers))[0];
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.title, "Crawler-specific noindex directive");
    assert_eq!(result.severity, Severity::Low);
    assert!(!result.description.contains("this page after"));
    assert!(result.description.contains("Googlebot-News only"));
    assert_eq!(result.raw_data.as_ref().unwrap()["general_noindex"], false);
    assert_eq!(
        result.raw_data.as_ref().unwrap()["scoped_noindex_agents"],
        serde_json::json!(["googlebot-news"])
    );
}

#[test]
fn test_noindex_check_ignores_valued_directives() {
    // "unavailable_after: <date>" and "max-snippet: N" are not noindex.
    let html = "<html><head><title>t</title></head></html>";
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-robots-tag",
        HeaderValue::from_static("max-snippet: 20, unavailable_after: 25 Jun 2027 15:00:00 PST"),
    );
    let results = NoindexCheck.run(&ctx_with_headers(html, headers));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_hreflang_ignores_js_bundle_mentions() {
    let html =
        r#"<html><head><script>var seoFields=["hreflang","canonical"];</script></head></html>"#;
    let results = HreflangCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert!(results[0].description.contains("No HTML link annotation"));
}

#[test]
fn test_hreflang_with_x_default_passes() {
    let html = r#"<html><head>
        <link rel="alternate" hreflang="en" href="https://example.com/">
        <link rel="alternate" hreflang="x-default" href="https://example.com/">
    </head></html>"#;
    let results = HreflangCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn test_hreflang_without_optional_x_default_passes() {
    let html = r#"<html><head>
        <link rel="alternate" hreflang="en" href="https://example.com/">
        <link rel="alternate" hreflang="de" href="https://example.com/de">
    </head></html>"#;
    let results = HreflangCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert!(results[0].description.contains("x-default is optional"));
}

#[test]
fn test_hreflang_html_set_without_self_reference_needs_review() {
    let html = r#"<html><head>
        <link rel="alternate" hreflang="en" href="https://example.com/en">
        <link rel="alternate" hreflang="de" href="https://example.com/de">
    </head></html>"#;
    let results = HreflangCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert_eq!(
        results[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(results[0].description.contains("self-reference"));
}

#[test]
fn test_hreflang_requires_alternate_rel_and_supports_unquoted_attributes() {
    let html = r#"<html><head>
        <link rel=stylesheet hreflang=de href=https://example.com/de>
        <link rel=alternate hreflang=en href=https://example.com/>
    </head></html>"#;
    let result = HreflangCheck.run(&ctx(html)).remove(0);
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(
        result.raw_data.as_ref().unwrap()["html_annotation_count"],
        1
    );
}

#[test]
fn test_open_graph_check_reads_the_matching_image_tag() {
    let html = r#"
            <html>
                <head>
                    <meta property="og:type" content="website">
                    <meta property="og:title" content="SiteCMD">
                    <meta property="og:description" content="Take command of your website.">
                    <meta property="og:image" content="https://sitecmd.com/images/sitecmd-social.png">
                </head>
            </html>
        "#;
    let check = OpenGraphCheck;
    let results = check.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert_eq!(
        results[0].raw_data,
        Some(serde_json::json!({
            "og_title": "SiteCMD",
            "og_description": "Take command of your website.",
            "og_image": "https://sitecmd.com/images/sitecmd-social.png"
        }))
    );
}

#[test]
fn test_duplicate_title_fail() {
    let html = "<html><head><title>First</title><title>Second</title></head></html>";
    let check = DuplicateMetaCheck;
    let results = check.run(&ctx(html));
    let dup = results
        .iter()
        .find(|r| r.check_id == "seo.duplicate_title")
        .unwrap();
    assert_eq!(dup.status, CheckStatus::Fail);
}

#[test]
fn test_no_duplicates_pass() {
    let html = r#"<html><head><title>Only One</title><meta name="description" content="Single"></head></html>"#;
    let check = DuplicateMetaCheck;
    let results = check.run(&ctx(html));
    let umbrella = results
        .iter()
        .find(|r| r.check_id == "seo.duplicate_meta")
        .expect("duplicate meta verdict");
    assert_eq!(umbrella.status, CheckStatus::Pass);
}

#[test]
fn titles_in_comments_and_scripts_are_not_duplicates() {
    let html = r#"<html><head>
        <title>Real Title</title>
        <!-- <title>Old Title</title> -->
        <script>var tpl = "<title>{{t}}</title>";</script>
    </head></html>"#;
    let results = DuplicateMetaCheck.run(&ctx(html));
    assert!(
        results
            .iter()
            .all(|r| r.check_id != "seo.duplicate_title" || r.status == CheckStatus::Pass),
        "non-content titles must not count as duplicates"
    );
}

#[test]
fn form_field_named_description_is_not_a_meta_description() {
    let html = r#"<html><head>
        <meta name="description" content="The real one">
    </head><body>
        <form><input name="description"><textarea name="description"></textarea></form>
    </body></html>"#;
    let results = DuplicateMetaCheck.run(&ctx(html));
    assert!(
        results
            .iter()
            .all(|r| r.check_id != "seo.duplicate_description" || r.status == CheckStatus::Pass),
        "form fields must not count as meta descriptions"
    );
}

#[test]
fn real_duplicate_meta_descriptions_still_fail() {
    let html = r#"<html><head>
        <meta name="description" content="One">
        <meta name="description" content="Two">
    </head></html>"#;
    let results = DuplicateMetaCheck.run(&ctx(html));
    let dup = results
        .iter()
        .find(|r| r.check_id == "seo.duplicate_description")
        .expect("duplicate description must fire");
    assert_eq!(dup.status, CheckStatus::Fail);
    assert!(dup
        .description
        .contains("Found 2 <meta name=\"description\"> elements"));
}

#[test]
fn svg_title_element_is_not_a_duplicate_document_title() {
    let html = r#"<html><head><title>Home Page</title></head><body><a href="/"><svg viewBox="0 0 1 1"><title>Home icon</title></svg></a></body></html>"#;
    let results = DuplicateMetaCheck.run(&ctx(html));
    assert!(
        results
            .iter()
            .all(|r| r.check_id != "seo.duplicate_title" || r.status == CheckStatus::Pass),
        "an svg <title> must not be reported as a duplicate document title"
    );
}

#[test]
fn og_image_relative_url_fails() {
    let html = r#"<html><head>
        <meta property="og:title" content="Site">
        <meta property="og:image" content="/social/card.png">
    </head></html>"#;
    let results = OgImageAbsoluteCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(results[0].description.contains("/social/card.png"));
}

#[test]
fn og_protocol_relative_url_fails_and_absolute_passes() {
    let relative = r#"<meta property="og:image" content="//cdn.example.com/card.png">"#;
    assert_eq!(
        OgImageAbsoluteCheck.run(&ctx(relative))[0].status,
        CheckStatus::Warn
    );

    let absolute = r#"<html><head>
        <meta property="og:image" content="https://example.com/card.png">
        <meta property="og:url" content="https://example.com/">
    </head></html>"#;
    assert_eq!(
        OgImageAbsoluteCheck.run(&ctx(absolute))[0].status,
        CheckStatus::Pass
    );
}

#[test]
fn og_absent_url_tags_pass_absoluteness_check() {
    // Missing OG tags are seo.open_graph's finding, not this check's.
    let html = "<html><head><title>x</title></head></html>";
    assert_eq!(
        OgImageAbsoluteCheck.run(&ctx(html))[0].status,
        CheckStatus::Pass
    );
}

#[test]
fn charset_meta_early_passes() {
    let html = r#"<!doctype html><html><head><meta charset="utf-8"><title>x</title></head></html>"#;
    assert_eq!(
        MetaCharsetCheck.run(&ctx(html))[0].status,
        CheckStatus::Pass
    );
}

#[test]
fn charset_meta_beyond_first_kilobyte_warns() {
    let padding = format!("<!doctype html><html><head><!-- {} -->", "x".repeat(1100));
    let html = format!(r#"{}<meta charset="utf-8"></head></html>"#, padding);
    let results = MetaCharsetCheck.run(&ctx(&html));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(results[0].description.contains("1024"));
}

#[test]
fn charset_from_content_type_header_passes_without_meta() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    let html = "<html><head><title>x</title></head></html>";
    assert_eq!(
        MetaCharsetCheck.run(&ctx_with_headers(html, headers))[0].status,
        CheckStatus::Pass
    );
}

#[test]
fn charset_missing_everywhere_fails() {
    let html = "<html><head><title>x</title></head></html>";
    let results = MetaCharsetCheck.run(&ctx(html));
    assert_eq!(results[0].status, CheckStatus::Fail);
}
