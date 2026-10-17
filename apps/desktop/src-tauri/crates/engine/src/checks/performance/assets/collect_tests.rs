use super::*;

fn allow_all(_url: &url::Url) -> bool {
    true
}

fn collect(html: &str, page: &str, limit: usize) -> AssetCollection {
    let lower = html.to_ascii_lowercase();
    let page_url = url::Url::parse(page).expect("page url");
    collect_assets(html, &lower, &page_url, allow_all, limit)
}

fn sampled_urls(collection: &AssetCollection) -> Vec<String> {
    collection
        .sampled
        .iter()
        .map(|asset| asset.url.to_string())
        .collect()
}

#[test]
fn collects_all_supported_asset_sources_and_resolves_relative_urls() {
    let html = r#"<html><head>
            <link rel="stylesheet" href="/css/App.css">
            <link rel="preload" href="/skip/preload.woff2">
            <script src="js/Main.js"></script>
            <script>inline();</script>
        </head><body>
            <img src="/img/Hero.png" alt="hero">
            <picture>
                <source srcset="/img/hero.avif" type="image/avif">
                <img src="/img/fallback.jpg" alt="fallback">
            </picture>
        </body></html>"#;
    let collection = collect(html, "https://example.com/page/", 30);
    let urls = sampled_urls(&collection);
    assert!(urls.contains(&"https://example.com/css/App.css".to_string()));
    assert!(urls.contains(&"https://example.com/page/js/Main.js".to_string()));
    assert!(urls.contains(&"https://example.com/img/Hero.png".to_string()));
    assert!(urls.contains(&"https://example.com/img/hero.avif".to_string()));
    assert!(urls.contains(&"https://example.com/img/fallback.jpg".to_string()));
    assert!(
        !urls.iter().any(|url| url.contains("preload")),
        "non-stylesheet links must not be collected"
    );
    assert_eq!(collection.sampled.len(), 5);
    assert_eq!(collection.found, 5);
}

#[test]
fn preserves_original_url_casing() {
    let html = r#"<IMG SRC="/Photos/IMG_2024.JPG" alt="x">"#;
    let collection = collect(html, "https://example.com/", 30);
    assert_eq!(
        sampled_urls(&collection),
        vec!["https://example.com/Photos/IMG_2024.JPG".to_string()]
    );
}

#[test]
fn dedups_repeated_urls_and_merges_srcset_flags() {
    let html = r#"
            <img src="/img/a.png" alt="one">
            <img src="/img/a.png" srcset="/img/a.png 1x, /img/a-2x.png 2x" alt="two">
        "#;
    let collection = collect(html, "https://example.com/", 30);
    assert_eq!(collection.sampled.len(), 2, "a.png must appear once");
    let a = collection
        .sampled
        .iter()
        .find(|asset| asset.url.path() == "/img/a.png")
        .expect("a.png collected");
    assert!(
        a.has_srcset,
        "srcset presence must survive dedup against the plain reference"
    );
}

#[test]
fn prioritizes_images_over_scripts_over_styles_when_capped() {
    let html = r#"
            <link rel="stylesheet" href="/one.css">
            <script src="/one.js"></script>
            <img src="/one.png" alt="a">
            <img src="/two.png" alt="b">
            <script src="/two.js"></script>
        "#;
    let collection = collect(html, "https://example.com/", 3);
    let urls = sampled_urls(&collection);
    assert_eq!(
        urls,
        vec![
            "https://example.com/one.png".to_string(),
            "https://example.com/two.png".to_string(),
            "https://example.com/one.js".to_string(),
        ]
    );
    assert_eq!(collection.fetchable_found, 5);
    assert_eq!(collection.found, 5);
}

#[test]
fn counts_data_uris_without_fetching() {
    // 8 base64 chars decode to 6 bytes.
    let html = r#"<img src="data:image/png;base64,AAAAAAAA" alt="dot">"#;
    let collection = collect(html, "https://example.com/", 30);
    assert!(collection.sampled.is_empty());
    assert_eq!(collection.data_uri_count, 1);
    assert_eq!(collection.data_uri_bytes, 6);
    assert_eq!(collection.found, 1);
}

#[test]
fn skips_blob_and_javascript_schemes() {
    let html = r#"
            <img src="blob:https://example.com/uuid" alt="a">
            <script src="javascript:alert(1)"></script>
            <img src="/real.png" alt="b">
        "#;
    let collection = collect(html, "https://example.com/", 30);
    assert_eq!(
        sampled_urls(&collection),
        vec!["https://example.com/real.png".to_string()]
    );
    assert_eq!(collection.skipped_unsupported, 2);
    assert_eq!(collection.found, 3);
}

#[test]
fn refused_targets_count_as_skipped_unsupported() {
    let html = r#"
            <img src="http://169.254.169.254/latest/meta-data/x.png" alt="a">
            <img src="https://cdn.example.com/ok.png" alt="c">
        "#;
    let lower = html.to_ascii_lowercase();
    let page_url = url::Url::parse("https://example.com/").expect("page url");
    let collection = collect_assets(
        html,
        &lower,
        &page_url,
        |url| url.host_str() != Some("169.254.169.254"),
        30,
    );
    assert_eq!(
        sampled_urls(&collection),
        vec!["https://cdn.example.com/ok.png".to_string()]
    );
    assert_eq!(collection.skipped_unsupported, 1);
}

#[test]
fn parse_srcset_extracts_urls_and_drops_descriptors() {
    assert_eq!(
        parse_srcset("/img/a-320.jpg 320w, /img/a-640.jpg 640w"),
        vec!["/img/a-320.jpg".to_string(), "/img/a-640.jpg".to_string()]
    );
    assert_eq!(
        parse_srcset(" hero.png 1x ,hero-2x.png 2x "),
        vec!["hero.png".to_string(), "hero-2x.png".to_string()]
    );
    assert!(parse_srcset("").is_empty());
    assert!(parse_srcset("  ,  ").is_empty());
}

#[test]
fn character_references_are_decoded_before_the_url_is_fetched() {
    // astro.build and tailwindcss.com write optimizer URLs with `&amp;`.
    // Requesting the raw text returns 400 from both optimizers, which the
    // sampler then reported as broken images.
    let html = r#"<img src="/_image?href=%2Fhero.png&amp;w=256&amp;f=webp" srcset="/_image?href=%2Fhero.png&amp;w=512 2x">
            <script src="/app.js?v=1&amp;b=2"></script>
            <link rel="stylesheet" href="/style.css?v=1&amp;b=2">"#;
    let collection = collect(html, "https://example.com/", 30);
    let urls = sampled_urls(&collection);
    assert!(
        urls.contains(&"https://example.com/_image?href=%2Fhero.png&w=256&f=webp".to_string()),
        "{urls:?}"
    );
    assert!(
        urls.contains(&"https://example.com/_image?href=%2Fhero.png&w=512".to_string()),
        "{urls:?}"
    );
    assert!(urls.contains(&"https://example.com/app.js?v=1&b=2".to_string()));
    assert!(urls.contains(&"https://example.com/style.css?v=1&b=2".to_string()));
}

#[test]
fn parse_srcset_keeps_data_uris_opaque() {
    // The comma inside a data URI must not be split into bogus candidates.
    let candidates = parse_srcset("/small.png 1x, data:image/png;base64,AAAA 2x");
    assert_eq!(candidates[0], "/small.png");
    assert_eq!(candidates.len(), 2);
    assert!(candidates[1].starts_with("data:"));
}

#[test]
fn attr_value_ignores_data_src_and_preserves_case() {
    let tag = r#"<img data-src="/lazy/Wrong.png" src="/right/Photo.PNG">"#;
    assert_eq!(attr_value(tag, "src"), Some("/right/Photo.PNG".to_string()));
    let tag = r#"<img data-src="/lazy/only.png">"#;
    assert_eq!(attr_value(tag, "src"), None);
}

#[test]
fn unquoted_attributes_on_minified_html_are_collected() {
    let collection = collect(
        "<img src=/hero.png><script src=/app.js></script><link rel=stylesheet href=/style.css>",
        "https://example.com/",
        30,
    );
    let urls = sampled_urls(&collection);
    assert!(urls.contains(&"https://example.com/hero.png".to_string()));
    assert!(urls.contains(&"https://example.com/app.js".to_string()));
    assert!(urls.contains(&"https://example.com/style.css".to_string()));
}

#[test]
fn data_uri_estimated_bytes_handles_base64_and_plain_payloads() {
    assert_eq!(
        data_uri_estimated_bytes("data:image/png;base64,AAAAAAAA"),
        6
    );
    assert_eq!(data_uri_estimated_bytes("data:text/plain,hello"), 5);
    assert_eq!(data_uri_estimated_bytes("data:image/png"), 0);
}

#[test]
fn a_page_naming_more_assets_than_the_sample_keeps_the_first_and_counts_the_rest() {
    let images: String = (0..40)
        .map(|index| format!("<img src=\"/i/{index}.png\" alt=\"\">"))
        .collect();
    let collection = collect(
        &format!("{images}<script src=\"/app.js\"></script>"),
        "https://example.com/",
        30,
    );
    assert_eq!(collection.sampled.len(), 30);
    assert_eq!(
        collection.sampled[0].url.as_str(),
        "https://example.com/i/0.png"
    );
    assert_eq!(
        collection.sampled[29].url.as_str(),
        "https://example.com/i/29.png"
    );
    assert_eq!(collection.fetchable_found, 41);
    assert_eq!(collection.found, 41);
}

#[test]
fn a_duplicate_past_the_sample_is_counted_once() {
    let images: String = (0..35)
        .map(|index| format!("<img src=\"/i/{index}.png\" alt=\"\">"))
        .collect();
    let collection = collect(
        &format!("{images}<link rel=\"stylesheet\" href=\"/i/33.png\">"),
        "https://example.com/",
        30,
    );
    assert_eq!(collection.fetchable_found, 35);
    assert_eq!(collection.found, 36);
}

#[test]
fn a_kept_image_takes_the_srcset_flag_of_a_later_source_naming_it() {
    // A wrong kept index merges the duplicate into another asset.
    // Repeated references must preserve element groups and count once.
    let html = r#"<img src="/first.png" alt="f"><img src="/hero.png" alt="h"><picture><source srcset="/hero.png 1x, /hero-2x.png 2x"></picture>"#;
    let collection = collect(html, "https://example.com/", 30);
    let first = collection
        .sampled
        .iter()
        .find(|asset| asset.url.path() == "/first.png")
        .expect("first sampled");
    assert!(!first.has_srcset);
    let hero = collection
        .sampled
        .iter()
        .find(|asset| asset.url.path() == "/hero.png")
        .expect("hero sampled");
    assert!(hero.has_srcset);
    assert_eq!(hero.group, 1, "the first reference's group stands");
    let candidate = collection
        .sampled
        .iter()
        .find(|asset| asset.url.path() == "/hero-2x.png")
        .expect("candidate sampled");
    assert_eq!(candidate.group, 2);
    assert_eq!(collection.fetchable_found, 3);
}

#[test]
fn the_sample_alone_is_the_whole_collections_sample() {
    // Counting references can stop before distinct fetchable assets fill the sample.
    let many: String = (0..45)
        .map(|index| format!("<img src=\"/i/{index}.png\" alt=\"\">"))
        .collect();
    for html in [
        "<link rel=\"stylesheet\" href=\"/a.css\"><script src=\"/a.js\"></script><img src=\"/a.png\" alt=\"\">",
        many.as_str(),
        r#"<img src="data:image/png;base64,AAAA" alt=""><img src="blob:x" alt=""><img src="/real.png" alt=""><img src="/real.png" alt=""><img src="/other.png" alt="">"#,
    ] {
        for limit in [0, 1, 2, 30] {
            let lower = html.to_ascii_lowercase();
            let page = url::Url::parse("https://example.com/").expect("page url");
            let whole: Vec<String> = collect_assets(html, &lower, &page, allow_all, limit)
                .sampled
                .iter()
                .map(|asset| asset.url.to_string())
                .collect();
            let alone: Vec<String> = asset_sample(html, &lower, &page, allow_all, limit)
                .iter()
                .map(|url| url.to_string())
                .collect();
            assert_eq!(alone, whole, "{html}, limit {limit}");
        }
    }
}

#[test]
fn the_sample_alone_stops_reading_once_it_is_full() {
    // Checking only after an asset pass resolves the extra image beyond the sample.
    let html = format!(
        "{}{}",
        (0..31)
            .map(|index| format!("<img src=\"/i/{index}.png\" alt=\"\">"))
            .collect::<String>(),
        (0..1000)
            .map(|index| format!("<script src=\"/s/{index}.js\"></script>"))
            .collect::<String>()
    );
    let lower = html.to_ascii_lowercase();
    let page = url::Url::parse("https://example.com/").expect("page url");
    let asked = std::cell::Cell::new(0usize);
    let counting = |_: &url::Url| {
        asked.set(asked.get() + 1);
        true
    };
    assert_eq!(asset_sample(&html, &lower, &page, counting, 30).len(), 30);
    assert_eq!(
        asked.get(),
        30,
        "the sample read {} references",
        asked.get()
    );
    asked.set(0);
    collect_assets(&html, &lower, &page, counting, 30);
    assert_eq!(
        asked.get(),
        1031,
        "a verdict's collection reads every reference"
    );
}

#[test]
fn references_that_cannot_be_fetched_are_never_counted_as_assets_past_the_sample() {
    // Unfetchable references must not increase asset counts after the sample fills.
    let images: String = (0..32)
        .map(|index| format!("<img src=\"/i/{index}.png\" alt=\"\">"))
        .collect();
    let html = format!(
        r#"{images}<img src="data:image/png;base64,AAAA" alt=""><img src="blob:x" alt=""><img src="http://blocked.example/x.png" alt=""><img src="/i/0.png" alt=""><img src="/i/31.png" alt="">"#
    );
    let lower = html.to_ascii_lowercase();
    let page = url::Url::parse("https://example.com/").expect("page url");
    let collection = collect_assets(
        &html,
        &lower,
        &page,
        |url| url.host_str() != Some("blocked.example"),
        30,
    );
    assert_eq!(collection.sampled.len(), 30);
    assert_eq!(collection.fetchable_found, 32);
    assert_eq!(collection.found, 37);
    assert_eq!(collection.data_uri_count, 1);
    assert_eq!(collection.skipped_unsupported, 2);
}
