//! Shared fuzz oracles, also exercised by the stable workspace test suite.

use std::sync::LazyLock;

use sitecmd_engine::checks::seo::sitemap_document::{
    parse_sitemap_document, sitemap_urls_from_robots,
};
use sitecmd_engine::evaluation::{evaluate, EvaluationRequest, PageArtifact};

static PAGE: LazyLock<PageArtifact> = LazyLock::new(|| {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../engine/fixtures/checks/golden.json"))
            .expect("checked-in page corpus");
    serde_json::from_value(corpus["cases"][0]["page"].clone()).expect("page fixture")
});

/// Feed arbitrary markup through the real portable verdict runners.
pub fn page_input(data: &[u8]) {
    let mut page = PAGE.clone();
    page.body = String::from_utf8_lossy(data).into_owned();
    let request: EvaluationRequest =
        serde_json::from_value(serde_json::json!({ "page": page })).expect("page request");
    assert_deterministic(&request);
}

/// Exercise both XML discovery and robots directives with arbitrary UTF-8.
pub fn sitemap_input(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let parsed = parse_sitemap_document(&text);
    assert_eq!(parsed.locs(), parse_sitemap_document(&text).locs());
    assert_eq!(
        sitemap_urls_from_robots(&text),
        sitemap_urls_from_robots(&text)
    );
}

/// Parse mutated wire payloads, then evaluate every request that deserializes.
pub fn evaluation_payload(data: &[u8]) {
    if let Ok(request) = serde_json::from_slice::<EvaluationRequest>(data) {
        assert_deterministic(&request);
    }
}

fn assert_deterministic(request: &EvaluationRequest) {
    match (evaluate(request), evaluate(request)) {
        (Ok(first), Ok(second)) => {
            assert_eq!(
                serde_json::to_value(first).expect("serializable evaluation"),
                serde_json::to_value(second).expect("serializable evaluation")
            );
        }
        (Err(first), Err(second)) => assert_eq!(first, second),
        _ => panic!("identical facts must produce the same evaluation outcome"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_page_corpus_exercises_fuzz_oracles() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../engine/fixtures/checks/golden.json")).unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            page_input(case["page"]["body"].as_str().unwrap().as_bytes());
            evaluation_payload(
                &serde_json::to_vec(&serde_json::json!({ "page": case["page"] })).unwrap(),
            );
        }
    }

    #[test]
    fn sitemap_oracle_accepts_unicode_and_malformed_documents() {
        for input in [
            "abcdefg😃",
            "🙂🙂🙂",
            "Sitemap: https://example.com/sitemap.xml",
            "<urlset><url><loc>https://example.com</loc></url></urlset>",
            "<sitemapindex><sitemap><loc>&#x1F642;</loc></sitemap>",
            "</loc><!DOCTYPE urlset [<!ENTITY x 'value'>]>",
        ] {
            sitemap_input(input.as_bytes());
        }
    }

    #[test]
    fn invalid_payloads_and_non_utf8_bytes_do_not_panic() {
        for input in [&b"\xff\xfe\0"[..], &b"{"[..], &b"null"[..]] {
            evaluation_payload(input);
            page_input(input);
            sitemap_input(input);
        }
    }
}
