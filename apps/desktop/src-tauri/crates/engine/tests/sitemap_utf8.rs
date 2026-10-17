//! Sitemap validity uses the original response's UTF-8 validity.

use sitecmd_engine::checks::seo::geo::sitemap_freshness::evaluate_sitemap_freshness;
use sitecmd_engine::checks::seo::sitemap::SitemapProbe;
use sitecmd_engine::checks::seo::sitemap_walk::walk_sitemap_candidates;
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeResponse};

fn response(bytes: Vec<u8>) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status: 200,
        final_url: "https://example.com/sitemap.xml".into(),
        content_type: Some("application/xml".into()),
        content_length: Some(bytes.len() as u64),
        headers: Vec::new(),
        body: Some(decode_probe_body(bytes)),
    })
}

#[test]
fn sitemap_validity_distinguishes_invalid_bytes_from_unicode() {
    let prefix = b"<urlset><url><loc>https://example.com/caf\xc3\xa9</loc><lastmod>2026-10-15</lastmod></url><!--";
    let suffix = b"--></urlset>";
    for (padding, valid) in [
        (b"ASCII".as_slice(), true),
        ("\u{FFFD} \u{4e16}\u{754c}".as_bytes(), true),
        (b"\xff".as_slice(), false),
        (b"\xe2\x82".as_slice(), false),
    ] {
        let bytes = [prefix.as_slice(), padding, suffix.as_slice()].concat();
        let answer = response(bytes);
        let candidates = vec!["https://example.com/sitemap.xml".into()];
        let result = walk_sitemap_candidates(&candidates, |_| Some(&answer)).expect("answered");
        if valid {
            let SitemapProbe::Found(found) = result else {
                panic!("valid Unicode sitemap was refused: {result:?}");
            };
            assert_eq!(found.entry_count, 1);
            assert!(found.body.contains("caf\u{e9}"));
            let freshness = evaluate_sitemap_freshness(&found);
            assert_eq!(
                freshness[0].raw_data.as_ref().expect("facts")["coverage_pct"],
                100
            );
        } else {
            let SitemapProbe::Missing { observations } = result else {
                panic!("invalid UTF-8 sitemap was accepted: {result:?}");
            };
            assert_eq!(
                observations[0].outcome,
                "HTTP 200 but the sitemap is not valid UTF-8"
            );
        }
    }
}

#[test]
fn invalid_child_encoding_leaves_the_index_comparison_incomplete() {
    use sitecmd_engine::checks::seo::sitemap_walk::{sitemap_child_request, sitemap_request};
    use sitecmd_engine::evaluation::{
        probe_key, ExecutedProbe, PageArtifact, RouteSession, SessionSitemapCause,
    };
    use sitecmd_engine::probe::ProbeRequest;

    let page: PageArtifact = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-10-16T00:00:00Z"
    }))
    .expect("page");
    for valid in [true, false] {
        let mut route = RouteSession::open(page.clone())
            .expect("route")
            .with_sitemap_children(1);
        route.record(Some(vec![
            ExecutedProbe::new(
                probe_key(&ProbeRequest::get("https://example.com/robots.txt")),
                response(b"Sitemap: https://example.com/sitemap.xml".to_vec()),
            ),
            ExecutedProbe::new(
                probe_key(&sitemap_request("https://example.com/sitemap.xml")),
                response(b"<sitemapindex><sitemap><loc>https://example.com/child.xml</loc></sitemap></sitemapindex>".to_vec()),
            ),
        ]));
        route.plan();
        let padding: &[u8] = if valid {
            "\u{FFFD}".as_bytes()
        } else {
            b"\xff"
        };
        let body = [
            b"<urlset><url><loc>https://example.com/listed</loc></url><!--".as_slice(),
            padding,
            b"--></urlset>".as_slice(),
        ]
        .concat();
        route.record(Some(vec![ExecutedProbe::new(
            probe_key(&sitemap_child_request("https://example.com/child.xml")),
            response(body),
        )]));
        let routes = [
            "https://example.com/".into(),
            "https://example.com/listed".into(),
        ];
        let facts = route.session_page(&routes).expect("facts").expect("page");
        let sitemap = facts.sitemap.expect("index");
        if valid {
            assert_eq!(sitemap.entries, ["r1"]);
            assert!(sitemap.partial_causes.is_empty());
        } else {
            assert!(sitemap.entries.is_empty());
            assert_eq!(
                sitemap.partial_causes,
                [SessionSitemapCause::Index { listed: 1, read: 0 }]
            );
        }
    }
}
