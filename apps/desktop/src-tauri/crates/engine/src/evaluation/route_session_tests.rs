use super::*;

#[test]
fn probe_plans_ignore_resolver_and_vulnerability_facts() {
    let linked: PageArtifact = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/",
        "requested_url": "https://example.com/",
        "status_code": 200,
        "headers": [["content-type", "text/html; charset=utf-8"]],
        "body": concat!(
            "<html><head><title>Home</title><link rel=\"icon\" href=\"/icon.png\"></head>",
            "<body><a href=\"/about\">About</a><a href=\"/team\">Team</a>",
            "<a href=\"https://elsewhere.example.net/\">Elsewhere</a></body></html>"
        ),
        "evaluation_time": "2026-08-05T00:00:00Z"
    }))
    .expect("a linked page");
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/checks/golden.json"))
            .expect("corpus parses");
    let pages = std::iter::once(linked).chain(
        corpus["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .map(|case| serde_json::from_value(case["page"].clone()).expect("a page artifact")),
    );
    let facts: RouteFacts = serde_json::from_value(serde_json::json!({
        "resolver_facts": {
            "domain": "example.com",
            "apex_txt": { "answer": "no_records" },
            "apex_mx": { "answer": "no_records" },
            "dmarc_txt": { "answer": "no_records" },
            "dkim_txt": [],
            "dnskey": { "answer": "no_records" },
            "caa": { "answer": "no_records" },
            "www_cname": { "answer": "no_records" },
            "www_target_addresses": null
        },
        "vulnerability_facts": { "status": "answered", "advisories": [] }
    }))
    .expect("route facts parse");
    for page in pages {
        let route = RouteSession::open(page).expect("opens");
        let outcomes = ProbeOutcomes::index(&[]);
        assert_eq!(
            serde_json::to_value(plan_probes(&route.context(&outcomes, &facts)))
                .expect("plan with facts serializes"),
            serde_json::to_value(route.plan()).expect("route plan serializes"),
            "{}",
            route.page.url
        );
    }
}

#[test]
fn every_call_reads_one_resolution_of_the_page_anchors() {
    let page: PageArtifact = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/",
        "status_code": 200,
        "headers": [],
        "body": "<a href=\"/about\">About</a><a href=\"https://elsewhere.example.net/\">Out</a>",
        "evaluation_time": "2026-08-05T00:00:00Z"
    }))
    .expect("a page");
    let mut route = RouteSession::open(page).expect("opens");
    route.record(Some(Vec::new()));
    route.plan();
    let first = route.link_targets.get().map(std::ptr::from_ref);
    assert!(first.is_some(), "a link planner resolved the anchors");
    route.plan();
    route.evaluate(&RouteFacts::default());
    assert_eq!(route.link_targets.get().map(std::ptr::from_ref), first);
}

#[test]
fn every_call_reads_one_resolution_of_the_asset_sample() {
    let page: PageArtifact = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/",
        "status_code": 200,
        "headers": [],
        "body": "<img src=\"/hero.png\" alt=\"Hero\"><script src=\"/app.js\"></script>",
        "evaluation_time": "2026-08-05T00:00:00Z"
    }))
    .expect("a page");
    let mut route = RouteSession::open(page).expect("opens");
    route.record(Some(Vec::new()));
    route.plan();
    let first = route.asset_sample.get().map(std::ptr::from_ref);
    assert!(first.is_some(), "the asset planner resolved the sample");
    route.plan();
    route.evaluate(&RouteFacts::default());
    assert_eq!(route.asset_sample.get().map(std::ptr::from_ref), first);
}
