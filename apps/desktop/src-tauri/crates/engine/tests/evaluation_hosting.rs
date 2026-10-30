//! The evaluation asks the DNS questions hosting is read from, and answers the
//! hosting a page and its resolver facts show.

use sitecmd_engine::evaluation::{evaluate, EvaluationRequest, PageArtifact};

fn page(url: &str) -> PageArtifact {
    serde_json::from_value(serde_json::json!({
        "url": url,
        "status_code": 200,
        "headers": [],
        "body": "<html><body>Hello</body></html>",
        "evaluation_time": "2026-01-01T00:00:00Z"
    }))
    .expect("page parses")
}

fn request(url: &str, resolver_facts: Option<serde_json::Value>) -> EvaluationRequest {
    EvaluationRequest {
        page: page(url),
        resolver_facts: resolver_facts.map(|wire| serde_json::from_value(wire).unwrap()),
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    }
}

#[test]
fn the_evaluation_asks_for_the_host_s_cname_and_the_domain_s_nameservers() {
    let response = evaluate(&request("https://WWW.Example.com/pricing", None)).unwrap();
    let resolver = response
        .external_fact_plan
        .resolver
        .expect("a public domain has DNS questions");
    assert_eq!(resolver.host_cname_name, "www.example.com");
    assert_eq!(resolver.ns_name, "example.com");
    assert_eq!(resolver.domain, "example.com");
}

#[test]
fn the_evaluation_names_a_pages_dev_site_s_host_without_any_dns() {
    let response = evaluate(&request("https://shop.pages.dev/", None)).unwrap();
    assert_eq!(response.stack.hosting.as_deref(), Some("Cloudflare Pages"));
}

#[test]
fn the_evaluation_reads_the_resolver_facts_it_is_handed() {
    let facts = serde_json::json!({
        "domain": "example.com",
        "apex_txt": { "answer": "no_records" },
        "apex_mx": { "answer": "no_records" },
        "dmarc_txt": { "answer": "no_records" },
        "dnskey": { "answer": "no_records" },
        "caa": { "answer": "no_records" },
        "www_cname": { "answer": "no_records" },
        "host_cname": { "answer": "records", "value": ["shop.pages.dev."] },
        "ns": { "answer": "records", "value": ["ada.ns.cloudflare.com."] }
    });
    let response = evaluate(&request("https://www.example.com/", Some(facts))).unwrap();
    assert_eq!(response.stack.hosting.as_deref(), Some("Cloudflare Pages"));
    assert_eq!(response.stack.dns_provider.as_deref(), Some("Cloudflare"));
}

#[test]
fn a_resolver_plan_cannot_query_a_host_with_its_root_dot() {
    let response = evaluate(&request("https://www.example.com./", None)).unwrap();
    let resolver = response
        .external_fact_plan
        .resolver
        .expect("a public domain has DNS questions");
    assert_eq!(resolver.host_cname_name, "www.example.com");
}
