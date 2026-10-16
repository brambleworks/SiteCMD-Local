//! Raw response bodies have the same meaning through the ABI and natively.

#[path = "support/abi.rs"]
mod abi;

use serde_json::{json, Value};
use sitecmd_engine::checks::seo::sitemap::{parse_sitemap_document, SitemapParse};
use sitecmd_engine::evaluation::{ExecutedProbe, PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeResponse};
use sitecmd_engine_wasm::{
    engine_route_evaluate, engine_route_open, engine_route_plan, engine_route_session_page,
};

fn page(bytes: &[u8]) -> PageArtifact {
    serde_json::from_value(json!({
        "url": "https://example.com/", "requested_url": "https://example.com/",
        "status_code": 200, "headers": [], "body": decode_probe_body(bytes.to_vec()).text,
        "evaluation_time": "2026-08-05T00:00:00Z"
    }))
    .expect("page")
}

fn samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = vec![
        (
            "ASCII".into(),
            b"User-agent: *\nDisallow: /private".to_vec(),
        ),
        (
            "quotes and backslashes".into(),
            br#""quoted" \\ path"#.to_vec(),
        ),
        ("line breaks".into(), b"first\r\nsecond\nthird\r".to_vec()),
        (
            "non-ASCII".into(),
            "caf\u{e9} \u{4e16}\u{754c} \u{1f680}".as_bytes().to_vec(),
        ),
        ("invalid byte".into(), vec![0xff]),
        ("truncated UTF-8".into(), vec![0xe2, 0x82]),
        ("empty".into(), Vec::new()),
    ];
    samples.extend((0..32).map(|byte| (format!("C0 {byte}"), vec![byte])));
    samples
}

fn body_call(entry: abi::Entry, request: &Value, region: &[u8]) -> Vec<u8> {
    abi::call_raw(
        entry,
        &abi::frame(&serde_json::to_vec(request).expect("JSON"), region),
    )
}

fn wire_open(bytes: &[u8]) -> Vec<u8> {
    let mut request = json!({"page": page(b"")});
    request["page"]["body"] = json!({"at": 3, "len": bytes.len()});
    let mut region = b"pre".to_vec();
    region.extend_from_slice(bytes);
    region.extend_from_slice(b"post");
    body_call(engine_route_open, &request, &region)
}

fn native_route() -> RouteSession {
    RouteSession::open(page(b"<html><head><title>Example</title></head></html>"))
        .expect("native route")
}

fn outcome(key: String, url: String, bytes: &[u8]) -> ExecutedProbe {
    ExecutedProbe::new(
        key,
        ProbeOutcome::Response(ProbeResponse {
            status: 200,
            final_url: url,
            content_type: Some("text/plain".into()),
            content_length: Some(bytes.len() as u64),
            headers: Vec::new(),
            body: Some(decode_probe_body(bytes.to_vec())),
        }),
    )
}

fn outcomes(route: &RouteSession, bytes: &[u8]) -> Vec<ExecutedProbe> {
    route
        .plan()
        .probes
        .into_iter()
        .map(|probe| outcome(probe.key, probe.request.url, bytes))
        .collect()
}

fn probe_request(probes: &[ExecutedProbe], bytes: &[u8]) -> (Value, Vec<u8>) {
    let mut request = json!({"probe_outcomes": probes});
    let mut region = b"prefix".to_vec();
    for probe in request["probe_outcomes"].as_array_mut().expect("outcomes") {
        probe["outcome"]["body"] = json!({"at": region.len(), "len": bytes.len()});
        region.extend_from_slice(bytes);
    }
    region.extend_from_slice(b"suffix");
    (request, region)
}

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("JSON answer")
}

#[test]
fn referenced_page_bodies_match_native_open_and_evaluation() {
    for (name, bytes) in samples() {
        let route = RouteSession::open(page(&bytes)).expect("native open");
        assert_eq!(value(&wire_open(&bytes)), json!(route.opened()), "{name}");
        assert_eq!(
            value(&abi::call(engine_route_evaluate, b"{}")),
            json!(route.evaluate(&RouteFacts::default())),
            "{name}"
        );
    }
}

#[test]
fn referenced_probe_bodies_match_native_plans() {
    for (name, sample) in samples() {
        let path: String = sample.iter().map(|byte| format!("{byte:02x}")).collect();
        let url = format!("https://example.com/samples/{path}/sitemap.xml");
        let bytes = format!("Sitemap: {url}\n").into_bytes();
        let mut route = native_route();
        let robots = route
            .plan()
            .probes
            .into_iter()
            .find(|probe| probe.request.url.ends_with("/robots.txt"))
            .expect("robots probe");
        let probes = vec![outcome(robots.key, robots.request.url, &bytes)];
        let (request, region) = probe_request(&probes, &bytes);
        route.record(Some(probes));
        let expected = route.plan();
        assert!(
            expected.probes.iter().any(|probe| probe.request.url == url),
            "{name}"
        );
        abi::open(&page(b"<html><head><title>Example</title></head></html>"));
        assert_eq!(
            value(&body_call(engine_route_plan, &request, &region)),
            json!(expected),
            "{name}"
        );
    }
}

#[test]
fn referenced_probe_bodies_match_native_evaluations() {
    for (name, bytes) in samples() {
        let mut route = native_route();
        let probes = outcomes(&route, &bytes);
        let (mut request, region) = probe_request(&probes, &bytes);
        request["vulnerability_facts"] = json!({"status": "answered", "advisories": []});
        let facts: RouteFacts = serde_json::from_value(request.clone()).expect("facts");
        route.record(Some(probes));
        abi::open(&page(b"<html><head><title>Example</title></head></html>"));
        assert_eq!(
            value(&body_call(engine_route_evaluate, &request, &region)),
            json!(route.evaluate(&facts)),
            "{name}"
        );
    }
}

#[test]
fn two_mib_page_bodies_match_native_open_and_session_facts() {
    const SIZE: usize = 2_097_152;
    let tail = b"<title>tail</title>";
    for byte in [b'"', 1, b'a'] {
        let mut bytes = vec![byte; SIZE - tail.len()];
        bytes.extend_from_slice(tail);
        let artifact = page(&bytes);
        let routes = [artifact.url.clone()];
        let route = RouteSession::open(artifact.clone()).expect("native open");
        let mut request = json!({"page": artifact});
        request["page"]["body"] = json!({"at": 0, "len": SIZE});
        assert_eq!(
            value(&body_call(engine_route_open, &request, &bytes)),
            json!(route.opened()),
            "padding byte {byte}"
        );
        let expected = route
            .session_page(&routes)
            .expect("native facts")
            .expect("named page");
        assert!(
            expected.title.is_some(),
            "padding byte {byte}: native title missing"
        );
        let actual = value(&abi::call_json(
            engine_route_session_page,
            &json!({"routes": routes}),
        ));
        assert_eq!(
            actual["title"],
            json!(expected.title),
            "padding byte {byte}: title fact"
        );
        assert_eq!(actual, json!(expected), "padding byte {byte}");
    }
}

#[test]
fn two_mib_robots_bodies_match_native_plans() {
    const SIZE: usize = 2_097_152;
    let url = "https://example.com/tail.xml";
    let tail = format!("\nSitemap: {url}");
    for byte in [b'"', 1, b'a'] {
        let mut bytes = vec![byte; SIZE - tail.len()];
        bytes.extend_from_slice(tail.as_bytes());
        let mut route = native_route();
        let robots = route
            .plan()
            .probes
            .into_iter()
            .find(|probe| probe.request.url.ends_with("/robots.txt"))
            .expect("robots probe");
        let probe = outcome(robots.key, robots.request.url, &bytes);
        let (request, region) = probe_request(std::slice::from_ref(&probe), &bytes);
        route.record(Some(vec![probe]));
        let expected = route.plan();
        assert!(expected.probes.iter().any(|probe| probe.request.url == url));
        abi::open(&page(b"<html><head><title>Example</title></head></html>"));
        let actual = value(&body_call(engine_route_plan, &request, &region));
        assert!(
            actual["probes"]
                .as_array()
                .expect("plan probes")
                .iter()
                .any(|probe| probe["request"]["url"] == url),
            "padding byte {byte}: tail sitemap missing"
        );
        assert_eq!(actual, json!(expected), "padding byte {byte}");
    }
}

#[test]
fn control_padded_sitemaps_keep_the_native_parser_refusal() {
    let bytes = b"<urlset>\x01<url><loc>https://example.com/listed</loc></url></urlset>";
    let decoded = decode_probe_body(bytes.to_vec());
    assert_eq!(decoded.text.as_bytes(), bytes);
    assert!(matches!(
        parse_sitemap_document(&decoded.text),
        SitemapParse::Salvaged {
            reason: "the sitemap XML has text outside an entry",
            ..
        }
    ));
    let mut route = native_route();
    let sitemap = route
        .plan()
        .probes
        .into_iter()
        .find(|probe| probe.request.url == "https://example.com/sitemap.xml")
        .expect("sitemap probe");
    let probes = vec![outcome(sitemap.key, sitemap.request.url, bytes)];
    let (request, region) = probe_request(&probes, bytes);
    let json = serde_json::to_vec(&request).expect("JSON");
    assert_eq!(
        &abi::frame(&json, &region)[4 + json.len() + 6..][..bytes.len()],
        bytes
    );
    route.record(Some(probes));
    abi::open(&page(b"<html><head><title>Example</title></head></html>"));
    assert_eq!(
        value(&body_call(engine_route_plan, &request, &region)),
        json!(route.plan())
    );
    assert_eq!(
        value(&abi::call(engine_route_evaluate, b"{}")),
        json!(route.evaluate(&RouteFacts::default()))
    );
    let routes = ["https://example.com/", "https://example.com/listed"];
    assert_eq!(
        value(&abi::call_json(
            sitecmd_engine_wasm::engine_route_session_page,
            &json!({"routes": routes})
        )),
        json!(route
            .session_page(&routes.map(str::to_string))
            .expect("facts"))
    );
}
