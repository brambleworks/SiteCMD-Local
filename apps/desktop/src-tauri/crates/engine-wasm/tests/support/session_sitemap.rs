//! Sitemap routes survive the framed route ABI.

use super::{abi, request};
use sitecmd_engine::evaluation::{ExecutedProbe, RouteSession};
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeRequest, ProbeResponse};
use sitecmd_engine_wasm::{engine_route_plan, engine_route_sitemap_routes};

const SITEMAP: &str = concat!(
    "<urlset><url><loc>https://example.com/a</loc></url>",
    "<url><loc>https://example.com/b</loc></url></urlset>"
);

fn response(request: &ProbeRequest) -> ProbeOutcome {
    let body = if request.url.ends_with("/sitemap.xml") {
        SITEMAP
    } else {
        ""
    };
    ProbeOutcome::Response(ProbeResponse {
        status: 200,
        final_url: request.url.clone(),
        content_type: None,
        content_length: None,
        headers: Vec::new(),
        body: Some(decode_probe_body(body.as_bytes().to_vec())),
    })
}

#[test]
fn sitemap_routes_round_trip_bounds_and_error_status_through_the_abi() {
    // An ABI caller loses sitemap bounds or stores routes from an error document.
    for status in [200, 500] {
        let mut page = request("https://example.com/").page;
        page.status_code = status;
        abi::open(&page);
        let mut native = RouteSession::open(page).expect("route");
        for _ in 0..40 {
            let plan = native.plan();
            if plan.probes.is_empty() {
                break;
            }
            let outcomes: Vec<_> = plan
                .probes
                .into_iter()
                .map(|probe| ExecutedProbe::new(probe.key, response(&probe.request)))
                .collect();
            native.record(Some(outcomes.clone()));
            let recorded = abi::call_json(
                engine_route_plan,
                &serde_json::json!({"probe_outcomes": outcomes}),
            );
            assert!(abi::refusal(&recorded).is_none());
        }
        for (limit, byte_limit) in [(5_000, 1_048_576), (1, 6), (0, 2)] {
            let bytes = abi::call_json(
                engine_route_sitemap_routes,
                &serde_json::json!({"limit": limit, "byte_limit": byte_limit}),
            );
            let expected =
                serde_json::to_value(native.sitemap_routes(limit, byte_limit)).expect("native");
            assert_eq!(bytes, serde_json::to_vec(&expected).expect("JSON"));
            assert_eq!(expected["complete"], status == 200 && limit == 5_000);
            if status == 500 {
                assert!(expected["routes"].is_null());
            }
        }
        let malformed = abi::call(engine_route_sitemap_routes, br#"{"limit": "many"}"#);
        assert!(abi::refusal(&malformed).is_some());
    }
}
