use super::*;
use serde_json::json;

#[test]
fn only_a_checkout_or_compatible_basis_may_resolve_absence() {
    assert!(CodeBasisKind::ExactCheckout.may_resolve_absence());
    assert!(CodeBasisKind::Compatible.may_resolve_absence());
    assert!(!CodeBasisKind::Stale.may_resolve_absence());
    assert!(!CodeBasisKind::Unknown.may_resolve_absence());
}

#[test]
fn the_desktop_basis_is_named_apart_from_the_attested_one() {
    assert_eq!(
        serde_json::to_value(CodeBasisKind::ExactCheckout).expect("serialize"),
        json!("exact_checkout")
    );
    let attested: Result<CodeBasisKind, _> = serde_json::from_value(json!("exact"));
    assert!(attested.is_err());
}

#[test]
fn a_web_occurrence_carries_its_route_and_query_flag_flat() {
    let occurrence = WebOccurrence {
        check: "security.csp".parse().expect("fixture identifier"),
        route: Some(crate::route::CanonicalRoute::new("/product", true)),
        scope_route: Some("/catalog".parse().expect("fixture identifier")),
        severity: crate::vocab::Severity::High,
        confidence: None,
    };
    assert_eq!(
        serde_json::to_value(&occurrence).expect("serialize"),
        json!({
            "check": "security.csp",
            "route": "/product",
            "query_dependent": true,
            "scope_route": "/catalog",
            "severity": "high",
        })
    );
}

#[test]
fn a_site_scoped_occurrence_does_not_invent_a_route() {
    let occurrence = WebOccurrence {
        check: "seo.duplicate_title_across_pages"
            .parse()
            .expect("fixture identifier"),
        route: None,
        scope_route: None,
        severity: crate::vocab::Severity::Medium,
        confidence: Some(crate::vocab::IssueConfidence::Confirmed),
    };

    let value = serde_json::to_value(&occurrence).expect("serialize");
    assert!(value.get("route").is_none());
    assert!(value.get("query_dependent").is_none());
}

#[test]
fn coverage_states_a_claim_and_the_pairs_it_does_not_reach() {
    let coverage = WireCoverage {
        kind: crate::coverage::ScanCoverageKind::PageSet,
        complete: true,
        routes: vec![
            "/".parse().expect("fixture identifier"),
            "/docs".parse().expect("fixture identifier"),
        ],
        checks: vec![
            "security.csp".parse().expect("fixture identifier"),
            "performance.lcp".parse().expect("fixture identifier"),
        ],
        exceptions: vec![WireCoverageException {
            route: Some("/docs".parse().expect("fixture identifier")),
            checks_not_run: vec!["performance.lcp".parse().expect("fixture identifier")],
            reason: crate::coverage::CoverageExceptionReason::CheckSkipped,
        }],
    };
    let value = serde_json::to_value(&coverage).expect("serialize");
    assert_eq!(value["kind"], json!("page_set"));
    assert_eq!(value["complete"], json!(true));
    assert_eq!(value["exceptions"][0]["reason"], json!("check_skipped"));
    assert_eq!(
        value["exceptions"][0]["checks_not_run"],
        json!(["performance.lcp"])
    );
}

#[test]
fn a_code_snapshot_states_no_crawl_profile() {
    // A code scan walks a project tree and crawls nothing. Carrying the field
    // would state a fact about an activity that did not occur.
    let versions = CodeVersions {
        fingerprint_schema: 1,
        fingerprint_key_version: 1,
        canonicalizer: 1,
    };
    let value = serde_json::to_value(&versions).expect("serialize");
    assert!(value.get("crawl_profile").is_none(), "{value:#}");
    assert_eq!(value["fingerprint_key_version"], json!(1));
}

#[test]
fn an_empty_collection_is_omitted_rather_than_sent_as_noise() {
    // The payload is meant to be read by a human in the sync inspector. Empty
    // arrays for every optional collection would bury the facts that matter.
    let coverage = WireCoverage {
        kind: crate::coverage::ScanCoverageKind::Project,
        complete: true,
        routes: vec![],
        checks: vec![],
        exceptions: vec![],
    };
    let value = serde_json::to_value(&coverage).expect("serialize");
    assert_eq!(value, json!({"kind": "project", "complete": true}));
}

#[test]
fn measurement_units_accept_only_the_manifest_vocabulary() {
    // runtime labels such as webkit and Next.js were accepted as units.
    for unit in ["ms", "ratio"] {
        assert!(serde_json::from_value::<MeasurementSample>(
            json!({"check":"performance.lcp", "value":1.0, "unit":unit})
        )
        .is_ok());
    }
    for unit in ["webkit", "Next.js", "bytes", "score", "dns"] {
        assert!(serde_json::from_value::<MeasurementSample>(
            json!({"check":"performance.lcp", "value":1.0, "unit":unit})
        )
        .is_err());
    }
}
