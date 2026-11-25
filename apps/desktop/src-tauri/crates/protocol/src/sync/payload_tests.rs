use super::*;
use crate::coverage::{CoverageExceptionReason, ScanCoverageKind};
use crate::sync::snapshot::*;
use crate::sync::{ProjectFingerprintKey, FINGERPRINT_KEY_LEN};
use crate::vocab::{IssueConfidence, Severity};
use serde_json::{json, Value};

fn web_snapshot() -> WebSnapshot {
    WebSnapshot {
        observed_at: 1_754_784_000_000,
        based_on_event_sequence: 0,
        versions: WebVersions {
            fingerprint_schema: 1,
            canonicalizer: 1,
            crawl_profile: 1,
        },
        manifest_digest: "9e4b".repeat(4).parse().expect("fixture identifier"),

        coverage: WireCoverage {
            kind: ScanCoverageKind::PageSet,
            complete: true,
            routes: vec![
                "/".parse().expect("fixture identifier"),
                "/pricing".parse().expect("fixture identifier"),
            ],
            checks: vec!["security.csp".parse().expect("fixture identifier")],
            exceptions: vec![WireCoverageException {
                route: Some("/docs".parse().expect("fixture identifier")),
                checks_not_run: vec!["performance.lcp".parse().expect("fixture identifier")],
                reason: CoverageExceptionReason::CheckSkipped,
            }],
        },
        occurrences: vec![WebOccurrence {
            check: "security.csp".parse().expect("fixture identifier"),
            route: Some(crate::route::CanonicalRoute::new("/pricing", false)),
            scope_route: Some("/pricing".parse().expect("fixture identifier")),
            severity: Severity::High,
            confidence: Some(IssueConfidence::Confirmed),
        }],
        measurement_samples: vec![],
    }
}

fn bootstrap() -> DesktopSubmission {
    let mut submission = DesktopSubmission::new("site_9f2c81d0a4b3".parse().unwrap(), 1);
    submission.groups = Some(GroupSubmission {
        mode: GroupMode::Bootstrap,
        entries: vec![GroupEntry {
            check: "seo.canonical".parse().expect("fixture identifier"),
            state: ClientGroupState::ClaimedFixed,
            dismissal: None,
            state_changed_at: 1_754_697_600_000,
            sources: vec![FindingSource::Web],
            last_known_occurrences: vec![LastKnownOccurrence::Web(LastKnownWebOccurrence {
                identity: crate::route::CanonicalRoute::new("/", false),
                scope_routes: vec!["/".parse().expect("fixture identifier")],
            })],
        }],
    });
    submission.snapshots.web = Some(web_snapshot());
    submission
}

fn to_value(submission: &DesktopSubmission) -> Value {
    serde_json::from_str(&submission.render_for_inspection().expect("render")).expect("valid json")
}

#[test]
fn the_envelope_uses_the_wire_field_names() {
    let value = to_value(&bootstrap());
    for key in [
        "schema_version",
        "site_id",
        "environment",
        "submission_sequence",
        "groups",
        "snapshots",
    ] {
        assert!(value.get(key).is_some(), "missing {key} in {value:#}");
    }
    assert_eq!(value["schema_version"], json!(SCHEMA_VERSION));
    assert_eq!(value["environment"], json!("production"));
    assert_eq!(value["groups"]["mode"], json!("bootstrap"));
}

#[test]
fn omitting_groups_is_not_an_empty_group_set() {
    let mut submission = DesktopSubmission::new("site_1".parse().unwrap(), 2);
    submission.snapshots.web = Some(web_snapshot());
    let value = to_value(&submission);
    assert!(value.get("groups").is_none(), "{value:#}");
}

#[test]
fn a_client_cannot_assert_a_verified_state() {
    for state in ["verified_fixed", "regressed"] {
        let parsed: Result<ClientGroupState, _> = serde_json::from_value(json!(state));
        assert!(
            parsed.is_err(),
            "{state} must not be a client-assertable state"
        );
    }
    for state in ["active", "dismissed", "claimed_fixed"] {
        let parsed: Result<ClientGroupState, _> = serde_json::from_value(json!(state));
        assert!(parsed.is_ok(), "{state} must be assertable");
    }
}

#[test]
fn a_desktop_cannot_assert_attested_provenance() {
    for kind in ["exact", "unattested"] {
        let parsed: Result<DesktopProvenanceKind, _> = serde_json::from_value(json!(kind));
        assert!(parsed.is_err(), "{kind} must not be desktop-assertable");
    }
}

#[test]
fn a_dismissal_carries_its_policy_and_nothing_else_does() {
    let dismissed = GroupEntry {
        check: "security.csp".parse().expect("fixture identifier"),
        state: ClientGroupState::Dismissed,
        dismissal: Some(DismissalPolicy::Snoozed {
            until: 1_754_870_400_000,
        }),
        state_changed_at: 0,
        sources: vec![FindingSource::Web],
        last_known_occurrences: vec![],
    };
    assert!(dismissed.policy_matches_state());

    let mut policy_without_dismissal = dismissed.clone();
    policy_without_dismissal.state = ClientGroupState::Active;
    assert!(!policy_without_dismissal.policy_matches_state());

    let mut dismissal_without_policy = dismissed;
    dismissal_without_policy.dismissal = None;
    assert!(!dismissal_without_policy.policy_matches_state());
}

#[test]
fn dismissal_policies_serialize_with_their_kind_discriminator() {
    let cases = [
        (
            DismissalPolicy::Snoozed { until: 42 },
            json!({"kind": "snoozed", "until": 42}),
        ),
        (
            DismissalPolicy::Ignored {
                reopen_on_reobservation: true,
            },
            json!({"kind": "ignored", "reopen_on_reobservation": true}),
        ),
        (DismissalPolicy::Blocked {}, json!({"kind": "blocked"})),
    ];
    for (policy, expected) in cases {
        assert_eq!(serde_json::to_value(&policy).expect("serialize"), expected);
    }
}

#[test]
fn last_known_occurrences_distinguish_web_from_code() {
    // The two variants are structurally disjoint, which is what makes the
    // untagged encoding unambiguous rather than a guess at read time.
    let web = serde_json::to_value(LastKnownOccurrence::Web(LastKnownWebOccurrence {
        identity: crate::route::CanonicalRoute::new("/pricing", true),
        scope_routes: vec!["/plans".parse().expect("fixture identifier")],
    }))
    .expect("serialize");
    assert_eq!(
        web,
        json!({
            "route": "/pricing",
            "query_dependent": true,
            "scope_routes": ["/plans"]
        })
    );

    let code = serde_json::to_value(LastKnownOccurrence::Code {
        location_hash: "8c1f".repeat(16).parse().expect("fixture identifier"),
    })
    .expect("serialize");
    assert_eq!(code, json!({"location_hash": "8c1f".repeat(16)}));

    let round_trip: LastKnownOccurrence = serde_json::from_value(web).expect("parse web");
    assert!(matches!(round_trip, LastKnownOccurrence::Web(_)));
}

#[test]
fn the_payload_round_trips() {
    let original = bootstrap();
    let json = original.render_for_inspection().expect("render");
    let parsed: DesktopSubmission = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed, original);
}

#[test]
fn the_inspector_renders_the_bytes_that_are_sent() {
    let submission = bootstrap();
    let rendered: Value =
        serde_json::from_str(&submission.render_for_inspection().expect("render")).expect("json");
    let transported: Value = serde_json::to_value(&submission).expect("serialize");
    assert_eq!(rendered, transported);
}

#[test]
fn no_finding_content_survives_into_the_payload() {
    // Leak markers represent local finding text that the wire shape must exclude.
    const SECRETS: [&str; 8] = [
        "AKIAIOSFODNN7EXAMPLE",
        "/Users/example/project/src/lib/render.ts",
        "eval(userInput)",
        "Remove the eval call and parse the value instead",
        "Content-Security-Policy header is missing",
        "line 42",
        "detail_json",
        "C:\\Users\\example\\secret.env",
    ];

    let key = ProjectFingerprintKey::from_bytes([7u8; FINGERPRINT_KEY_LEN]);
    let mut submission = DesktopSubmission::new("site_9f2c81d0a4b3".parse().unwrap(), 3);
    submission.snapshots.code = Some(CodeSnapshot {
        observed_at: 1_754_780_400_000,
        based_on_event_sequence: 0,
        versions: CodeVersions {
            fingerprint_schema: 1,
            fingerprint_key_version: 1,
            canonicalizer: 1,
        },
        manifest_digest: "9e4b".repeat(4).parse().expect("fixture identifier"),

        key_commitment: key.commitment().parse().unwrap(),
        code_basis: CodeBasis {
            commit_sha: Some("45822983".parse().expect("fixture identifier")),
            kind: CodeBasisKind::Compatible,
            unvouched: vec![],
        },
        coverage: WireCoverage {
            kind: ScanCoverageKind::Project,
            complete: true,
            routes: vec![],
            checks: vec![],
            exceptions: vec![],
        },
        occurrences: vec![CodeOccurrence {
            check: "code_scan.security".parse().expect("fixture identifier"),
            // The location the finding came from reaches the wire only as this
            // keyed hash. The path itself is one of the markers below.
            location_hash: key
                .location_hash("no-eval", "src/lib/render.ts")
                .parse()
                .unwrap(),
            instance_count: 1,
            severity: Severity::Critical,
            confidence: Some(IssueConfidence::NeedsReview),
            provenance: CodeProvenance {
                commit_sha: Some("45822983".parse().expect("fixture identifier")),
                kind: DesktopProvenanceKind::Compatible,
            },
        }],
    });

    let wire = submission.render_for_inspection().expect("render");
    for secret in SECRETS {
        assert!(!wire.contains(secret), "payload leaked {secret}:\n{wire}");
    }
    // And the part that does travel is unresolvable without the key.
    assert!(!wire.contains("render.ts"), "{wire}");
    assert!(wire.contains(&key.location_hash("no-eval", "src/lib/render.ts")));
}
