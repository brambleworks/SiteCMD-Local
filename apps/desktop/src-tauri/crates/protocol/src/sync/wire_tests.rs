use super::*;
#[test]
fn arbitrary_machine_text_cannot_serialize_as_any_wire_value() {
    macro_rules! rejected { ($($kind:ident),*) => { $(
        assert!($kind::try_from("customer source\nconst secret = 1;").is_err(), stringify!($kind));
    )* }; }
    rejected!(
        ManifestDigest,
        AuthorityId,
        FindingIdentity,
        DeploymentTarget,
        Identifier,
        CheckId,
        Digest,
        CommitSha,
        RoutePath,
        RepositorySlug,
        RepositoryId,
        GitRef,
        WorkflowRef,
        Timestamp,
        SitecmdBranch,
        OutcomeCode,
        FindingOutcome,
        ClaimPurpose,
        OrderingKind,
        SeverityThreshold,
        DeviceCode
    );
}
#[test]
fn device_codes_accept_every_base64url_code() {
    // Bug: a device code starting with `-` or `_` was refused before the CLI could poll.
    for code in ["-Zm9v_YmFy", "_Zm9v-YmFy", "DEVICECODEFIXTURE"] {
        assert!(DeviceCode::try_from(code).is_ok(), "{code}");
    }
    for code in ["", "Zm9v=", "Zm9v.YmFy", "Zm9v YmFy", &"a".repeat(257)] {
        assert!(DeviceCode::try_from(code).is_err(), "{code}");
    }
}
#[test]
fn rejects_unknown_outcomes_and_fake_hashes() {
    assert!(OutcomeCode::try_from("tool output").is_err());
    assert!(Digest::try_from("src/customer.ts").is_err());
    assert!(RoutePath::try_from("/path?customer=secret").is_err());
    assert!(CommitSha::try_from("not-a-sha").is_err());
    assert!(OutcomeCode::try_from("build_failed").is_ok());
    assert!(serde_json::from_str::<Digest>("\"not-a-hash\"").is_err());
}

#[test]
fn canonical_route_objects_cannot_bypass_route_validation() {
    let route = crate::route::CanonicalRoute::new("/?secret=customer", false);
    assert!(serde_json::to_string(&route).is_err());
}

fn corpus(kind: &str) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/parity/wire_identifiers.json"
    ))
    .unwrap();
    let mut failures = Vec::new();
    for (label, expected) in [("valid", true), ("invalid", false)] {
        for value in fixture["types"][kind][label].as_array().unwrap() {
            macro_rules! accepts {
                ($ty:ty) => {{
                    let constructed =
                        <$ty>::try_from(value.as_str().expect("string corpus example"));
                    let decoded = serde_json::from_value::<$ty>(value.clone());
                    assert_eq!(
                        constructed.is_ok(),
                        decoded.is_ok(),
                        "constructor and decoder: {kind} {value}"
                    );
                    if let Ok(typed) = &constructed {
                        assert_eq!(
                            serde_json::to_value(typed).expect("valid wire value"),
                            *value
                        );
                    }
                    constructed.is_ok()
                }};
            }
            let accepted = match kind {
                "route_path" => accepts!(RoutePath),
                "git_ref" => accepts!(GitRef),
                "deployment_id" => accepts!(Identifier),
                "deployment_target" => accepts!(DeploymentTarget),
                "check_id" => accepts!(CheckId),
                "finding_identity" => accepts!(FindingIdentity),
                "sitecmd_branch" => accepts!(SitecmdBranch),
                "workflow_ref" => accepts!(WorkflowRef),
                "repository_slug" => accepts!(RepositorySlug),
                "commit_sha" => accepts!(CommitSha),
                "digest" => accepts!(Digest),
                "timestamp" => accepts!(Timestamp),
                "authority_id" => accepts!(AuthorityId),
                "manifest_digest" => accepts!(ManifestDigest),
                _ => panic!("unknown corpus type"),
            };
            if accepted != expected {
                failures.push(format!("{kind} {label}: {value}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn provider_deployment_identifiers_match_corpus() {
    // provider branches, targets, and predecessor ids were refused locally.
    for kind in ["git_ref", "deployment_id", "deployment_target"] {
        corpus(kind);
    }
}
#[test]
fn cookie_check_ids_match_corpus() {
    // valid HTTP cookie token characters blocked an entire submission.
    corpus("check_id");
}
#[test]
fn routes_match_corpus() {
    // routes longer than Connect's limit were sent as valid identities.
    corpus("route_path");
}
#[test]
fn workflows_match_corpus() {
    // workflow refs required a suffix their producer forbade.
    corpus("workflow_ref");
}
#[test]
fn lane_branch_and_instant_grammars_match_corpus() {
    // finding lanes, branch casing, and strict instants disagreed with Connect.
    for kind in [
        "finding_identity",
        "sitecmd_branch",
        "repository_slug",
        "commit_sha",
        "digest",
        "timestamp",
    ] {
        corpus(kind);
    }
    assert!(serde_json::from_str::<SeverityThreshold>("\"info\"").is_err());
}

#[test]
fn pull_request_head_sha_is_exactly_forty_digits() {
    // pull request heads accepted abbreviated and SHA-256 commits.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/parity/wire_identifiers.json"
    ))
    .unwrap();
    for (key, accepted) in [("head_valid", true), ("head_invalid", false)] {
        for value in fixture["types"]["commit_sha"][key].as_array().unwrap() {
            assert_eq!(
                serde_json::from_value::<HeadSha>(value.clone()).is_ok(),
                accepted
            );
        }
    }
}

#[test]
fn every_url_path_character_has_a_wire_corpus_example() {
    // Every emitted path character needs both canonicalization and wire coverage.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/parity/wire_identifiers.json"
    ))
    .unwrap();
    assert!(
        RoutePath::try_from("/a^b").is_err(),
        "raw caret is not canonical"
    );
    assert!(RoutePath::try_from("/a%5Eb").is_ok());
    assert_eq!(crate::route::canonical_path("/a^b"), "/a%5Eb");
    let valid = fixture["types"]["route_path"]["valid"].as_array().unwrap();
    for byte in b'!'..=b'~' {
        let mut url = url::Url::parse("https://example.com/").unwrap();
        url.set_path(&format!("/a{}b", byte as char));
        let path = crate::route::canonical_route(&url).route;
        assert!(
            RoutePath::try_from(path.as_str()).is_ok(),
            "engine emitted {path}"
        );
        assert!(
            valid.iter().any(|value| value == &path),
            "missing corpus example {path}"
        );
    }
}

#[test]
fn authority_and_manifest_width_have_valid_and_invalid_corpus_examples() {
    // live ordering authorities and the engine's 16-digit manifest were uncovered.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/parity/wire_identifiers.json"
    ))
    .unwrap();
    for kind in ["authority_id", "manifest_digest"] {
        for label in ["valid", "invalid"] {
            assert!(
                fixture["types"][kind][label]
                    .as_array()
                    .is_some_and(|values| !values.is_empty()),
                "missing {kind}.{label}"
            );
        }
        corpus(kind);
    }
}

#[test]
fn route_corpus_covers_refused_characters_and_repeated_slashes() {
    // missing refusal and repeated-slash examples left Connect's route parity unchecked.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/parity/wire_identifiers.json"
    ))
    .unwrap();
    let routes = &fixture["types"]["route_path"];
    for path in ["/a>b", "/a`b", "/a{b", "/a}b"] {
        assert!(routes["invalid"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == path));
        assert!(RoutePath::try_from(path).is_err());
    }
    assert!(routes["valid"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "//a"));
    assert_eq!(crate::route::canonical_path("//a"), "//a");
    assert_ne!(crate::route::canonical_path("//a"), "/a");
    corpus("route_path");
}

#[test]
fn authored_route_transformations_have_canonical_corpus_pairs() {
    // The shared corpus must exercise Unicode, control, whitespace, and backslash rules.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/parity/wire_identifiers.json"
    ))
    .unwrap();
    let routes = &fixture["types"]["route_path"];
    for (authored, expected) in [
        ("/café", "/caf%C3%A9"),
        ("/a\tb", "/ab"),
        ("/a\nb", "/ab"),
        ("/a\\b", "/a/b"),
        ("/a\u{1}b", "/a%01b"),
    ] {
        let mut observed = url::Url::parse("https://example.com/").unwrap();
        observed.set_path(authored);
        assert_eq!(observed.path(), expected);
        assert_eq!(crate::route::canonical_route(&observed).route, expected);
        assert_eq!(crate::route::canonical_path(authored), expected);
        assert!(routes["canonicalization"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pair| { pair["authored"] == authored && pair["canonical"] == expected }));
        assert!(routes["valid"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == expected));
        assert!(routes["invalid"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == authored));
    }
}
