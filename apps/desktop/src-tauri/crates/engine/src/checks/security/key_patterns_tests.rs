//! Prefix metadata and iteration must agree with every recognized format.

use super::{key_pattern_services, KeyClass, KeyPattern, KEY_PATTERNS, PEM_PATTERN};

#[test]
fn overlapping_prefixes_use_the_longest_match_regardless_of_order() {
    let original = &KEY_PATTERNS[0];
    assert_eq!(original.service, "OpenAI");
    let reordered = KeyPattern {
        service: original.service,
        prefixes: &["sk-", "sk-proj-"],
        class: original.class,
        regex: original.regex.clone(),
        key_group: original.key_group,
    };
    assert!(reordered
        .matches(&format!("sk-proj-{}", "x".repeat(24)))
        .next()
        .is_none());
    let positive = format!("sk-proj-{}", "aB3_".repeat(6));
    assert_eq!(
        reordered.matches(&positive).next().unwrap().as_str(),
        positive
    );
}

#[test]
fn an_unmatched_capture_group_does_not_end_the_search() {
    let pattern = KeyPattern {
        service: "npm Token",
        prefixes: &["npm_"],
        class: KeyClass::Secret,
        regex: regex::Regex::new(r"unrelated|(npm_[A-Za-z0-9]{36})").unwrap(),
        key_group: 1,
    };
    let token = format!("npm_{}", "aB3".repeat(12));
    assert_eq!(
        pattern
            .matches(&format!("unrelated {token}"))
            .next()
            .unwrap()
            .as_str(),
        token
    );
}

#[test]
fn every_positive_sample_has_a_listed_literal_prefix_for_each_matching_pattern() {
    let samples: Vec<_> = [
        ("sk-", "aB3".repeat(8)),
        ("sk-proj-", "aB3_".repeat(6)),
        ("sk-svcacct-", "aB3_".repeat(6)),
        ("sk-admin-", "aB3_".repeat(6)),
        ("sk-ant-", "aB3".repeat(8)),
        ("sk_live_", "aB3".repeat(8)),
        ("sk_test_", "aB3".repeat(8)),
        ("pk_live_", "aB3".repeat(8)),
        ("pk_test_", "aB3".repeat(8)),
        ("AKIA", "A1B2".repeat(4)),
        ("AIza", "aB3_".repeat(8) + "aB3"),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            format!("{}.{}", "aB3".repeat(8), "cD4".repeat(8)),
        ),
        ("ghp_", "aB3".repeat(12)),
        ("gho_", "aB3".repeat(12)),
        ("ghu_", "aB3".repeat(12)),
        ("ghs_", "aB3".repeat(12)),
        ("ghr_", "aB3".repeat(12)),
        ("github_pat_", "aB3_".repeat(20) + "Z9"),
        ("rk_live_", "aB3".repeat(8)),
        ("glpat-", "aB3_-".repeat(4)),
        ("npm_", "aB3".repeat(12)),
        ("xoxb-", "aB3".repeat(8)),
        ("xoxa-", "aB3".repeat(8)),
        ("xoxp-", "aB3".repeat(8)),
        ("xoxr-", "aB3".repeat(8)),
        ("xoxs-", "aB3".repeat(8)),
        ("SK", "a1b2".repeat(8)),
        (
            "SG.",
            format!("{}.{}", "aB3_".repeat(5) + "aB", "cD4_".repeat(10) + "cD4"),
        ),
        ("key-", "aB3Z".repeat(8)),
    ]
    .into_iter()
    .map(|(prefix, body)| format!("{prefix}{body}"))
    .chain([format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----",
        "PRIVATE KEY",
        "aB3+".repeat(32),
        "PRIVATE KEY"
    )])
    .collect();
    for pattern in KEY_PATTERNS.iter().chain([&*PEM_PATTERN]) {
        let mut found = 0;
        for sample in &samples {
            for value in pattern.matches(sample) {
                found += 1;
                assert!(
                    pattern
                        .prefixes
                        .iter()
                        .any(|prefix| value.as_str().starts_with(prefix)),
                    "{} has stale prefixes",
                    pattern.service
                );
            }
        }
        assert!(found > 0, "{} has no positive sample", pattern.service);
    }
}

#[test]
fn a_lowercase_pem_marker_keeps_its_case_insensitive_match() {
    let text = format!(
        "-----begin private key-----\n{}\n-----end private key-----",
        "aB3+".repeat(32)
    );
    assert_eq!(key_pattern_services(&text), ["Private Key (PEM)"]);
}
