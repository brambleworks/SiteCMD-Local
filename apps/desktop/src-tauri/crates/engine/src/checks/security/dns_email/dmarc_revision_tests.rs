use super::*;

#[test]
fn a_bad_author_policy_cannot_inherit_a_psd_pass() {
    // Bug: a single DMARC record with a bad policy is discarded for a false PSD Pass.
    let (result, questions) = walk(
        "example.bank",
        &[
            ("_dmarc.example.bank", &["v=DMARC1; p=rejct"]),
            ("_dmarc.bank", &["v=DMARC1; p=reject; psd=y"]),
        ],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Fail);
    assert_eq!(result.title, "DMARC policy is not applied");
    assert!(result
        .description
        .contains("receivers apply no DMARC processing"));
    assert_eq!(questions.txt, ["_dmarc.example.bank"]);
    assert_eq!(questions.mx, ["example.bank"]);
}

#[test]
fn missing_policy_at_a_psd_boundary_stops_the_walk() {
    // Bug: policy validation discards a boundary record that discovery must keep.
    for psd in ["n", "y"] {
        let boundary = format!("v=DMARC1; psd={psd}; rua=mailto:a@example.com");
        let (result, questions) = walk(
            "a.example.com",
            &[
                ("_dmarc.example.com", &[&boundary]),
                ("_dmarc.com", &["v=DMARC1; p=reject; psd=y"]),
            ],
            Some(true),
        );
        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(
            questions.txt,
            ["_dmarc.a.example.com", "_dmarc.example.com"]
        );
        assert_eq!(
            result.raw_data.as_ref().unwrap()["organizational_domain"],
            if psd == "n" {
                "example.com"
            } else {
                "a.example.com"
            }
        );
    }
}

#[test]
fn policy_errors_with_a_reporting_uri_act_as_p_none() {
    // Bug: bad or missing p, sp, or np fails instead of applying the reporting fallback.
    for tags in ["", "p=rejct;", "p=reject; sp=bogus;", "p=reject; np=bogus;"] {
        let record = format!("v=DMARC1; {tags} rua=mailto:r@example.com");
        assert!(matches!(
            evaluate_dmarc(&records(&[&record])),
            DmarcEvaluation::PolicyNone
        ));
        let (result, questions) = walk(
            "example.com",
            &[("_dmarc.example.com", &[&record])],
            Some(true),
        );
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(
            result.description.contains("treat it as p=none"),
            "{}",
            result.description
        );
        assert!(!result.description.contains("required"));
        assert_eq!(
            result.raw_data.as_ref().unwrap()["effective_policy"],
            "none"
        );
        assert_eq!(questions.txt.len(), 1);
    }
}

#[test]
fn unusable_reporting_uris_do_not_rescue_a_missing_policy() {
    // Bug: an optional p tag is called required instead of reporting no DMARC processing.
    for rua in [
        "",
        "; rua=not-a-uri",
        "; rua=mailto:",
        "; rua=mailto:a b@example.com",
        "; rua=mailto:r@example.com%ZZ",
    ] {
        let record = format!("v=DMARC1{rua}");
        let (result, questions) = walk(
            "example.com",
            &[("_dmarc.example.com", &[&record])],
            Some(true),
        );
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.description.contains("no valid p= policy tag"));
        assert!(result.description.contains("no valid rua= reporting URI"));
        assert!(!result.description.contains("required"));
        assert_eq!(questions.txt.len(), 1);
    }
}

#[test]
fn optional_policy_errors_fail_direct_records_or_use_reporting_fallback() {
    // Bug: direct sp and np validation changes verdicts without pinning both fallback paths.
    for tag in ["sp", "np"] {
        for reporting in [true, false] {
            let record = format!(
                "v=DMARC1; p=reject; {tag}=bogus{}",
                if reporting {
                    "; rua=mailto:r@example.com"
                } else {
                    ""
                }
            );
            let (result, questions) = walk(
                "example.com",
                &[("_dmarc.example.com", &[&record])],
                Some(true),
            );
            assert_eq!(
                result.status,
                if reporting {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Fail
                }
            );
            assert!(result
                .description
                .contains(&format!("unknown policy value {tag}=bogus")));
            assert_eq!(questions.txt.len(), 1);
        }
    }
}

#[test]
fn reporting_fallback_cannot_reapply_an_inherited_sp() {
    // Bug: fallback to p=none can accidentally reselect an enforcing sp from the bad record.
    let (result, _) = walk(
        "example.com",
        &[(
            "_dmarc.com",
            &["v=DMARC1; p=rejct; sp=reject; rua=mailto:r@example.com; psd=y"],
        )],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(
        result.raw_data.as_ref().unwrap()["effective_policy"],
        "none"
    );
    assert_eq!(result.raw_data.as_ref().unwrap()["policy_domain"], "com");
}

#[test]
fn inherited_advice_always_publishes_the_authors_own_record() {
    // Bug: advice on an inherited Pass replaces enforcement with monitoring.
    for (policy, expected) in [
        ("p=reject", CheckStatus::Pass),
        ("p=reject; sp=quarantine", CheckStatus::Pass),
        ("p=reject; t=y", CheckStatus::Pass),
        ("p=none", CheckStatus::Warn),
        ("p=reject; sp=none", CheckStatus::Warn),
        ("p=quarantine; t=y", CheckStatus::Warn),
        ("p=rejct", CheckStatus::Warn),
    ] {
        let record = format!("v=DMARC1; {policy}; psd=y; rua=mailto:operator@com");
        let (result, _) = walk("example.com", &[("_dmarc.com", &[&record])], Some(true));
        assert_eq!(result.status, expected);
        if expected == CheckStatus::Pass {
            assert!(
                result.manual_fix.is_none(),
                "{policy}: {:?}",
                result.manual_fix
            );
            continue;
        }
        let advice = result
            .manual_fix
            .as_deref()
            .expect("publish own record advice");
        assert!(
            advice.contains("Publish a TXT record at _dmarc.example.com"),
            "{advice}"
        );
        assert!(!advice.contains("sp="), "{policy}: {advice}");
        assert!(!advice.contains("t=y"));
        assert!(
            advice.contains("rua=mailto:dmarc-reports@example.com"),
            "{advice}"
        );
    }
}

#[test]
fn wrongly_cased_versions_are_discarded_before_policy_discovery() {
    // Bug: a lowercase DMARC version blocks discovery of the actual policy.
    let (result, questions) = walk(
        "mail.example.com",
        &[
            ("_dmarc.mail.example.com", &["v=dmarc1; p=none; psd=n"]),
            ("_dmarc.example.com", &["v = DMARC1; p=reject; psd=n"]),
        ],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(questions.txt.len(), 2);
}

#[test]
fn direct_reporting_fallback_advice_repairs_the_bad_tag() {
    // Bug: changing p leaves an invalid sp or np tag in place and preserves fallback.
    for tag in ["sp", "np"] {
        let record = format!("v=DMARC1; p=reject; {tag}=bogus; rua=mailto:r@example.com");
        let (result, _) = walk(
            "example.com",
            &[("_dmarc.example.com", &[&record])],
            Some(true),
        );
        let advice = result.manual_fix.as_deref().expect("repair advice");
        assert!(advice.contains(&format!("invalid {tag}=")), "{advice}");
        assert!(advice.contains("Correct or remove"), "{advice}");
        assert!(!advice.contains("move to `p=quarantine`"));
    }
}

#[test]
fn unapplied_policy_copy_explains_the_outcome_once_without_parse_claims() {
    // Bug: a syntactically valid record is called malformed and no DMARC is repeated.
    let (result, _) = walk(
        "example.com",
        &[("_dmarc.example.com", &["v=DMARC1"])],
        Some(true),
    );
    assert_eq!(result.title, "DMARC policy is not applied");
    assert_eq!(
        result.description.matches("no DMARC").count(),
        1,
        "{}",
        result.description
    );
    assert!(!result.description.contains("cannot parse"));
    assert!(!result
        .why_it_matters
        .as_deref()
        .unwrap()
        .contains("cannot parse"));
}

#[test]
fn reporting_fallback_does_not_explain_an_inoperative_np_policy() {
    // Bug: fallback descriptions present an invalid np value as a second policy.
    for tags in ["p=reject; np=bogus", "p=rejct; np=reject"] {
        let record = format!("v=DMARC1; {tags}; rua=mailto:r@example.com");
        let (result, _) = walk(
            "example.com",
            &[("_dmarc.example.com", &[&record])],
            Some(true),
        );
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(
            !result.description.contains("The record also publishes np="),
            "{}",
            result.description
        );
    }
}

#[test]
fn fallback_evidence_reports_effective_policy_without_a_synthesized_publication() {
    // Bug: the evidence says p=none was published when only fallback synthesized it.
    let record = "v=DMARC1; p=reject; sp=bogus; rua=mailto:r@example.com";
    let (result, _) = walk(
        "example.com",
        &[("_dmarc.example.com", &[record])],
        Some(true),
    );
    let raw = result.raw_data.as_ref().expect("policy evidence");
    assert_eq!(raw["effective_policy"], "none");
    assert_eq!(raw["records"][0], record);
    assert!(raw.get("published_policy").is_none());
}
