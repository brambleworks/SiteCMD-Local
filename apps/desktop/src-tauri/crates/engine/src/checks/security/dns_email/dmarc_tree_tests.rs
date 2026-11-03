use super::*;

#[path = "dmarc_revision_tests.rs"]
mod revision;

struct ObservedQuestions {
    txt: Vec<String>,
    mx: Vec<String>,
}

fn walk(
    domain: &str,
    answers: &[(&str, &[&str])],
    mx: Option<bool>,
) -> (CheckResult, ObservedQuestions) {
    let name = dmarc_lookup_name(domain);
    let txt = answers
        .iter()
        .find(|(question, _)| *question == name)
        .map(|(_, values)| DnsOutcome::Records(records(values)))
        .unwrap_or(DnsOutcome::NoRecords);
    let mut questions = ObservedQuestions {
        txt: vec![name],
        mx: Vec::new(),
    };
    let mut step = evaluate_dmarc_txt(domain, txt);
    let result = loop {
        match step {
            DmarcStep::Done(mut results) => break results.remove(0),
            DmarcStep::NeedsTxt(pending) => {
                let name = pending.lookup_name();
                assert!(!questions.txt.iter().any(|previous| previous == name));
                questions.txt.push(name.to_string());
                let txt = answers
                    .iter()
                    .find(|(question, _)| *question == name)
                    .map(|(_, values)| DnsOutcome::Records(records(values)))
                    .unwrap_or(DnsOutcome::NoRecords);
                step = pending.evaluate(txt);
            }
            DmarcStep::NeedsMx(pending) => {
                questions.mx.push(pending.domain().to_string());
                assert_eq!(pending.domain(), domain);
                let mx = match mx {
                    Some(true) => DnsOutcome::Records(vec![MxRecord {
                        preference: 10,
                        exchange: "mail.example.com".into(),
                    }]),
                    Some(false) => DnsOutcome::NoRecords,
                    None => DnsOutcome::Failed("MX unavailable".into()),
                };
                break pending.evaluate(&mx).remove(0);
            }
        }
    };
    (result, questions)
}

#[test]
fn organizational_policy_uses_sp_then_falls_back_to_p() {
    // Bug: an absent subdomain record never discovers the organizational policy.
    for (record, expected) in [
        ("v=DMARC1; p=reject; sp=none", CheckStatus::Warn),
        ("v=DMARC1; p=reject", CheckStatus::Pass),
    ] {
        let (result, _) = walk(
            "mail.example.com",
            &[("_dmarc.example.com", &[record])],
            Some(true),
        );
        assert_eq!(result.status, expected);
        assert!(result.description.contains("_dmarc.example.com applies"));
        assert_eq!(
            result.raw_data.as_ref().unwrap()["policy_domain"],
            "example.com"
        );
    }
}

#[test]
fn psd_n_stops_at_the_organizational_domain() {
    // Bug: an explicit organizational boundary is not used to stop discovery.
    let (result, questions) = walk(
        "a.mail.example.com",
        &[
            ("_dmarc.mail.example.com", &["v=DMARC1; p=reject; psd=n"]),
            ("_dmarc.example.com", &["v=DMARC1; p=none"]),
        ],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(
        questions.txt,
        ["_dmarc.a.mail.example.com", "_dmarc.mail.example.com"]
    );
}

#[test]
fn psd_y_selects_the_domain_one_label_below_it() {
    // Bug: a PSD record cannot establish the organizational domain below it.
    let (result, questions) = walk(
        "a.mail.example.com",
        &[
            ("_dmarc.mail.example.com", &["v=DMARC1; p=reject; psd=u"]),
            ("_dmarc.example.com", &["v=DMARC1; p=none; psd=y"]),
        ],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(
        result.raw_data.as_ref().unwrap()["organizational_domain"],
        "mail.example.com"
    );
    assert_eq!(questions.txt.last().unwrap(), "_dmarc.example.com");
}

#[test]
fn psd_u_selects_the_highest_valid_record() {
    // Bug: discovery cannot continue past a non-terminal record to the organization.
    let (result, questions) = walk(
        "a.mail.example.com",
        &[
            ("_dmarc.mail.example.com", &["v=DMARC1; p=none; psd=u"]),
            ("_dmarc.example.com", &["v=DMARC1; p=reject; psd=u"]),
        ],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(
        result.raw_data.as_ref().unwrap()["policy_domain"],
        "example.com"
    );
    assert_eq!(questions.txt.last().unwrap(), "_dmarc.com");
}

#[test]
fn long_names_skip_to_seven_labels_and_never_exceed_eight_txt_questions() {
    // Bug: long domains need a bounded walk that skips intermediate labels.
    let (_, questions) = walk("a.b.c.d.e.f.g.h.i.j.mail.example.com", &[], Some(false));
    assert_eq!(
        questions.txt,
        [
            "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
            "_dmarc.g.h.i.j.mail.example.com",
            "_dmarc.h.i.j.mail.example.com",
            "_dmarc.i.j.mail.example.com",
            "_dmarc.j.mail.example.com",
            "_dmarc.mail.example.com",
            "_dmarc.example.com",
            "_dmarc.com",
        ]
    );
}

#[test]
fn short_names_and_eight_labels_have_the_expected_question_ceiling() {
    // Bug: the query ceiling must include the Author Domain and the MX gate.
    for (domain, total) in [
        ("example.com", 3),
        ("mail.example.com", 4),
        ("a.b.c.d.e.mail.example.com", 9),
        ("a.b.c.d.e.f.g.h.i.j.mail.example.com", 9),
    ] {
        let (_, questions) = walk(domain, &[], Some(false));
        assert_eq!(questions.txt.len() + questions.mx.len(), total);
        assert_eq!(questions.mx, [domain]);
        assert!(questions.txt.len() <= MAX_DMARC_TXT_QUESTIONS);
        assert_eq!(dmarc_tree_walk_names(domain), questions.txt[1..]);
    }
}

#[test]
fn author_policy_takes_precedence_and_test_mode_applies_to_inherited_sp() {
    // Bug: policy selection can confuse the Author Domain's p with an inherited sp.
    let (direct, questions) = walk(
        "example.com",
        &[("_dmarc.example.com", &["v=DMARC1; p=none; sp=reject"])],
        Some(true),
    );
    assert_eq!(direct.status, CheckStatus::Warn);
    assert_eq!(questions.txt.len(), 1);
    let (inherited, _) = walk(
        "mail.example.com",
        &[(
            "_dmarc.example.com",
            &["v=DMARC1; p=none; sp=reject; t=y; psd=n"],
        )],
        Some(true),
    );
    assert_eq!(inherited.status, CheckStatus::Pass);
    assert_eq!(
        inherited.raw_data.as_ref().unwrap()["effective_policy"],
        "quarantine"
    );
}

#[test]
fn a_failed_tree_question_skips_instead_of_claiming_absence() {
    // Bug: a failed ancestor lookup must not become a missing-policy finding.
    let DmarcStep::NeedsTxt(pending) =
        evaluate_dmarc_txt("mail.example.com", DnsOutcome::NoRecords)
    else {
        panic!("discovery needs its parent");
    };
    let DmarcStep::Done(results) =
        pending.evaluate(DnsOutcome::Failed("TXT query timed out".into()))
    else {
        panic!("a failed tree lookup skips without asking for MX");
    };
    assert_eq!(results[0].status, CheckStatus::Skipped);
    assert!(results[0].description.contains("_dmarc.example.com"));
}

#[test]
fn non_version_and_duplicate_records_are_discarded_during_discovery() {
    // Bug: unrelated TXT and duplicate DMARC records must not block discovery.
    for bad in [
        vec!["v=DMARC2; p=reject"],
        vec!["v=spf1 -all"],
        vec!["p=reject; v=DMARC1"],
        vec!["v=DMARC1; p=none", "v=DMARC1; p=reject"],
    ] {
        let (result, questions) = walk(
            "a.mail.example.com",
            &[
                ("_dmarc.a.mail.example.com", &bad),
                ("_dmarc.mail.example.com", &bad),
                ("_dmarc.example.com", &["v=DMARC1; p=reject; psd=n"]),
            ],
            Some(true),
        );
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(questions.txt.len(), 3);
    }
}

#[test]
fn test_mode_reduces_policy_by_one_level() {
    // Bug: test mode incorrectly grades the published policy at full strength.
    for (published, effective, status) in [
        ("reject", "quarantine", CheckStatus::Pass),
        ("quarantine", "none", CheckStatus::Warn),
        ("none", "none", CheckStatus::Warn),
    ] {
        let record = format!("v=DMARC1; p={published}; t=y");
        let (result, questions) = walk(
            "example.com",
            &[("_dmarc.example.com", &[&record])],
            Some(true),
        );
        assert_eq!(result.status, status);
        assert_eq!(
            result.raw_data.as_ref().unwrap()["effective_policy"],
            effective
        );
        assert!(result.description.contains("test mode"));
        assert_eq!(questions.txt.len(), 1);
    }
}

#[test]
fn removed_and_unknown_tags_generate_no_advice() {
    // Bug: rollout advice recommends a removed sampling tag.
    let (result, _) = walk(
        "example.com",
        &[(
            "_dmarc.example.com",
            &["v=DMARC1; p=none; pct=50; rf=afrf; ri=86400; future=value"],
        )],
        Some(true),
    );
    let visible = format!(
        "{} {} {:?} {:?} {:?}",
        result.title,
        result.description,
        result.manual_fix,
        result.fix_prompt,
        result.why_it_matters
    );
    for removed in ["pct", "rf=", "ri=", "future="] {
        assert!(!visible.contains(removed), "{visible}");
    }
}

#[test]
fn np_is_reported_without_changing_the_applied_policy() {
    // Bug: non-existent-domain policy must not grade an unobserved From address.
    let (result, _) = walk(
        "mail.example.com",
        &[(
            "_dmarc.example.com",
            &["v=DMARC1; p=none; np=reject; psd=n"],
        )],
        Some(true),
    );
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.raw_data.as_ref().unwrap()["np"], "reject");
    assert!(result.description.contains("np=reject"));
}

#[test]
fn exhausted_discovery_preserves_mx_gates_and_original_error_paths() {
    // Bug: fallback discovery must retain missing, malformed, and duplicate findings.
    for (initial, title) in [
        (vec![], "No DMARC record"),
        (vec!["v=DMARC1; p=invalid"], "DMARC policy is not applied"),
        (
            vec!["v=DMARC1; p=none", "v=DMARC1; p=reject"],
            "DMARC policy is not applied",
        ),
    ] {
        for mx in [Some(true), Some(false), None] {
            let (result, questions) = walk("example.com", &[("_dmarc.example.com", &initial)], mx);
            assert_eq!(result.check_id, CHECK_ID);
            assert_eq!(result.title, title);
            assert_eq!(
                result.severity,
                if mx == Some(true) {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            );
            assert_eq!(
                result.status,
                if title == "DMARC policy is not applied" && mx == Some(true) {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Warn
                }
            );
            assert_eq!(questions.mx, ["example.com"]);
            assert_eq!(
                questions.txt,
                if title == "DMARC policy is not applied" && initial.len() == 1 {
                    vec!["_dmarc.example.com"]
                } else {
                    vec!["_dmarc.example.com", "_dmarc.com"]
                }
            );
        }
    }
}
