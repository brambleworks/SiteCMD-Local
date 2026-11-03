use super::*;
use crate::dns::{DnsOutcome, MxRecord};

#[path = "dmarc_tree_tests.rs"]
mod rfc9989;

fn records(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

#[test]
fn version_value_is_case_sensitive_and_equals_allows_whitespace() {
    // Bug: discovery accepts the wrong version case and rejects legal whitespace.
    assert!(is_dmarc_record("v=DMARC1; p=none"));
    assert!(is_dmarc_record("V = DMARC1 ; p=reject"));
    assert!(is_dmarc_record("v\t=\tDMARC1; p=reject"));
    assert!(!is_dmarc_record("v=dmarc1; p=reject"));
    assert!(!is_dmarc_record("p=reject; v=DMARC1"));
    assert!(!is_dmarc_record("v=DMARC10; p=none"));
    assert!(!is_dmarc_record("google-site-verification=abc"));
}

#[test]
fn extracts_tags_with_whitespace_and_case_variance() {
    let record = "v=DMARC1; P = Quarantine ; rua=mailto:reports@example.com";
    assert_eq!(dmarc_tag(record, "p").as_deref(), Some("quarantine"));
    assert_eq!(
        dmarc_tag(record, "rua").as_deref(),
        Some("mailto:reports@example.com")
    );
    assert_eq!(dmarc_tag(record, "sp"), None);
}

#[test]
fn policy_none_is_monitoring_only() {
    let evaluation = evaluate_dmarc(&records(&["v=DMARC1; p=none; rua=mailto:r@example.com"]));
    assert!(matches!(evaluation, DmarcEvaluation::PolicyNone));
}

#[test]
fn quarantine_and_reject_are_enforced() {
    assert!(matches!(
        evaluate_dmarc(&records(&["v=DMARC1; p=quarantine"])),
        DmarcEvaluation::PolicyEnforced { policy } if policy == "quarantine"
    ));
    assert!(matches!(
        evaluate_dmarc(&records(&["v=DMARC1; p=reject; sp=reject"])),
        DmarcEvaluation::PolicyEnforced { policy } if policy == "reject"
    ));
}

#[test]
fn missing_policy_with_reporting_uri_is_monitoring() {
    // Bug: RFC 9989 no longer requires p when a valid reporting URI permits fallback.
    assert!(matches!(
        evaluate_dmarc(&records(&["v=DMARC1; rua=mailto:r@example.com"])),
        DmarcEvaluation::PolicyNone
    ));
}

#[test]
fn unknown_policy_value_is_malformed() {
    assert!(matches!(
        evaluate_dmarc(&records(&["v=DMARC1; p=block"])),
        DmarcEvaluation::Malformed { .. }
    ));
}

#[test]
fn non_dmarc_txt_at_dmarc_name_is_no_record_not_malformed() {
    assert!(matches!(
        evaluate_dmarc(&records(&["some-verification=token"])),
        DmarcEvaluation::NoDmarcRecord
    ));
}

#[test]
fn duplicate_dmarc_records_are_malformed() {
    assert!(matches!(
        evaluate_dmarc(&records(&["v=DMARC1; p=none", "v=DMARC1; p=reject"])),
        DmarcEvaluation::Malformed { .. }
    ));
}

#[test]
fn p_none_severity_is_mx_gated() {
    let recs = records(&["v=DMARC1; p=none"]);
    let with_mx = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &recs,
        Some(true),
    );
    assert_eq!(with_mx.status, CheckStatus::Warn);
    assert_eq!(with_mx.severity, Severity::Medium);
    assert!(with_mx.description.contains("requested DMARC disposition"));
    assert!(!with_mx.description.contains("delivered normally"));
    assert!(!with_mx.description.contains("most domains"));

    let no_mx = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &recs,
        Some(false),
    );
    assert_eq!(no_mx.status, CheckStatus::Warn);
    assert_eq!(
        no_mx.severity,
        Severity::Low,
        "p=none on a no-MX domain must not grade worse than no DMARC at all"
    );
}

#[test]
fn malformed_record_is_mx_gated() {
    // Bug: changing the optional-p fallback must preserve malformed-record severity gates.
    let recs = records(&["v=DMARC1; p=rejct"]);
    let with_mx = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &recs,
        Some(true),
    );
    assert_eq!(with_mx.status, CheckStatus::Fail);
    assert_eq!(with_mx.severity, Severity::Medium);

    let no_mx = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &recs,
        Some(false),
    );
    assert_eq!(
        no_mx.status,
        CheckStatus::Warn,
        "a broken record on a no-MX domain must not outscore a missing one"
    );
    assert_eq!(no_mx.severity, Severity::Low);
}

#[test]
fn unrelated_txt_at_dmarc_name_reports_no_record() {
    let recs = records(&["some-verification=token"]);
    let result = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &recs,
        Some(true),
    );
    assert_eq!(result.title, "No DMARC record");
    assert_eq!(result.status, CheckStatus::Warn);
    assert!(
        result.description.contains("unrelated to DMARC"),
        "copy should call the TXT record unrelated: {}",
        result.description
    );
    assert!(
        !result.description.contains("No TXT record at"),
        "copy must not claim no TXT exists when one does: {}",
        result.description
    );
}

#[test]
fn missing_record_result_matches_the_missing_copy() {
    let result = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &[],
        Some(false),
    );
    assert_eq!(result.title, "No DMARC record");
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.severity, Severity::Low);
    assert!(result.description.contains("No TXT record at"));
    assert!(
        result
            .description
            .contains("publishes no MX records, so it shows no inbound mail setup"),
        "{}",
        result.description
    );
    assert!(result.description.contains("p=reject"));

    let unknown_mx = dmarc_result(
        "security.dns.dmarc",
        "example.com",
        "_dmarc.example.com",
        &[],
        None,
    );
    assert!(!unknown_mx.description.contains("MX records"));
}

#[test]
fn the_lookup_name_carries_the_dmarc_prefix() {
    assert_eq!(dmarc_lookup_name("example.com"), "_dmarc.example.com");
}

#[test]
fn a_failed_txt_lookup_skips_without_the_mx_question() {
    let step = evaluate_dmarc_txt(
        "example.com",
        DnsOutcome::Failed("TXT query timed out".into()),
    );
    let DmarcStep::Done(results) = step else {
        panic!("a failed lookup completes as Skipped");
    };
    assert_eq!(results[0].status, CheckStatus::Skipped);
    assert!(results[0].description.contains("_dmarc.example.com"));
}

#[test]
fn every_answered_posture_reaches_the_mx_gate_after_discovery() {
    for txt in [
        DnsOutcome::NoRecords,
        DnsOutcome::Records(records(&["v=DMARC1; p=none"])),
        DnsOutcome::Records(records(&["some-verification=token"])),
    ] {
        let mut step = evaluate_dmarc_txt("example.com", txt);
        while let DmarcStep::NeedsTxt(pending) = step {
            step = pending.evaluate(DnsOutcome::NoRecords);
        }
        let DmarcStep::NeedsMx(pending) = step else {
            panic!("an answered lookup must wait on the MX gate");
        };
        assert_eq!(pending.domain(), "example.com");
    }
}

#[test]
fn the_pending_step_grades_through_the_mx_answer() {
    let DmarcStep::NeedsMx(pending) = evaluate_dmarc_txt(
        "example.com",
        DnsOutcome::Records(records(&["v=DMARC1; p=reject"])),
    ) else {
        panic!("an answered lookup must wait on the MX gate");
    };
    let results = pending.evaluate(&DnsOutcome::NoRecords);
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert!(results[0].description.contains("p=reject"));
}
