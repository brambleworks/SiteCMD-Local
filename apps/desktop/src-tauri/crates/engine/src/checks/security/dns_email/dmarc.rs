//! DMARC policy grading against RFC 9989. Graded postures are MX-gated, while
//! failed TXT lookups remain skipped.

pub use super::dmarc_discovery::{
    dmarc_tree_walk_names, evaluate_dmarc_txt, DmarcStep, DmarcTreeWalk, PendingDmarc,
    MAX_DMARC_TXT_QUESTIONS,
};
use super::dmarc_policy::AppliedPolicy;
use super::missing_record_severity;
use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

pub const CHECK_ID: &str = "security.dns.dmarc";
pub const TITLE: &str = "DMARC record";

/// The name whose TXT records carry the domain's DMARC policy.
pub fn dmarc_lookup_name(domain: &str) -> String {
    format!("_dmarc.{}", domain)
}

/// True when the TXT record is a DMARC record (first tag is v=DMARC1).
pub fn is_dmarc_record(record: &str) -> bool {
    record
        .split(';')
        .next()
        .and_then(|first| first.split_once('='))
        .is_some_and(|(tag, value)| {
            tag.trim().eq_ignore_ascii_case("v") && value.trim() == "DMARC1"
        })
}

/// Discovery retains exactly one version-matching record regardless of policy validity.
pub(super) fn single_dmarc_record(records: &[String]) -> Option<&str> {
    let mut matching = records.iter().filter(|record| is_dmarc_record(record));
    let first = matching.next()?;
    matching.next().is_none().then_some(first.as_str())
}

/// Extract a DMARC tag value (lowercased) from a record, e.g. tag "p" from
/// "v=DMARC1; p=quarantine; rua=mailto:reports@example.com".
pub fn dmarc_tag(record: &str, key: &str) -> Option<String> {
    record
        .split(';')
        .filter_map(|part| part.split_once('='))
        .find_map(|(tag, value)| {
            if tag.trim().eq_ignore_ascii_case(key) {
                Some(value.trim().to_ascii_lowercase())
            } else {
                None
            }
        })
}

pub enum DmarcEvaluation {
    /// Monitoring only: receivers report but deliver failing mail normally.
    PolicyNone,
    /// p=quarantine or p=reject: receivers act on failing mail.
    PolicyEnforced { policy: String },
    /// Duplicate records or an unusable policy without a reporting fallback.
    Malformed { reason: String },
    /// Only unrelated TXT records (e.g. a stray verification token) live at
    /// the _dmarc name. Receivers ignore them, so the domain effectively
    /// has no DMARC record - it must not be called "malformed DMARC"
    ///.
    NoDmarcRecord,
}

/// Evaluate the TXT records found at the _dmarc name. The caller handles the
/// no-records case (missing) separately.
pub fn evaluate_dmarc(records: &[String]) -> DmarcEvaluation {
    let dmarc_records: Vec<&String> = records.iter().filter(|r| is_dmarc_record(r)).collect();

    if dmarc_records.is_empty() {
        return DmarcEvaluation::NoDmarcRecord;
    }
    if dmarc_records.len() > 1 {
        return DmarcEvaluation::Malformed {
            reason: "more than one v=DMARC1 record is published; receivers treat duplicates as if no record existed".into(),
        };
    }

    if let Some(problem) = policy_problem(dmarc_records[0]) {
        return if has_valid_reporting_uri(dmarc_records[0]) {
            DmarcEvaluation::PolicyNone
        } else {
            DmarcEvaluation::Malformed {
                reason: format!(
                    "{} and no valid rua= reporting URI, so receivers apply no DMARC processing",
                    problem.reason
                ),
            }
        };
    }
    match dmarc_tag(dmarc_records[0], "p").as_deref() {
        Some("none") => DmarcEvaluation::PolicyNone,
        Some(policy) => DmarcEvaluation::PolicyEnforced {
            policy: policy.to_string(),
        },
        None => unreachable!("policy_problem handles a missing p tag"),
    }
}

pub(super) struct PolicyProblem {
    pub tag: &'static str,
    pub reason: String,
}

pub(super) fn policy_problem(record: &str) -> Option<PolicyProblem> {
    for tag in ["p", "sp", "np"] {
        let reason = match dmarc_tag(record, tag).as_deref() {
            None if tag == "p" => Some("no valid p= policy tag".into()),
            Some(value) if !matches!(value, "none" | "quarantine" | "reject") => {
                Some(format!("unknown policy value {tag}={value}"))
            }
            _ => None,
        };
        if let Some(reason) = reason {
            return Some(PolicyProblem { tag, reason });
        }
    }
    None
}

fn has_valid_reporting_uri(record: &str) -> bool {
    let Some(rua) = dmarc_tag(record, "rua") else {
        return false;
    };
    rua.split(',').map(str::trim).any(|value| {
        // URL parsing normalizes some invalid URI characters, so check them first.
        let ascii_uri = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+;=%".contains(&byte));
        let escapes = value.split('%').skip(1).all(|suffix| {
            suffix
                .as_bytes()
                .get(..2)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        });
        ascii_uri
            && escapes
            && url::Url::parse(value)
                .is_ok_and(|uri| uri.host_str().is_some() || !uri.path().is_empty())
    })
}

fn publish_own_record_advice(domain: &str) -> String {
    format!(
        "Publish a TXT record at {} starting in monitoring mode: `v=DMARC1; p=none; rua=mailto:dmarc-reports@{}`. Review the aggregate reports to confirm your real senders pass, then graduate the policy to p=quarantine and finally p=reject.",
        dmarc_lookup_name(domain), domain
    )
}

/// Build the missing-DMARC result, preserving any unrelated TXT evidence.
fn no_dmarc_result(
    check_id: &str,
    domain: &str,
    dmarc_name: &str,
    unrelated_records: &[String],
    has_mx: Option<bool>,
) -> CheckResult {
    let mx_note = match has_mx {
        Some(true) => {
            " This domain publishes MX records, which confirms that it receives mail; this scan does not establish whether it also sends mail."
        }
        Some(false) => {
            " This domain publishes no MX records, so it shows no inbound mail setup; a domain that sends no mail can publish `v=DMARC1; p=reject` directly so receivers reject anyone using it as a visible From domain."
        }
        None => "",
    };
    let lead = if unrelated_records.is_empty() {
        format!("No TXT record at {}.", dmarc_name)
    } else {
        format!(
            "The TXT record{} at {} {} unrelated to DMARC (none starts with v=DMARC1), so receivers treat this domain as having no DMARC record.",
            if unrelated_records.len() == 1 { "" } else { "s" },
            dmarc_name,
            if unrelated_records.len() == 1 { "is" } else { "are" },
        )
    };
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
        title: "No DMARC record".into(),
        description: format!(
            "{} Without DMARC, the domain publishes no alignment-based request for receivers to quarantine or reject messages that use its visible From domain. Receivers can still apply their own filtering and authentication policy.{}",
            lead, mx_note
        ),
        status: CheckStatus::Warn,
        severity: missing_record_severity(has_mx),
        fix_prompt: None,
        manual_fix: Some(publish_own_record_advice(domain)),
        raw_data: Some(serde_json::json!({
            "domain": domain,
            "lookup_name": dmarc_name,
            "records": unrelated_records,
            "has_mx": has_mx,
        })),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: Some("DMARC connects SPF or DKIM alignment to the visible From domain and publishes the domain owner's requested disposition. Without it, receivers have no domain-published DMARC disposition to apply, although their own filtering still governs delivery.".into()),
    }
}

/// Grade DMARC TXT records with MX-aware severity.
pub fn dmarc_result(
    check_id: &str,
    domain: &str,
    dmarc_name: &str,
    records: &[String],
    has_mx: Option<bool>,
) -> CheckResult {
    if records.is_empty() {
        return no_dmarc_result(check_id, domain, dmarc_name, records, has_mx);
    }

    let raw_data = serde_json::json!({
        "domain": domain,
        "lookup_name": dmarc_name,
        "records": records,
        "has_mx": has_mx,
    });

    let applied = AppliedPolicy::from_records(records, dmarc_name != dmarc_lookup_name(domain));
    let evaluation = applied
        .as_ref()
        .map(AppliedPolicy::evaluation)
        .unwrap_or_else(|| evaluate_dmarc(records));
    let mut result = match evaluation {
        DmarcEvaluation::NoDmarcRecord => {
            no_dmarc_result(check_id, domain, dmarc_name, records, has_mx)
        }
        DmarcEvaluation::PolicyNone => CheckResult {
            check_id: check_id.into(),
            category: ScanCategory::Security,
            title: "DMARC policy is monitoring only (p=none)".into(),
            description: format!(
                "The DMARC record at {} sets p=none. The requested DMARC disposition is monitoring only: the domain requests no quarantine or reject treatment for messages that fail DMARC alignment, while receivers can still apply their own local filtering. Monitoring is a valid rollout or diagnostic posture. If the domain's objective is active anti-spoofing enforcement, review alignment data before moving deliberately toward quarantine or reject.",
                dmarc_name
            ),
            status: CheckStatus::Warn,
            severity: missing_record_severity(has_mx),
            fix_prompt: None,
            manual_fix: Some("Review the aggregate reports (the rua= address) for a few weeks to confirm your real senders pass SPF or DKIM alignment. Then tighten in steps: move to `p=quarantine`, and finally `p=reject` once quarantine shows no legitimate mail failing.".into()),
            raw_data: Some(raw_data),
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: Some("A monitoring-only policy provides visibility but requests no DMARC quarantine or reject treatment for alignment failures, so it should be evaluated against the domain's intended enforcement posture.".into()),
        },
        DmarcEvaluation::PolicyEnforced { policy } => CheckResult {
            check_id: check_id.into(),
            category: ScanCategory::Security,
            title: TITLE.into(),
            description: format!(
                "The DMARC record at {} publishes p={}, requesting receivers to {} messages that fail DMARC alignment. A receiver can still apply its own local policy.",
                dmarc_name,
                policy,
                if policy == "reject" { "reject" } else { "quarantine" }
            ),
            status: CheckStatus::Pass,
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: Some(raw_data),
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        },
        DmarcEvaluation::Malformed { reason } => CheckResult {
            check_id: check_id.into(),
            category: ScanCategory::Security,
            title: "DMARC policy is not applied".into(),
            description: format!(
                "The DMARC record at {} is not usable: {}.",
                dmarc_name, reason
            ),
            // MX-gated like the missing branch: on a domain that receives
            // no mail, a broken record must not outscore having no record.
            status: if has_mx == Some(true) {
                CheckStatus::Fail
            } else {
                CheckStatus::Warn
            },
            severity: missing_record_severity(has_mx),
            fix_prompt: None,
            manual_fix: Some(format!(
                "Publish exactly one TXT record at {} that starts with v=DMARC1 and includes a policy tag, for example `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}`.",
                dmarc_name, domain
            )),
            raw_data: Some(raw_data),
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: Some("Receivers do not apply a DMARC policy when the record has no usable policy or reporting fallback, or when multiple DMARC records are published.".into()),
        },
    };
    if let Some(applied) = applied {
        applied.explain(&mut result, domain, dmarc_name);
    }
    if result.manual_fix.is_some() && dmarc_name != dmarc_lookup_name(domain) {
        result.manual_fix = Some(publish_own_record_advice(domain));
    }
    result
}

#[cfg(test)]
#[path = "dmarc_tests.rs"]
mod tests;
