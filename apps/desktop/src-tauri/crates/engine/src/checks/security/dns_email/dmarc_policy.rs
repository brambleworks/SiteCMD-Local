//! Applied DMARC policy and explanatory evidence for RFC 9989 tags.

use super::dmarc::{
    dmarc_tag, evaluate_dmarc, policy_problem, single_dmarc_record, DmarcEvaluation, PolicyProblem,
};
use crate::checks::CheckResult;

pub(super) struct AppliedPolicy {
    pub published: String,
    pub effective: String,
    tag: &'static str,
    test_mode: bool,
    np: Option<String>,
    fallback_problem: Option<PolicyProblem>,
}

impl AppliedPolicy {
    pub fn from_records(records: &[String], inherited: bool) -> Option<Self> {
        let p = match evaluate_dmarc(records) {
            DmarcEvaluation::PolicyNone => "none".to_string(),
            DmarcEvaluation::PolicyEnforced { policy } => policy,
            _ => return None,
        };
        let record = single_dmarc_record(records)?;
        let fallback_problem = policy_problem(record);
        let sp = (inherited && fallback_problem.is_none())
            .then(|| dmarc_tag(record, "sp"))
            .flatten();
        let tag = if sp.is_some() { "sp" } else { "p" };
        let published = sp.unwrap_or(p);
        let test_mode = dmarc_tag(record, "t").as_deref() == Some("y");
        let effective = match (test_mode, published.as_str()) {
            (true, "reject") => "quarantine",
            (true, "quarantine") => "none",
            _ => &published,
        }
        .to_string();
        Some(Self {
            published,
            effective,
            tag,
            test_mode,
            np: dmarc_tag(record, "np"),
            fallback_problem,
        })
    }

    pub fn evaluation(&self) -> DmarcEvaluation {
        if self.effective == "none" {
            DmarcEvaluation::PolicyNone
        } else {
            DmarcEvaluation::PolicyEnforced {
                policy: self.effective.clone(),
            }
        }
    }

    pub fn explain(self, result: &mut CheckResult, domain: &str, lookup_name: &str) {
        let policy_domain = lookup_name.strip_prefix("_dmarc.").unwrap_or(lookup_name);
        if policy_domain != domain || self.test_mode {
            result.description = format!(
                "The DMARC record at {} applies {}={} to {}. The effective policy is {}. A receiver can still apply its own local policy.",
                lookup_name, self.tag, self.published, domain, self.effective
            );
            if self.effective == "none" {
                result.title = "DMARC policy is monitoring only (effective policy: none)".into();
            }
        }
        if let Some(problem) = &self.fallback_problem {
            result.description = format!(
                "The DMARC record at {} cannot supply a usable policy: {}. A valid rua= reporting URI makes receivers treat it as p=none, so the effective policy for {} is none.",
                lookup_name, problem.reason, domain
            );
            result.title = "DMARC policy is monitoring only (effective policy: none)".into();
            if policy_domain == domain {
                result.manual_fix = Some(if problem.tag == "p" {
                    format!("Set a valid p= tag in the TXT record at {} to none, quarantine, or reject. Review aggregate reports before choosing an enforcement policy.", lookup_name)
                } else {
                    format!("Correct or remove the invalid {}= tag in the TXT record at {}. Valid policy values are none, quarantine, and reject. Review aggregate reports before applying the corrected policy.", problem.tag, lookup_name)
                });
            }
        }
        if self.test_mode {
            result.description.push_str(" The record is in test mode (t=y); quarantine acts as none and reject acts as quarantine, while none is unchanged.");
            if policy_domain == domain && self.effective == "none" && self.published != "none" {
                result.manual_fix = Some("Review the aggregate reports to confirm your real senders pass SPF or DKIM alignment, then remove t=y when ready to apply the published policy at full strength.".into());
            }
        }
        if self.fallback_problem.is_none() {
            if let Some(np) = &self.np {
                result.description.push_str(&format!(" The record also publishes np={np} for non-existent subdomains; this scan does not apply that policy because it cannot determine whether a From address's subdomain exists."));
            }
        }
        if let Some(raw) = result.raw_data.as_mut() {
            raw["policy_domain"] = policy_domain.into();
            raw["effective_policy"] = self.effective.into();
            raw["policy_tag"] = self.tag.into();
            raw["test_mode"] = self.test_mode.into();
            if let Some(problem) = self.fallback_problem {
                raw["policy_fallback"] = true.into();
                raw["policy_problem"] = problem.reason.into();
            }
            if let Some(np) = self.np {
                raw["np"] = np.into();
            }
        }
    }
}
