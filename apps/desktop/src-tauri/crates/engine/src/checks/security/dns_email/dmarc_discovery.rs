//! RFC 9989 discovery, with one resolver question exposed per step.

use super::dmarc::{
    dmarc_lookup_name, dmarc_result, dmarc_tag, single_dmarc_record, CHECK_ID, TITLE,
};
use super::{has_mx_from, skipped_dns_failure};
use crate::checks::CheckResult;
use crate::dns::{DnsOutcome, MxRecord};

/// Maximum TXT questions, including the Author Domain, in RFC 9989 section 4.10.
pub const MAX_DMARC_TXT_QUESTIONS: usize = 8;

/// Parent TXT questions in RFC 9989 order, excluding the initial Author Domain.
pub fn dmarc_tree_walk_names(domain: &str) -> Vec<String> {
    let labels: Vec<_> = domain.split('.').collect();
    let first = if labels.len() > MAX_DMARC_TXT_QUESTIONS {
        labels.len() - (MAX_DMARC_TXT_QUESTIONS - 1)
    } else {
        1
    };
    (first..labels.len())
        .map(|start| dmarc_lookup_name(&labels[start..].join(".")))
        .collect()
}

/// The next DNS question needed to grade DMARC.
pub enum DmarcStep {
    Done(Vec<CheckResult>),
    NeedsTxt(DmarcTreeWalk),
    NeedsMx(PendingDmarc),
}

/// The discovered policy, waiting on the Author Domain's MX severity gate.
pub struct PendingDmarc {
    domain: String,
    policy_domain: String,
    organizational_domain: Option<String>,
    records: Vec<String>,
}

impl PendingDmarc {
    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn evaluate(self, mx: &DnsOutcome<Vec<MxRecord>>) -> Vec<CheckResult> {
        let mut result = dmarc_result(
            CHECK_ID,
            &self.domain,
            &dmarc_lookup_name(&self.policy_domain),
            &self.records,
            has_mx_from(mx),
        );
        if let Some(organization) = self.organizational_domain {
            if let Some(raw) = result.raw_data.as_mut() {
                raw["organizational_domain"] = organization.into();
            }
        }
        vec![result]
    }
}

/// A tree walk suspended until the runtime answers exactly one TXT question.
pub struct DmarcTreeWalk {
    pending: PendingDmarc,
    names: std::vec::IntoIter<String>,
    lookup_name: String,
    candidates: Vec<(String, Vec<String>)>,
}

impl DmarcTreeWalk {
    pub fn lookup_name(&self) -> &str {
        &self.lookup_name
    }

    pub fn evaluate(mut self, txt: DnsOutcome<Vec<String>>) -> DmarcStep {
        let records = match txt_records(&self.lookup_name, txt) {
            Ok(records) => records,
            Err(results) => return DmarcStep::Done(results),
        };
        let domain = self
            .lookup_name
            .strip_prefix("_dmarc.")
            .expect("DMARC lookup name")
            .to_string();
        let boundary = if let Some(record) = single_dmarc_record(&records) {
            let psd = dmarc_tag(record, "psd");
            self.candidates.push((domain, records));
            matches!(psd.as_deref(), Some("n" | "y"))
        } else {
            false
        };
        if !boundary {
            if let Some(name) = self.names.next() {
                self.lookup_name = name;
                return DmarcStep::NeedsTxt(self);
            }
        }
        self.finish()
    }

    fn finish(mut self) -> DmarcStep {
        if let Some((domain, records)) = self.candidates.last() {
            let record = single_dmarc_record(records).expect("discovered record");
            let organization = if dmarc_tag(record, "psd").as_deref() == Some("y") {
                let suffix = self
                    .pending
                    .domain
                    .strip_suffix(domain)
                    .expect("ancestor domain");
                let label = suffix
                    .trim_end_matches('.')
                    .rsplit('.')
                    .next()
                    .expect("child label");
                format!("{label}.{domain}")
            } else {
                domain.clone()
            };
            // Prefer the organization's own policy; otherwise use the PSD policy.
            let selected = self
                .candidates
                .iter()
                .find(|(name, _)| name == &organization)
                .unwrap_or_else(|| self.candidates.last().expect("candidate"));
            self.pending.policy_domain = selected.0.clone();
            self.pending.records = selected.1.clone();
            self.pending.organizational_domain = Some(organization);
        }
        DmarcStep::NeedsMx(self.pending)
    }
}

fn txt_records(name: &str, txt: DnsOutcome<Vec<String>>) -> Result<Vec<String>, Vec<CheckResult>> {
    match txt {
        DnsOutcome::Failed(detail) => {
            Err(vec![skipped_dns_failure(CHECK_ID, TITLE, name, &detail)])
        }
        DnsOutcome::NoRecords => Ok(Vec::new()),
        DnsOutcome::Records(records) => Ok(records),
    }
}

/// Begin with the Author Domain's TXT answer; absent or duplicate records need a walk.
pub fn evaluate_dmarc_txt(domain: &str, txt: DnsOutcome<Vec<String>>) -> DmarcStep {
    let records = match txt_records(&dmarc_lookup_name(domain), txt) {
        Ok(records) => records,
        Err(results) => return DmarcStep::Done(results),
    };
    let present = single_dmarc_record(&records).is_some();
    let pending = PendingDmarc {
        domain: domain.into(),
        policy_domain: domain.into(),
        organizational_domain: None,
        records,
    };
    if present {
        return DmarcStep::NeedsMx(pending);
    }
    let mut names = dmarc_tree_walk_names(domain).into_iter();
    match names.next() {
        Some(lookup_name) => DmarcStep::NeedsTxt(DmarcTreeWalk {
            pending,
            names,
            lookup_name,
            candidates: Vec::new(),
        }),
        None => DmarcStep::NeedsMx(pending),
    }
}
