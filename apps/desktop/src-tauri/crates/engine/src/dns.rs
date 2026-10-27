//! Portable DNS outcomes shared by resolver adapters and check verdicts.
//!
//! `NoRecords` means authoritative absence; transport and resolver errors must
//! remain `Failed` and never become evidence of absence.

use serde::{Deserialize, Serialize};

/// Outcome of one DNS question, as classified by a resolver adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "answer", content = "value", rename_all = "snake_case")]
pub enum DnsOutcome<T> {
    /// The zone answered with at least one record.
    Records(T),
    /// Authoritative absence (NXDOMAIN or empty answer) - a real finding.
    NoRecords,
    /// Timeout or resolver/transport error - NOT evidence of absence.
    Failed(String),
}

impl<T> DnsOutcome<T> {
    /// Project the records, folding an empty projection into `NoRecords` so
    /// "the answer held nothing of the queried type" and "the answer was
    /// empty" classify identically.
    pub fn map_records<U>(self, project: impl FnOnce(T) -> Vec<U>) -> DnsOutcome<Vec<U>> {
        match self {
            DnsOutcome::Records(value) => {
                let records = project(value);
                if records.is_empty() {
                    DnsOutcome::NoRecords
                } else {
                    DnsOutcome::Records(records)
                }
            }
            DnsOutcome::NoRecords => DnsOutcome::NoRecords,
            DnsOutcome::Failed(error) => DnsOutcome::Failed(error),
        }
    }
}

/// One MX record: preference and exchange host. A null MX (RFC 7505) keeps
/// its root exchange as `"."` so verdicts can classify the posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// One CAA property: the tag (lowercased) and its value in the display form
/// the adapter parsed - an issuer domain for issue/issuewild, a URL for
/// iodef, or the raw value for unknown tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaaRecord {
    pub tag: String,
    pub value: String,
}

/// One common DKIM selector and the TXT answer gathered for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimSelectorOutcome {
    pub selector: String,
    pub txt: DnsOutcome<Vec<String>>,
}

/// Address evidence for the target named by the `www` CNAME answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTargetAddresses {
    pub target: String,
    pub addresses: DnsOutcome<Vec<String>>,
}

/// Resolver output for every portable hosted DNS verdict.
///
/// The adapter sends only normalized record projections. Resolver-specific
/// response objects never cross into verdict code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverFacts {
    pub domain: String,
    #[serde(default)]
    pub apex_a: Option<DnsOutcome<Vec<String>>>,
    #[serde(default)]
    pub apex_aaaa: Option<DnsOutcome<Vec<String>>>,
    pub apex_txt: DnsOutcome<Vec<String>>,
    pub apex_mx: DnsOutcome<Vec<MxRecord>>,
    pub dmarc_txt: DnsOutcome<Vec<String>>,
    #[serde(default)]
    pub dkim_txt: Vec<DkimSelectorOutcome>,
    pub dnskey: DnsOutcome<usize>,
    pub caa: DnsOutcome<Vec<CaaRecord>>,
    pub www_cname: DnsOutcome<Vec<String>>,
    #[serde(default)]
    pub www_target_addresses: Option<DnsTargetAddresses>,
    /// The CNAME answer at the page's own host: where a custom domain points
    /// at the platform serving it.
    #[serde(default)]
    pub host_cname: Option<DnsOutcome<Vec<String>>>,
    /// The domain's nameservers, which name whose DNS answers for it.
    #[serde(default)]
    pub ns: Option<DnsOutcome<Vec<String>>>,
}

/// One DKIM TXT question the resolver adapter must answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimSelectorQuestion {
    pub selector: String,
    pub name: String,
}

/// Engine-authored DNS names for the hosted resolver adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverPlan {
    pub domain: String,
    pub apex_address_name: String,
    pub apex_txt_name: String,
    pub apex_mx_name: String,
    pub dmarc_txt_name: String,
    pub dkim_txt_names: Vec<DkimSelectorQuestion>,
    pub dnskey_name: String,
    pub caa_name: String,
    pub www_cname_name: String,
    /// The page's own host, lowercase and without a trailing dot: its CNAME
    /// names the platform serving it.
    pub host_cname_name: String,
    /// The registrable domain, whose NS answer names its DNS provider.
    pub ns_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_projection_folds_into_no_records() {
        let outcome: DnsOutcome<Vec<String>> = DnsOutcome::Records(vec!["unrelated".to_string()])
            .map_records(|_records| Vec::<String>::new());
        assert!(matches!(outcome, DnsOutcome::NoRecords));
    }

    #[test]
    fn records_and_failures_survive_the_projection() {
        let kept = DnsOutcome::Records(vec![1, 2]).map_records(|records| records);
        assert!(matches!(kept, DnsOutcome::Records(ref values) if values == &[1, 2]));
        let failed: DnsOutcome<Vec<i32>> =
            DnsOutcome::<Vec<i32>>::Failed("timed out".into()).map_records(|records| records);
        assert!(matches!(failed, DnsOutcome::Failed(ref detail) if detail == "timed out"));
    }

    #[test]
    fn outcomes_round_trip_through_the_corpus_encoding() {
        let outcome: DnsOutcome<Vec<MxRecord>> = DnsOutcome::Records(vec![MxRecord {
            preference: 10,
            exchange: "mail.example.com".into(),
        }]);
        let json = serde_json::to_value(&outcome).expect("serializes");
        assert_eq!(json["answer"], "records");
        let back: DnsOutcome<Vec<MxRecord>> = serde_json::from_value(json).expect("deserializes");
        assert!(matches!(back, DnsOutcome::Records(ref records)
            if records[0].exchange == "mail.example.com"));
    }
}
