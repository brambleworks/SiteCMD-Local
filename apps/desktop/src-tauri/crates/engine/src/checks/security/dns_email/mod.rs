//! Portable DNS, email-authentication, and domain-registration verdicts.
//!
//! Resolver failures produce skipped results because they are not evidence of
//! domain misconfiguration.

pub mod dangling_cname;
pub mod dkim;
pub mod dmarc;
mod dmarc_discovery;
mod dmarc_policy;
pub mod domain_expiry;
pub mod records;
pub mod spf;

use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};
use crate::dns::{DnsOutcome, MxRecord};

/// Where a check should direct its DNS questions, or why it cannot.
pub enum DomainTarget {
    /// The registrable domain (PSL eTLD+1): www.example.com -> example.com,
    /// sub.example.co.uk -> example.co.uk.
    Registrable(String),
    /// IP-literal,.local/.internal, or single-label host: there is no
    /// public DNS zone or registration to inspect.
    LocalOrIp,
}

pub fn registrable_domain_for_url(url: &url::Url) -> DomainTarget {
    let Some(url::Host::Domain(host)) = url.host() else {
        // IP literals (and URLs without a host) have no registrable domain.
        return DomainTarget::LocalOrIp;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.ends_with(".local") || host.ends_with(".internal") || !host.contains('.') {
        return DomainTarget::LocalOrIp;
    }
    // A leading `www.` label is never the registrable name, and under a
    // multi-label public suffix (`gov.uk`, `co.uk`, `com.au`) the PSL alone
    // cannot tell: `psl::domain_str("www.gov.uk")` returns `www.gov.uk`,
    // because that is "suffix plus one label". SPF, DMARC, DNSKEY, and RDAP
    // were then asked about a CNAME instead of the zone that holds the
    // records. Dropping the label first is safe for ordinary hosts, since
    // `example.com` and `www.example.com` share a registrable domain.
    let candidate = host.strip_prefix("www.").unwrap_or(&host);
    match psl::domain_str(candidate) {
        Some(domain) => DomainTarget::Registrable(domain.to_string()),
        // The candidate is itself a public suffix, so nothing is registrable
        // above it. It is still a real delegated zone - the scanned site is
        // served from it - and it is the name that holds the apex records.
        //
        // Accepted trade-off: scanning a hosting suffix itself (`pages.dev`,
        // `s3.amazonaws.com`) or its `www` alias now reads mail and DNSSEC
        // posture from the platform's zone rather than skipping. Those rows are
        // true about the name they consult and each one says which name that
        // is, so the reader can see the zone is the platform's; skipping
        // instead would have to be driven by a hosting-platform list, which is
        // a bigger and staler thing to maintain than a correctly named row.
        // The same applies to the `www.` strip: a genuinely registered `www`
        // label under a suffix is indistinguishable from an alias here, and
        // resolving to the parent zone is the right answer far more often.
        None if candidate.contains('.') => DomainTarget::Registrable(candidate.to_string()),
        None => DomainTarget::LocalOrIp,
    }
}

/// Skipped result for hosts with no public DNS zone (mirrors the localhost
/// skip pattern in checks/security/headers.rs).
pub fn skipped_local_result(check_id: &str, title: &str) -> CheckResult {
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
        title: title.into(),
        description: "Skipped on local, IP-literal, or internal hosts. DNS and domain-registration records exist only for public registrable domains, so run this check against the deployed site.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"reason": "local_or_ip_host"})),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// Skipped result for resolver/transport problems. A lookup failure is not
/// evidence about the domain, so it must never surface as a Fail.
pub fn skipped_dns_failure(check_id: &str, title: &str, domain: &str, detail: &str) -> CheckResult {
    let detail = crate::log_sanitizer::bounded_issue_evidence(detail);
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
        title: title.into(),
        description: format!(
            "DNS lookup failed for {}: {}. The resolver may be offline or the network may be blocking the query, so this check reports no finding rather than guessing.",
            domain, detail
        ),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(
            serde_json::json!({"reason": "dns_lookup_failed", "domain": domain, "detail": detail}),
        ),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// Severity for a missing email-authentication record: domains that receive
/// mail (MX present) get Medium, others Low. An unknown MX state (lookup
/// failure) also gets the gentler Low.
pub fn missing_record_severity(has_mx: Option<bool>) -> Severity {
    if has_mx == Some(true) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Some(true) if the MX answer holds at least one real (non-null) exchange.
/// None when DNS could not answer, so callers fall back to gentler severity.
pub fn has_mx_from(outcome: &DnsOutcome<Vec<MxRecord>>) -> Option<bool> {
    match outcome {
        DnsOutcome::Records(records) => Some(records.iter().any(|record| record.exchange != ".")),
        DnsOutcome::NoRecords => Some(false),
        DnsOutcome::Failed(_) => None,
    }
}

/// Apex SPF posture at the resolution needed by the DKIM gate.
pub enum SpfPosture {
    /// At least one v=spf1 record that authorizes senders.
    Present,
    /// The only SPF content is the null record `v=spf1 -all`.
    NullRecord,
    /// No v=spf1 record.
    Absent,
}

/// True for the RFC 7208 null record: `v=spf1 -all` with no other terms.
fn spf_is_null_record(record: &str) -> bool {
    let mut terms = record.split_whitespace();
    let is_version = terms
        .next()
        .is_some_and(|first| first.eq_ignore_ascii_case("v=spf1"));
    let rest: Vec<&str> = terms.collect();
    is_version && rest.len() == 1 && rest[0].eq_ignore_ascii_case("-all")
}

pub fn classify_spf_posture(records: &[String]) -> SpfPosture {
    let spf_records: Vec<&String> = records
        .iter()
        .filter(|record| spf::is_spf_record(record))
        .collect();
    if spf_records.is_empty() {
        SpfPosture::Absent
    } else if spf_records.iter().all(|record| spf_is_null_record(record)) {
        SpfPosture::NullRecord
    } else {
        SpfPosture::Present
    }
}

/// The apex SPF posture from a TXT answer, or None when DNS could not answer.
pub fn spf_posture_from(outcome: &DnsOutcome<Vec<String>>) -> Option<SpfPosture> {
    match outcome {
        DnsOutcome::Records(records) => Some(classify_spf_posture(records)),
        DnsOutcome::NoRecords => Some(SpfPosture::Absent),
        DnsOutcome::Failed(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_spf_posture, has_mx_from, missing_record_severity, registrable_domain_for_url,
        DnsOutcome, DomainTarget, MxRecord, Severity, SpfPosture,
    };

    fn target_for(url: &str) -> DomainTarget {
        registrable_domain_for_url(&url::Url::parse(url).expect("url"))
    }

    #[test]
    fn registrable_domain_strips_subdomains() {
        match target_for("https://www.example.com/page") {
            DomainTarget::Registrable(domain) => assert_eq!(domain, "example.com"),
            DomainTarget::LocalOrIp => panic!("www.example.com should be registrable"),
        }
    }

    #[test]
    fn registrable_domain_honors_multi_label_public_suffixes() {
        match target_for("https://sub.example.co.uk/") {
            DomainTarget::Registrable(domain) => assert_eq!(domain, "example.co.uk"),
            DomainTarget::LocalOrIp => panic!("example.co.uk should be registrable"),
        }
    }

    #[test]
    fn a_www_host_under_a_multi_label_suffix_resolves_to_the_zone_that_holds_the_records() {
        // `psl::domain_str("www.gov.uk")` answers `www.gov.uk`, because
        // `gov.uk` is a public suffix. Asking SPF, DMARC, DNSKEY, and RDAP
        // about that name asks about a CNAME, not the zone.
        match target_for("https://www.gov.uk/") {
            DomainTarget::Registrable(domain) => assert_eq!(domain, "gov.uk"),
            DomainTarget::LocalOrIp => panic!("www.gov.uk must resolve to the gov.uk zone"),
        }
        match target_for("https://www.nhs.uk/") {
            DomainTarget::Registrable(domain) => assert_eq!(domain, "nhs.uk"),
            DomainTarget::LocalOrIp => panic!("nhs.uk is an ordinary registrable domain"),
        }
    }

    #[test]
    fn a_public_suffix_served_as_a_site_is_its_own_zone() {
        match target_for("https://gov.uk/") {
            DomainTarget::Registrable(domain) => assert_eq!(domain, "gov.uk"),
            DomainTarget::LocalOrIp => panic!("gov.uk is a delegated zone with apex records"),
        }
    }

    #[test]
    fn a_site_served_from_a_hosting_suffix_reports_the_platform_zone_it_consults() {
        // Pinning the accepted trade-off documented on the fallback arm.
        // Scanning a hosting suffix itself (or its `www` alias) has no zone of
        // its own above it, so the DNS checks now read the platform's zone
        // where they used to skip. Every such row names the domain it
        // consulted, which is how the reader can tell whose zone it is.
        for (url, zone) in [
            ("https://pages.dev/", "pages.dev"),
            ("https://www.pages.dev/", "pages.dev"),
            ("https://s3.amazonaws.com/", "s3.amazonaws.com"),
        ] {
            match target_for(url) {
                DomainTarget::Registrable(domain) => assert_eq!(domain, zone, "{url}"),
                DomainTarget::LocalOrIp => panic!("{url} resolves to a real zone"),
            }
        }

        // The ordinary case is untouched: a deployment one label below the
        // suffix keeps its own registrable name and is graded on that.
        for (url, expected) in [
            ("https://preview.pages.dev/", "preview.pages.dev"),
            ("https://my-app.vercel.app/", "my-app.vercel.app"),
            (
                "https://bucket.s3.amazonaws.com/",
                "bucket.s3.amazonaws.com",
            ),
        ] {
            match target_for(url) {
                DomainTarget::Registrable(domain) => assert_eq!(domain, expected, "{url}"),
                DomainTarget::LocalOrIp => panic!("{url} has a registrable name"),
            }
        }
    }

    #[test]
    fn stripping_www_does_not_change_an_ordinary_host() {
        for url in [
            "https://www.example.co.uk/",
            "https://example.co.uk/",
            "https://deep.www.example.com/",
        ] {
            match target_for(url) {
                DomainTarget::Registrable(domain) => assert!(
                    domain == "example.co.uk" || domain == "example.com",
                    "{url} resolved to {domain}"
                ),
                DomainTarget::LocalOrIp => panic!("{url} should be registrable"),
            }
        }
    }

    #[test]
    fn ip_literal_hosts_have_no_registrable_domain() {
        assert!(matches!(
            target_for("http://192.168.1.10:3000/"),
            DomainTarget::LocalOrIp
        ));
        assert!(matches!(
            target_for("http://[::1]:8080/"),
            DomainTarget::LocalOrIp
        ));
    }

    #[test]
    fn local_and_internal_suffixes_are_skipped() {
        assert!(matches!(
            target_for("http://myserver.local/"),
            DomainTarget::LocalOrIp
        ));
        assert!(matches!(
            target_for("http://api.corp.internal/"),
            DomainTarget::LocalOrIp
        ));
        assert!(matches!(
            target_for("http://intranethost/"),
            DomainTarget::LocalOrIp
        ));
    }

    #[test]
    fn missing_record_severity_gates_on_mx() {
        assert_eq!(missing_record_severity(Some(true)), Severity::Medium);
        assert_eq!(missing_record_severity(Some(false)), Severity::Low);
        assert_eq!(missing_record_severity(None), Severity::Low);
    }

    fn mx_answer(exchanges: &[&str]) -> DnsOutcome<Vec<MxRecord>> {
        DnsOutcome::Records(
            exchanges
                .iter()
                .map(|exchange| MxRecord {
                    preference: 10,
                    exchange: exchange.to_string(),
                })
                .collect(),
        )
    }

    #[test]
    fn has_mx_requires_a_real_exchange() {
        assert_eq!(has_mx_from(&mx_answer(&["mail.example.com"])), Some(true));
        assert_eq!(has_mx_from(&mx_answer(&["."])), Some(false));
        assert_eq!(has_mx_from(&DnsOutcome::NoRecords), Some(false));
        assert_eq!(has_mx_from(&DnsOutcome::Failed("timed out".into())), None);
    }

    fn records(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn spf_posture_recognizes_the_null_record() {
        assert!(matches!(
            classify_spf_posture(&records(&["v=spf1 -all"])),
            SpfPosture::NullRecord
        ));
        assert!(matches!(
            classify_spf_posture(&records(&["V=SPF1 -ALL"])),
            SpfPosture::NullRecord
        ));
        // Unrelated TXT records alongside the null record don't change it.
        assert!(matches!(
            classify_spf_posture(&records(&["google-site-verification=abc", "v=spf1 -all"])),
            SpfPosture::NullRecord
        ));
    }

    #[test]
    fn spf_posture_with_sender_mechanisms_is_present() {
        assert!(matches!(
            classify_spf_posture(&records(&["v=spf1 include:_spf.google.com -all"])),
            SpfPosture::Present
        ));
        // Softfail-all is not the null record: it hedges instead of
        // declaring a no-mail posture.
        assert!(matches!(
            classify_spf_posture(&records(&["v=spf1 ~all"])),
            SpfPosture::Present
        ));
    }

    #[test]
    fn spf_posture_without_spf_records_is_absent() {
        assert!(matches!(
            classify_spf_posture(&records(&["google-site-verification=abc"])),
            SpfPosture::Absent
        ));
        assert!(matches!(classify_spf_posture(&[]), SpfPosture::Absent));
    }
}
