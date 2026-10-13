//! The resolver-backed DNS verdicts' grading, over the facts a runtime's resolver adapter gathered.

use super::probes::ProbeContext;
use crate::checks::security::dns_email::{
    dangling_cname, dkim, dmarc, records, registrable_domain_for_url, skipped_dns_failure,
    skipped_local_result, spf, DomainTarget,
};
use crate::vocab::CheckResult;

pub(super) fn resolver_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    let Some(facts) = ctx.resolver_facts else {
        return Vec::new();
    };
    let domain = match registrable_domain_for_url(&ctx.page.url) {
        DomainTarget::LocalOrIp => return local_dns_results(),
        DomainTarget::Registrable(domain) => domain,
    };
    if facts.domain != domain {
        return failed_dns_results(
            &domain,
            "the resolver facts belonged to a different registrable domain",
        );
    }

    let mut results = records::evaluate_caa(&domain, facts.caa.clone());

    results.extend(
        match dangling_cname::evaluate_www_cname(&domain, facts.www_cname.clone()) {
            dangling_cname::WwwAliasStep::Done(results) => results,
            dangling_cname::WwwAliasStep::LookupTarget(probe) => {
                let addresses = facts
                    .www_target_addresses
                    .as_ref()
                    .filter(|answer| answer.target.eq_ignore_ascii_case(probe.target()))
                    .map(|answer| answer.addresses.clone())
                    .unwrap_or_else(|| {
                        crate::dns::DnsOutcome::Failed(
                            "the CNAME target address fact was not gathered".into(),
                        )
                    });
                probe.evaluate(addresses)
            }
        },
    );

    results.extend(
        match dkim::evaluate_dkim_gate(&domain, &facts.apex_mx, &facts.apex_txt) {
            dkim::DkimStep::Done(results) => results,
            dkim::DkimStep::Sweep(sweep) => {
                let outcomes = sweep
                    .probe_names()
                    .into_iter()
                    .map(|(selector, _)| {
                        let txt = facts
                            .dkim_txt
                            .iter()
                            .find(|answer| answer.selector.eq_ignore_ascii_case(selector))
                            .map(|answer| answer.txt.clone())
                            .unwrap_or_else(|| {
                                crate::dns::DnsOutcome::Failed(
                                    "the selector TXT fact was not gathered".into(),
                                )
                            });
                        (selector.to_string(), txt)
                    })
                    .collect::<Vec<_>>();
                sweep.evaluate(&outcomes)
            }
        },
    );

    results.extend(
        match dmarc::evaluate_dmarc_txt(&domain, facts.dmarc_txt.clone()) {
            dmarc::DmarcStep::Done(results) => results,
            dmarc::DmarcStep::NeedsMx(pending) => pending.evaluate(&facts.apex_mx),
        },
    );
    results.extend(records::evaluate_dnssec(&domain, facts.dnskey.clone()));
    results.extend(records::evaluate_mx(&domain, facts.apex_mx.clone()));
    results.extend(
        match spf::evaluate_spf_txt(&domain, facts.apex_txt.clone()) {
            spf::SpfStep::Done(results) => results,
            spf::SpfStep::NeedsMx(pending) => pending.evaluate(&facts.apex_mx),
        },
    );
    results
}

fn local_dns_results() -> Vec<CheckResult> {
    [
        (records::CAA_CHECK_ID, records::CAA_TITLE),
        (dangling_cname::CHECK_ID, dangling_cname::TITLE),
        (dkim::CHECK_ID, dkim::TITLE),
        (dmarc::CHECK_ID, dmarc::TITLE),
        (records::DNSSEC_CHECK_ID, records::DNSSEC_TITLE),
        (records::MX_CHECK_ID, records::MX_TITLE),
        (spf::CHECK_ID, spf::TITLE),
    ]
    .into_iter()
    .map(|(id, title)| skipped_local_result(id, title))
    .collect()
}

fn failed_dns_results(domain: &str, detail: &str) -> Vec<CheckResult> {
    [
        (records::CAA_CHECK_ID, records::CAA_TITLE),
        (dangling_cname::CHECK_ID, dangling_cname::TITLE),
        (dkim::CHECK_ID, dkim::TITLE),
        (dmarc::CHECK_ID, dmarc::TITLE),
        (records::DNSSEC_CHECK_ID, records::DNSSEC_TITLE),
        (records::MX_CHECK_ID, records::MX_TITLE),
        (spf::CHECK_ID, spf::TITLE),
    ]
    .into_iter()
    .map(|(id, title)| skipped_dns_failure(id, title, domain, detail))
    .collect()
}
