//! System-resolver adapter for the engine's DMARC verdict.

use super::{domain_target, lookup_mx, lookup_txt};
use crate::checks::{AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::security::dns_email::{dmarc, skipped_local_result, DomainTarget};

pub struct DmarcCheck;

#[async_trait::async_trait]
impl AsyncCheck for DmarcCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "security.dns.dmarc"
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn skip_in_predeploy(&self) -> bool {
        true // DNS records are per-domain, not per-build; nothing to verify locally.
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let domain = match domain_target(ctx) {
            DomainTarget::Registrable(domain) => domain,
            DomainTarget::LocalOrIp => {
                return vec![skipped_local_result(dmarc::CHECK_ID, dmarc::TITLE)]
            }
        };

        let txt = lookup_txt(&dmarc::dmarc_lookup_name(&domain)).await;
        let mut step = dmarc::evaluate_dmarc_txt(&domain, txt);
        loop {
            match step {
                dmarc::DmarcStep::Done(results) => return results,
                dmarc::DmarcStep::NeedsTxt(pending) => {
                    let txt = lookup_txt(pending.lookup_name()).await;
                    step = pending.evaluate(txt);
                }
                dmarc::DmarcStep::NeedsMx(pending) => {
                    let mx = lookup_mx(pending.domain()).await;
                    return pending.evaluate(&mx);
                }
            }
        }
    }
}
