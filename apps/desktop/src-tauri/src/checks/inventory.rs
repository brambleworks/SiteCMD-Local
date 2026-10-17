//! Every web check id the desktop registries can emit, in one sorted list.

use super::{accessibility, compliance, config, performance, predeploy, security, seo};

pub fn web_check_ids() -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let sync = security::sync_checks()
        .into_iter()
        .chain(seo::sync_checks())
        .chain(performance::sync_checks())
        .chain(accessibility::sync_checks())
        .chain(compliance::sync_checks())
        .chain(config::sync_checks())
        .chain(predeploy::all_predeploy_checks());
    for check in sync {
        ids.extend(check.emitted_ids());
    }
    let asynchronous = security::async_checks()
        .into_iter()
        .chain(seo::async_checks())
        .chain(performance::async_checks())
        .chain(compliance::async_checks())
        .chain(config::async_checks());
    for check in asynchronous {
        ids.extend(check.emitted_ids());
    }
    // Session-level cross-page checks (the engine's session module) run
    // over a whole scanned site, not a single PageContext/CheckContext, so
    // they have no Check/AsyncCheck object for this union to iterate.
    ids.extend(
        crate::core::session_analysis::SESSION_CHECK_IDS
            .iter()
            .map(|id| id.to_string()),
    );
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
