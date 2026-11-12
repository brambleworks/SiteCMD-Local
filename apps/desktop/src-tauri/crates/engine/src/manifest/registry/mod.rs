//! Capability registry used to generate the published manifest.

use super::Entry;

mod accessibility;
mod compliance;
mod config;
mod performance;
mod polish;
mod security;
mod seo;

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;

/// The registry, family by family. Split by check family because that is how
/// the checks themselves are organized and how a reviewer reads them; the
/// published document flattens and sorts by check id.
pub const FAMILIES: &[&[Entry]] = &[
    accessibility::ENTRIES,
    compliance::ENTRIES,
    config::ENTRIES,
    performance::ENTRIES,
    polish::ENTRIES,
    security::ENTRIES,
    seo::ENTRIES,
];

/// Every registered row, in no particular order.
pub fn entries() -> impl Iterator<Item = &'static Entry> {
    FAMILIES.iter().copied().flatten()
}

/// Runner-only ids that emit results under sub-ids. They are declared for
/// completeness but excluded from observation comparability.
pub const RUNNER_IDS: &[(&str, &str)] = &[
    (
        "security.headers",
        "emits security.headers.{csp,hsts,permissions_policy,referrer_policy,x_content_type_options,x_frame_options}",
    ),
    (
        "security.server_info",
        "emits security.server_info.{server_header,x_powered_by}",
    ),
    ("seo.headings", "emits seo.headings.{h1,hierarchy}"),
    (
        "security.ssl",
        "the desktop TLS shell; emits security.ssl.{expiry,hostname,chain,protocol}",
    ),
    (
        "security.exposed_files",
        "the desktop probe shell; emits security.exposed_files.{summary,source_secrets,<path>}",
    ),
];
