//! Validate identities and conservatively remove unencodable coverage.

use std::collections::{BTreeMap, BTreeSet};

use sitecmd_protocol::coverage::{CoverageExceptionReason, ScanCoverageKind};
use sitecmd_protocol::sync::{wire::CheckId, WireCoverage, WireCoverageException};

use super::RunMaterial;
use crate::db::OccurrenceIdentity;

pub(super) fn wire_or_note<T: std::str::FromStr<Err = String>>(
    label: &str,
    value: &str,
) -> Option<T> {
    match value.parse() {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("Connected evidence omitted {label} {value:?}: {error}");
            None
        }
    }
}

pub(super) fn incomplete_coverage(coverage: &mut WireCoverage) {
    coverage.complete = false;
    coverage.exceptions.push(WireCoverageException {
        route: None,
        checks_not_run: coverage.checks.clone(),
        reason: CoverageExceptionReason::SessionIncomplete,
    });
}

pub(super) fn encodable_identity(identity: &OccurrenceIdentity) -> bool {
    wire_or_note::<CheckId>("check id", &identity.check_id).is_some()
}

pub(super) fn canonical_coverage(runs: &[&RunMaterial]) -> WireCoverage {
    let complete = runs.iter().all(|run| run.coverage.successful);
    let mut omitted = false;
    let mut checks = BTreeSet::new();
    let mut global_exceptions: BTreeMap<CoverageExceptionReason, BTreeSet<CheckId>> =
        BTreeMap::new();
    for run in runs {
        omitted |= !run.coverage.page_urls.is_empty();
        for check in &run.coverage.checks {
            if let Some(check) = wire_or_note("coverage check id", check) {
                checks.insert(check);
            } else {
                omitted = true;
            }
        }
        for exception in &run.coverage.exceptions {
            if exception.route.is_some() {
                omitted = true;
                continue;
            }
            let global_checks = global_exceptions.entry(exception.reason).or_default();
            for check in &exception.checks_not_run {
                if let Some(check) = wire_or_note("exception check id", check) {
                    global_checks.insert(check);
                } else {
                    omitted = true;
                }
            }
        }
    }
    let mut coverage = WireCoverage {
        kind: ScanCoverageKind::Project,
        complete,
        routes: Vec::new(),
        checks: checks.into_iter().collect(),
        exceptions: global_exceptions
            .into_iter()
            .map(|(reason, checks)| WireCoverageException {
                route: None,
                checks_not_run: checks.into_iter().collect(),
                reason,
            })
            .collect(),
    };
    if omitted {
        incomplete_coverage(&mut coverage);
    }
    coverage
}

#[cfg(test)]
mod tests {
    use super::*;
    use sitecmd_protocol::coverage::{CoverageException, ScanCoverageManifest};
    use sitecmd_protocol::release::{ExecutionProfile, ReleaseStamp};

    const CHECK: &str = "code_scan.n-plus-one-query";

    fn assert_incomplete_coverage(coverage: ScanCoverageManifest) {
        let run = RunMaterial {
            execution_id: 1,
            observed_at: 100,
            based_on_event_sequence: 0,
            coverage,
            diagnostics: Default::default(),
            stamp: ReleaseStamp {
                engine_release: "2.0.0".into(),
                manifest_digest: "a".repeat(16),
                canonicalizer: 1,
                crawl_profile: 1,
                execution: ExecutionProfile::default(),
            },
        };
        let wire = canonical_coverage(&[&run]);
        assert!(!wire.complete, "{wire:?}");
        assert!(wire.routes.is_empty());
        assert_eq!(wire.checks, [CHECK.parse::<CheckId>().unwrap()]);
        assert_eq!(
            wire.exceptions,
            [WireCoverageException {
                route: None,
                checks_not_run: wire.checks.clone(),
                reason: CoverageExceptionReason::SessionIncomplete,
            }]
        );
    }

    #[test]
    fn project_coverage_with_leftover_page_urls_is_incomplete() {
        // Dropping leftover page URLs can turn partial evidence into a complete claim.
        let coverage = ScanCoverageManifest::declared(
            ScanCoverageKind::Project,
            vec!["https://example.com/page".into()],
            vec![CHECK.into()],
        );
        assert_incomplete_coverage(coverage);
    }

    #[test]
    fn project_coverage_with_a_route_exception_is_incomplete() {
        // Dropping a route exception can let a scan clear a check it did not run.
        let mut coverage =
            ScanCoverageManifest::declared(ScanCoverageKind::Project, vec![], vec![CHECK.into()]);
        coverage.exceptions.push(CoverageException {
            route: Some("https://example.com/page".into()),
            checks_not_run: vec![CHECK.into()],
            reason: CoverageExceptionReason::CheckSkipped,
        });
        assert_incomplete_coverage(coverage);
    }
}
