//! Pair-precise coverage for route and check verdicts.
//!
//! Skipped checks and incomplete set-level analysis become explicit exceptions.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanCoverageKind {
    Site,
    PageSet,
    Page,
    Project,
    CheckSet,
    RuleSet,
}

impl ScanCoverageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::PageSet => "page_set",
            Self::Page => "page",
            Self::Project => "project",
            Self::CheckSet => "check_set",
            Self::RuleSet => "rule_set",
        }
    }

    /// Whether the kind observes routes. Code kinds observe a project tree,
    /// which has no routes to key pairs on, so their pairs are the check
    /// alone.
    pub fn is_route_scoped(self) -> bool {
        matches!(
            self,
            Self::Page | Self::PageSet | Self::Site | Self::CheckSet
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageExceptionReason {
    CheckSkipped,
    SessionIncomplete,
}

impl CoverageExceptionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CheckSkipped => "check_skipped",
            Self::SessionIncomplete => "session_incomplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageException {
    pub route: Option<String>,
    pub checks_not_run: Vec<String>,
    pub reason: CoverageExceptionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCoverageManifest {
    pub kind: ScanCoverageKind,
    pub successful: bool,
    #[serde(default)]
    pub page_urls: Vec<String>,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub exceptions: Vec<CoverageException>,
}

impl ScanCoverageManifest {
    /// Declare complete coverage for finding-only producers whose registered
    /// rules run over every scanned file.
    pub fn declared(kind: ScanCoverageKind, page_urls: Vec<String>, checks: Vec<String>) -> Self {
        Self {
            kind,
            successful: true,
            page_urls,
            checks,
            exceptions: Vec::new(),
        }
    }

    /// A run that is still in flight or proved nothing. Claims nothing, so it
    /// resolves nothing.
    pub fn unproven(kind: ScanCoverageKind, page_urls: Vec<String>) -> Self {
        Self {
            kind,
            successful: false,
            page_urls,
            checks: Vec::new(),
            exceptions: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if matches!(
            self.kind,
            ScanCoverageKind::CheckSet | ScanCoverageKind::RuleSet
        ) && self.checks.is_empty()
        {
            return Err(format!(
                "{} coverage requires an explicit check set",
                self.kind.as_str()
            ));
        }
        if matches!(
            self.kind,
            ScanCoverageKind::Page | ScanCoverageKind::PageSet
        ) && self.page_urls.is_empty()
        {
            return Err(format!(
                "{} coverage requires at least one page URL",
                self.kind.as_str()
            ));
        }
        Ok(())
    }
}

/// Whether this run proved the `(route, check)` pair.
///
/// `route: None` asks about an observation with no route of its own (a
/// site-level finding), which one claimed, unexcepted route is enough to
/// prove.
pub fn covers(
    coverage: &ScanCoverageManifest,
    route: Option<&str>,
    check_id: &str,
    claim_key: for<'a> fn(&'a str) -> &'a str,
) -> bool {
    if !coverage.successful {
        return false;
    }
    let key = claim_key(check_id);
    if !claims_check(coverage, check_id, key) {
        return false;
    }
    if excepted_on(coverage, None, check_id, key) {
        return false;
    }
    if !coverage.kind.is_route_scoped() {
        return true;
    }
    match route {
        Some(route) => {
            claims_route(coverage, route) && !excepted_on(coverage, Some(route), check_id, key)
        }
        None => coverage
            .page_urls
            .iter()
            .any(|claimed| !excepted_on(coverage, Some(claimed), check_id, key)),
    }
}

fn claims_check(coverage: &ScanCoverageManifest, check_id: &str, key: &str) -> bool {
    coverage
        .checks
        .iter()
        .any(|claimed| claimed == check_id || claimed == key)
}

fn claims_route(coverage: &ScanCoverageManifest, route: &str) -> bool {
    coverage.page_urls.iter().any(|claimed| claimed == route)
}

/// Test global and route-specific exceptions against exact or family IDs.
fn excepted_on(
    coverage: &ScanCoverageManifest,
    route: Option<&str>,
    check_id: &str,
    key: &str,
) -> bool {
    coverage.exceptions.iter().any(|exception| {
        let applies = match (&exception.route, route) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(excepted), Some(route)) => excepted == route,
        };
        applies
            && exception
                .checks_not_run
                .iter()
                .any(|excepted| excepted == check_id || excepted == key)
    })
}

/// Claim only the exact check ID.
pub fn exact_claim_key(check_id: &str) -> &str {
    check_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_uses_the_given_claim_key() {
        // A coverage reader ignores the caller's claim-key policy.
        let coverage = ScanCoverageManifest::declared(
            ScanCoverageKind::Project,
            Vec::new(),
            vec!["accessibility.axe.".into()],
        );
        let check = "accessibility.axe.label";
        fn family(id: &str) -> &str {
            &id[..id.rfind('.').unwrap() + 1]
        }
        assert!(covers(&coverage, None, check, family));
        assert!(!covers(&coverage, None, check, exact_claim_key));
    }
}
