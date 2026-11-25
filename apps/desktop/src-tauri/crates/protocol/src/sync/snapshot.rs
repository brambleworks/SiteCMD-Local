//! Source-specific connected-service snapshots with coverage-bound resolution.

use crate::manifest::ManifestDigest;
use crate::sync::wire::{CheckId, CommitSha, Digest, RoutePath};
use serde::{Deserialize, Serialize};

use crate::coverage::{CoverageExceptionReason, ScanCoverageKind};
use crate::route::CanonicalRoute;
use crate::vocab::{IssueConfidence, MeasurementUnit, Severity};

/// Engine versions pinned by one Web snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebVersions {
    pub fingerprint_schema: u16,
    pub canonicalizer: u16,
    pub crawl_profile: u16,
}

/// Code-snapshot versions, including the fingerprint key but no crawl profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeVersions {
    pub fingerprint_schema: u16,
    pub fingerprint_key_version: u16,
    pub canonicalizer: u16,
}

/// One uncovered route-check pair with its explicit coverage reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCoverageException {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RoutePath>,
    pub checks_not_run: Vec<CheckId>,
    pub reason: CoverageExceptionReason,
}

/// Pair-level snapshot authority. `complete` claims the route-check product;
/// `exceptions` removes individual pairs from that claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCoverage {
    pub kind: ScanCoverageKind,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RoutePath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<WireCoverageException>,
}

/// Web finding identity plus the severity and confidence inputs required by
/// the shared scorer for weighting, caps, and deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebOccurrence {
    pub check: CheckId,
    /// Absent for a site-scoped cross-page finding. Assigning the environment
    /// root would falsely make one route capable of verifying a set-level
    /// finding, so route absence is part of the identity contract.
    #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
    pub route: Option<CanonicalRoute>,
    /// The canonical authored route whose execution reached `route`. It can
    /// differ after a redirect and governs scope and absence coverage, while
    /// `route` remains the final resource identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_route: Option<RoutePath>,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<IssueConfidence>,
}

/// Checkout provenance claims available to an unattested desktop.
/// Exact and unattested verdicts remain server-assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopProvenanceKind {
    /// A known-ancestor commit with the relevant files unchanged since. Only
    /// the side holding git can compute this, which is why no server-side
    /// corroboration can mint it.
    Compatible,
    /// Local evidence predates the deployment.
    Stale,
    /// No trustworthy code-side baseline exists.
    Unknown,
}

/// The commit a code occurrence was observed against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProvenance {
    #[serde(default)]
    pub commit_sha: Option<CommitSha>,
    pub kind: DesktopProvenanceKind,
}

/// A code pair's identity: the check, and the keyed hash of where it fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodePairIdentity {
    pub check: CheckId,
    pub location_hash: Digest,
}

/// Whether a code snapshot may resolve absence, and for which pairs.
/// Snapshot-level authority covers clean scans; `unvouched` excludes pairs in
/// paths whose compatibility cannot be established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeBasis {
    #[serde(default)]
    pub commit_sha: Option<CommitSha>,
    pub kind: CodeBasisKind,
    /// The pairs this basis does NOT cover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unvouched: Vec<CodePairIdentity>,
}

/// The four bases, two of which may resolve absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeBasisKind {
    /// Clean working tree at the deployed SHA, self-reported by the desktop.
    ExactCheckout,
    /// A known ancestor with the relevant files unchanged since.
    /// Machine-independent, so one installation's compatible snapshot soundly
    /// clears what another established.
    Compatible,
    /// Older than the current deployment. Informs presence, resolves nothing.
    Stale,
    /// No usable relationship to the deployed commit.
    Unknown,
}

impl CodeBasisKind {
    /// Whether a basis of this kind may resolve absence for pairs it vouches
    /// for. Stale and unknown bases inform presence and never clear.
    pub fn may_resolve_absence(self) -> bool {
        matches!(self, Self::ExactCheckout | Self::Compatible)
    }
}

/// Code finding identity, multiplicity, provenance, and score inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeOccurrence {
    pub check: CheckId,
    pub location_hash: Digest,
    pub instance_count: u32,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<IssueConfidence>,
    pub provenance: CodeProvenance,
}

/// Timing sample excluded from lifecycle state because it varies by vantage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasurementSample {
    pub check: CheckId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RoutePath>,
    pub value: f64,
    /// The unit, which the capability manifest is the authority on. A sample
    /// whose unit disagrees with its check's manifest entry is rejected rather
    /// than charted against values it cannot be compared to.
    pub unit: MeasurementUnit,
}

/// A completed web scan, as the service reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebSnapshot {
    pub observed_at: i64,
    /// Latest site event sequence known to the producer when scanning.
    pub based_on_event_sequence: i64,
    pub versions: WebVersions,
    pub manifest_digest: ManifestDigest,
    pub coverage: WireCoverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<WebOccurrence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measurement_samples: Vec<MeasurementSample>,
}

/// A completed code scan, as the service reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSnapshot {
    pub observed_at: i64,
    pub based_on_event_sequence: i64,
    pub versions: CodeVersions,
    pub manifest_digest: ManifestDigest,
    /// The commitment of the key these fingerprints were computed under, so a
    /// producer hashing under the wrong key for a claimed version fails
    /// visibly instead of corrupting identity matching in silence.
    pub key_commitment: Digest,
    pub code_basis: CodeBasis,
    pub coverage: WireCoverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<CodeOccurrence>,
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
