//! Desktop evidence submission. Omitted groups mean no update, never deletion.

use crate::sync::wire::{CheckId, Digest, Identifier, RoutePath};
use serde::{Deserialize, Serialize};

use crate::route::CanonicalRoute;
use crate::sync::snapshot::{CodeSnapshot, WebSnapshot};
use crate::sync::SCHEMA_VERSION;

/// Submission environment, tagged so new variants remain wire-compatible.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    #[default]
    Production,
}

/// Which scan sources a lifecycle group has findings from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Web,
    Code,
}

/// Lifecycle states a client may assert.
///
/// Only the service may derive `verified_fixed` or `regressed` from evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientGroupState {
    Active,
    Dismissed,
    ClaimedFixed,
}

/// Dismissal policy evaluated by the service, independent of desktop uptime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DismissalPolicy {
    /// Effective until the moment passes, evaluated server-side at read time.
    Snoozed { until: i64 },
    /// Temporary by the desktop's own rule: seeing it again reopens it.
    Ignored { reopen_on_reobservation: bool },
    /// Durable. Nothing but an explicit user mutation changes it. This is the
    /// dismissal that means stop.
    Blocked {},
}

/// Last-known web identity with final-route and authored-scope provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastKnownWebOccurrence {
    #[serde(flatten)]
    pub identity: CanonicalRoute,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_routes: Vec<RoutePath>,
}

/// The two variants are structurally disjoint, which is what makes the
/// untagged encoding unambiguous: a web identity has a route, a code identity
/// has a keyed hash, and neither has the other's field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LastKnownOccurrence {
    Web(LastKnownWebOccurrence),
    Code { location_hash: Digest },
}

/// One lifecycle group as the desktop is importing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    /// The canonical check id, which is what groups key on.
    pub check: CheckId,
    pub state: ClientGroupState,
    /// Present exactly when the state is `dismissed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissal: Option<DismissalPolicy>,
    pub state_changed_at: i64,
    pub sources: Vec<FindingSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub last_known_occurrences: Vec<LastKnownOccurrence>,
}

impl GroupEntry {
    /// Return whether dismissal state and policy are present together.
    pub fn policy_matches_state(&self) -> bool {
        matches!(self.state, ClientGroupState::Dismissed) == self.dismissal.is_some()
    }
}

/// How the server should read the `groups` member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMode {
    /// One-time import, including a valid empty group set.
    Bootstrap,
}

/// The lifecycle groups a bootstrap submission carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSubmission {
    pub mode: GroupMode,
    pub entries: Vec<GroupEntry>,
}

/// A web finding's identity inside a correlation pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebIdentity {
    pub check: CheckId,
    pub route: RoutePath,
}

/// A code finding's identity inside a correlation pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeIdentity {
    pub check: CheckId,
    pub location_hash: Digest,
}

/// Association between synced web and opaque code identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationPair {
    pub web: WebIdentity,
    pub code: CodeIdentity,
}

/// Correlation pairs keyed to the fingerprint version that produced their code hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationPairs {
    pub fingerprint_key_version: u16,
    pub pairs: Vec<CorrelationPair>,
}

/// Optional source snapshots carried by a submission.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshots {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<WebSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<CodeSnapshot>,
}

impl Snapshots {
    pub fn is_empty(&self) -> bool {
        self.web.is_none() && self.code.is_none()
    }
}

/// Complete outbound payload rendered by the sync inspector and CLI dry run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesktopSubmission {
    pub schema_version: u16,
    /// The server-issued opaque site identifier, minted at connection.
    pub site_id: Identifier,
    pub environment: Environment,
    /// This installation's own monotonic counter. It orders this producer's
    /// submissions and nothing else: independent producers' counters are never
    /// compared, because they are not measuring the same thing.
    pub submission_sequence: i64,
    /// Present only for the one-time bootstrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<GroupSubmission>,
    pub snapshots: Snapshots,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_pairs: Option<CorrelationPairs>,
}

impl DesktopSubmission {
    /// A submission with the current schema version and nothing else claimed.
    pub fn new(site_id: Identifier, submission_sequence: i64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            site_id,
            environment: Environment::Production,
            submission_sequence,
            groups: None,
            snapshots: Snapshots::default(),
            correlation_pairs: None,
        }
    }

    /// Pretty-prints the exact wire payload for the app inspector and CLI
    /// dry-run output.
    pub fn render_for_inspection(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
