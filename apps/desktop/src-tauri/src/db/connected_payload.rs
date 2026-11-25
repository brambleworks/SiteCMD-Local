//! Build connected-service wire payloads from immutable local evidence.
//! Output types cannot carry source text, paths, prompts, or issue descriptions.

use rusqlite::OptionalExtension;
use sitecmd_protocol::coverage::ScanCoverageManifest;
use sitecmd_protocol::sync::{
    ClientGroupState, CodeBasis, CodeBasisKind, CodeOccurrence, CodeProvenance, CodeSnapshot,
    CodeVersions, DesktopProvenanceKind, DesktopSubmission, DismissalPolicy, FindingSource,
    GroupEntry, GroupMode, GroupSubmission, LastKnownOccurrence, ProjectFingerprintKey,
    WireCoverage, FINGERPRINT_SCHEMA,
};

use crate::core::normalized_scan::{NormalizedRunDiagnostics, ScanEvidenceSource};

#[path = "connected_payload_wire.rs"]
mod wire;
use wire::{canonical_coverage, encodable_identity, incomplete_coverage, wire_or_note};

use super::{
    BootstrapSet, BootstrapState, Database, DbError, ObservedOccurrence, OccurrenceLocation,
    SourceEvidence,
};

/// The deployment relationship the desktop can honestly claim for a code
/// snapshot. A missing commit is represented explicitly as an unknown basis:
/// the findings still inform presence and the snapshot clears nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedCodeBasis {
    pub commit_sha: Option<String>,
    pub kind: CodeBasisKind,
}

/// Everything a caller chooses at submission time. Scan facts are never
/// caller-supplied; they are read from immutable run records below.
#[derive(Debug, Clone)]
pub struct ConnectedSubmissionRequest {
    pub site_id: String,
    pub submission_sequence: i64,
    pub include_groups: bool,
    pub fingerprint_key: Option<ProjectFingerprintKey>,
    /// The epoch of `fingerprint_key`, from the site binding. 1 until a
    /// rotation has completed.
    pub fingerprint_key_version: u16,
    /// The connected service's ordered deployment head. The builder compares
    /// it with provenance persisted on the exact code run below; callers do
    /// not supply a checkout claim of their own.
    pub deployed_commit: Option<String>,
}

#[derive(Debug, Clone)]
struct RunMaterial {
    execution_id: i64,
    observed_at: i64,
    based_on_event_sequence: i64,
    coverage: ScanCoverageManifest,
    diagnostics: NormalizedRunDiagnostics,
    stamp: sitecmd_protocol::release::ReleaseStamp,
}

fn group_entry(
    group: &super::BootstrapGroup,
    fingerprint_key: Option<&ProjectFingerprintKey>,
) -> Result<Option<GroupEntry>, DbError> {
    if wire_or_note::<sitecmd_protocol::sync::wire::CheckId>("group check id", &group.check_id)
        .is_none()
    {
        return Ok(None);
    }
    let (state, dismissal) = match &group.state {
        BootstrapState::Active | BootstrapState::Regressed => (ClientGroupState::Active, None),
        BootstrapState::Snoozed { until } => (
            ClientGroupState::Dismissed,
            Some(DismissalPolicy::Snoozed { until: *until }),
        ),
        BootstrapState::Ignored => (
            ClientGroupState::Dismissed,
            Some(DismissalPolicy::Ignored {
                reopen_on_reobservation: true,
            }),
        ),
        BootstrapState::Blocked { .. } => (
            ClientGroupState::Dismissed,
            Some(DismissalPolicy::Blocked {}),
        ),
        BootstrapState::Verified { .. } => (ClientGroupState::ClaimedFixed, None),
    };
    let mut last_known_occurrences = Vec::new();
    for occurrence in &group.last_known_occurrences {
        let (OccurrenceLocation::File { rule, path }, Some(key)) =
            (&occurrence.location, fingerprint_key)
        else {
            continue;
        };
        if encodable_identity(occurrence) {
            last_known_occurrences.push(LastKnownOccurrence::Code {
                location_hash: key.location_hash(rule, path).try_into()?,
            });
        }
    }
    Ok(Some(GroupEntry {
        check: group.check_id.as_str().try_into()?,
        state,
        dismissal,
        state_changed_at: group.state_changed_at,
        sources: group
            .sources
            .iter()
            .filter(|source| **source == ScanEvidenceSource::CodeScan)
            .map(|_| FindingSource::Code)
            .collect(),
        last_known_occurrences,
    }))
}

fn shared_stamp<'a>(
    runs: &'a [&RunMaterial],
) -> Result<&'a sitecmd_protocol::release::ReleaseStamp, DbError> {
    let first = &runs
        .first()
        .ok_or_else(|| DbError::Other("snapshot evidence has no run records".into()))?
        .stamp;
    for run in runs.iter().skip(1) {
        if run.stamp.engine_release != first.engine_release
            || run.stamp.manifest_digest != first.manifest_digest
            || run.stamp.canonicalizer != first.canonicalizer
            || run.stamp.crawl_profile != first.crawl_profile
        {
            return Err(DbError::Other(
                "runs in one source snapshot carry incompatible version stamps".into(),
            ));
        }
    }
    Ok(first)
}

pub(crate) fn code_occurrence(
    occurrence: &ObservedOccurrence,
    key: &ProjectFingerprintKey,
    basis: &ConnectedCodeBasis,
) -> Option<CodeOccurrence> {
    if !encodable_identity(&occurrence.identity) {
        return None;
    }
    let OccurrenceLocation::File { rule, path } = &occurrence.identity.location else {
        return None;
    };
    let provenance_kind = match basis.kind {
        CodeBasisKind::ExactCheckout | CodeBasisKind::Compatible => {
            DesktopProvenanceKind::Compatible
        }
        CodeBasisKind::Stale => DesktopProvenanceKind::Stale,
        CodeBasisKind::Unknown => DesktopProvenanceKind::Unknown,
    };
    Some(CodeOccurrence {
        check: occurrence.identity.check_id.as_str().try_into().ok()?,
        location_hash: key.location_hash(rule, path).try_into().ok()?,
        instance_count: occurrence.identity.instance_count,
        severity: occurrence.severity,
        confidence: Some(occurrence.confidence),
        provenance: CodeProvenance {
            commit_sha: basis
                .commit_sha
                .as_deref()
                .map(TryInto::try_into)
                .transpose()
                .ok()?,
            kind: provenance_kind,
        },
    })
}

fn code_snapshot(
    evidence: &SourceEvidence,
    stamp: &sitecmd_protocol::release::ReleaseStamp,
    basis: ConnectedCodeBasis,
    coverage: WireCoverage,
    key: &ProjectFingerprintKey,
    key_version: u16,
) -> Result<CodeSnapshot, DbError> {
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    for occurrence in &evidence.occurrences {
        if let OccurrenceLocation::File { rule, .. } = &occurrence.identity.location {
            let rule = engine
                .info()
                .code_rule(rule)
                .ok_or(crate::core::audit::UNKNOWN_CODE_RULE)?;
            if encodable_identity(&occurrence.identity)
                && occurrence.identity.check_id != rule.check_id
            {
                return Err(crate::core::audit::INCONSISTENT_CODE_RULE.into());
            }
        }
    }
    let occurrences = evidence
        .occurrences
        .iter()
        .filter_map(|occurrence| code_occurrence(occurrence, key, &basis))
        .collect();
    Ok(CodeSnapshot {
        observed_at: evidence.observed_at,
        based_on_event_sequence: evidence.based_on_event_sequence,
        versions: CodeVersions {
            fingerprint_schema: FINGERPRINT_SCHEMA,
            fingerprint_key_version: key_version,
            canonicalizer: stamp.canonicalizer,
        },
        manifest_digest: stamp.manifest_digest.as_str().try_into()?,
        key_commitment: key.commitment().try_into()?,
        code_basis: CodeBasis {
            commit_sha: basis.commit_sha.map(TryInto::try_into).transpose()?,
            kind: basis.kind,
            unvouched: Vec::new(),
        },
        coverage,
        occurrences,
    })
}

/// Compares full or abbreviated hexadecimal commit ids case-insensitively.
/// Abbreviations must meet both Git's seven-character floor and the service
/// minimum.
fn names_the_same_commit(stated: &str, observed: &str) -> bool {
    if stated == observed {
        return true;
    }
    if stated.len() < 7 || stated.len() > observed.len() {
        return false;
    }
    if !observed.chars().all(|digit| digit.is_ascii_hexdigit()) {
        return false;
    }
    observed
        .as_bytes()
        .iter()
        .zip(stated.as_bytes())
        .all(|(observed, stated)| observed.eq_ignore_ascii_case(stated))
}

fn connected_code_basis(
    runs: &[&RunMaterial],
    deployed_commit: Option<&str>,
) -> Option<ConnectedCodeBasis> {
    let first = runs.first()?.diagnostics.code_commit_sha.clone();
    if runs
        .iter()
        .any(|run| run.diagnostics.code_commit_sha != first)
    {
        // Evidence from different commits is not one snapshot. Refusing the
        // code half is safer than choosing whichever run happened to sort
        // first and assigning all findings to its checkout.
        return None;
    }
    let kind = if runs
        .iter()
        .all(|run| run.diagnostics.code_tree_clean == Some(true))
        && first
            .as_deref()
            .zip(deployed_commit)
            .is_some_and(|(observed, stated)| names_the_same_commit(stated, observed))
    {
        CodeBasisKind::ExactCheckout
    } else {
        CodeBasisKind::Unknown
    };
    Some(ConnectedCodeBasis {
        commit_sha: first,
        kind,
    })
}

impl Database {
    fn connected_run_material(&self, run_id: i64) -> Result<RunMaterial, DbError> {
        self.execute(move |conn| {
            let Some((observed_at, coverage_json, diagnostics_json, execution_id, based_on_event_sequence)) = conn
                .query_row(
                    "SELECT COALESCE(run.completed_at, run.started_at),
                            run.coverage_json, run.diagnostics_json, run.execution_id,
                            execution.based_on_event_sequence
                     FROM scan_runs run JOIN scan_executions execution ON execution.id = run.execution_id
                     WHERE run.id = ?1 AND run.source = 'code_scan' AND run.status = 'complete'",
                    [run_id],
                    |row| Ok((row.get(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                              row.get(3)?, row.get(4)?)),
                )
                .optional()?
            else {
                return Err(DbError::Other(format!(
                    "connected evidence references missing complete run {run_id}"
                )));
            };
            let stamp = super::engine_release::read_stamp(conn, run_id)?.ok_or_else(|| {
                DbError::Other(format!(
                    "connected evidence run {run_id} has no release stamp"
                ))
            })?;
            Ok(RunMaterial {
                execution_id,
                observed_at,
                based_on_event_sequence,
                coverage: serde_json::from_str(&coverage_json)?,
                diagnostics: serde_json::from_str(&diagnostics_json)?,
                stamp,
            })
        })?
    }

    fn connected_source_runs(
        &self,
        evidence: &SourceEvidence,
    ) -> Result<Vec<RunMaterial>, DbError> {
        evidence
            .run_ids
            .iter()
            .map(|run_id| self.connected_run_material(*run_id))
            .collect()
    }

    /// Build from the completed run that produced these host-counted observations.
    pub(crate) fn build_audited_code_snapshot(
        &self,
        run_id: i64,
        occurrences: Vec<ObservedOccurrence>,
        key: ProjectFingerprintKey,
        key_version: u16,
        deployed_commit: Option<&str>,
    ) -> Result<CodeSnapshot, DbError> {
        let run = self.connected_run_material(run_id)?;
        let evidence = SourceEvidence {
            source: ScanEvidenceSource::CodeScan,
            execution_id: run.execution_id,
            run_ids: vec![run_id],
            observed_at: run.observed_at,
            based_on_event_sequence: run.based_on_event_sequence,
            occurrences,
        };
        let basis = connected_code_basis(&[&run], deployed_commit)
            .ok_or_else(|| DbError::Other("missing checkout basis".into()))?;
        let mut coverage = canonical_coverage(&[&run]);
        if evidence
            .occurrences
            .iter()
            .any(|o| !encodable_identity(&o.identity))
        {
            incomplete_coverage(&mut coverage);
        }
        code_snapshot(&evidence, &run.stamp, basis, coverage, &key, key_version)
    }

    /// Build the exact object the inspector displays and the transport sends.
    /// This is read-only: callers allocate a durable sequence separately only
    /// when they are about to submit.
    #[tracing::instrument(skip(self, request, environment_scope_key), fields(project_id))]
    pub fn build_connected_submission(
        &self,
        project_id: i64,
        environment_scope_key: &str,
        request: ConnectedSubmissionRequest,
    ) -> Result<DesktopSubmission, DbError> {
        if request.site_id.trim().is_empty() {
            return Err("a connected payload needs a site id".into());
        }
        if request.submission_sequence <= 0 {
            return Err("a connected payload needs a positive submission sequence".into());
        }
        let set: BootstrapSet = if request.include_groups {
            self.derive_bootstrap_set(project_id, environment_scope_key)?
        } else {
            BootstrapSet {
                groups: Vec::new(),
                evidence: self.latest_submission_evidence(project_id, environment_scope_key)?,
            }
        };
        let mut submission =
            DesktopSubmission::new(request.site_id.try_into()?, request.submission_sequence);
        if request.include_groups {
            let entries = set
                .groups
                .iter()
                .map(|group| group_entry(group, request.fingerprint_key.as_ref()))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect();
            submission.groups = Some(GroupSubmission {
                mode: GroupMode::Bootstrap,
                entries,
            });
        }

        for evidence in &set.evidence {
            let Some(current_key) = request.fingerprint_key.as_ref() else {
                continue;
            };
            let owned_runs = self.connected_source_runs(evidence)?;
            let runs = owned_runs.iter().collect::<Vec<_>>();
            let stamp = shared_stamp(&runs)?;
            let Some(code_basis) = connected_code_basis(&runs, request.deployed_commit.as_deref())
            else {
                continue;
            };
            let mut coverage = canonical_coverage(&runs);
            if evidence
                .occurrences
                .iter()
                .any(|o| !encodable_identity(&o.identity))
            {
                incomplete_coverage(&mut coverage);
            }
            submission.snapshots.code = Some(code_snapshot(
                evidence,
                stamp,
                code_basis,
                coverage,
                current_key,
                request.fingerprint_key_version,
            )?);
        }
        Ok(submission)
    }
}

#[cfg(test)]
#[path = "connected_payload_tests.rs"]
mod tests;
