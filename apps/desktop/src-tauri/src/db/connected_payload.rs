//! Build connected-service wire payloads from immutable local evidence.
//! Output types cannot carry source text, paths, prompts, or issue descriptions.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use rusqlite::OptionalExtension;
use sitecmd_engine::checks::performance::{browser_vitals, ttfb};
use sitecmd_engine::coverage::{CoverageExceptionReason, ScanCoverageKind, ScanCoverageManifest};
use sitecmd_engine::manifest::{
    capability_manifest, CapabilityManifest, CheckClass, HostedLane, MeasurementUnit,
};
use sitecmd_engine::measurement::from_result_raw_data;
use sitecmd_engine::route::{canonical_route, CanonicalRoute};
use sitecmd_engine::sync::{
    ClientGroupState, CodeBasis, CodeBasisKind, CodeOccurrence, CodeProvenance, CodeSnapshot,
    CodeVersions, DesktopProvenanceKind, DesktopSubmission, DismissalPolicy, FindingSource,
    GroupEntry, GroupMode, GroupSubmission, LastKnownOccurrence, LastKnownWebOccurrence,
    MeasurementSample, ProjectFingerprintKey, StackFacts, WebOccurrence, WebSnapshot, WebVersions,
    WireCoverage, WireCoverageException, WireExecutionProfile, FINGERPRINT_SCHEMA,
};

use crate::core::detector::DetectedStack;
use crate::core::normalized_scan::{NormalizedRunDiagnostics, ScanEvidenceSource, ScanRunKind};

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

/// Pending rotation used only with complete, exception-free code coverage.
#[derive(Debug, Clone)]
pub struct PendingRotation {
    pub key: ProjectFingerprintKey,
    pub version: u16,
}

/// Valid placeholder sequence for callers that build but never submit the
/// enclosing desktop envelope. It does not reserve or order anything.
const UNSEQUENCED_ENVELOPE: i64 = 1;

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
    pub pending_rotation: Option<PendingRotation>,
    /// The connected service's ordered deployment head. The builder compares
    /// it with provenance persisted on the exact code run below; callers do
    /// not supply a checkout claim of their own.
    pub deployed_commit: Option<String>,
}

#[derive(Debug, Clone)]
struct MeasurementRow {
    check_id: String,
    page_url: Option<String>,
    raw_data: serde_json::Value,
}

#[derive(Debug, Clone)]
struct RunMaterial {
    run_kind: ScanRunKind,
    started_at: i64,
    coverage: ScanCoverageManifest,
    diagnostics: NormalizedRunDiagnostics,
    stamp: sitecmd_engine::release::ReleaseStamp,
    measurements: Vec<MeasurementRow>,
    web_occurrence_keys: BTreeSet<(String, String)>,
}

fn parse_url_route(raw: &str) -> Result<CanonicalRoute, DbError> {
    let url = url::Url::parse(raw).map_err(|error| {
        DbError::Other(format!("scan evidence contains an invalid URL: {error}"))
    })?;
    Ok(canonical_route(&url))
}

/// The manifest, resolved once, as the engine's own consumers resolve it:
/// building it digests every contract row plus the document, and both readers
/// below run per finding row.
static MANIFEST: LazyLock<CapabilityManifest> = LazyLock::new(capability_manifest);

fn is_measurement(check_id: &str) -> bool {
    MANIFEST
        .entry(check_id)
        .is_some_and(|entry| entry.class == CheckClass::Measurement)
}

/// Accept measurements only when declared provenance matches the manifest lane.
/// Missing provenance remains valid for legacy metrics.
fn connected_measurement(row: &MeasurementRow) -> Option<(f64, MeasurementUnit)> {
    let entry = MANIFEST.entry(&row.check_id)?;
    let Some(source) = row
        .raw_data
        .get("measurement_source")
        .and_then(serde_json::Value::as_str)
    else {
        // Reject legacy TTFB samples with ambiguous provenance.
        if row.check_id == "performance.ttfb" {
            return None;
        }
        return from_result_raw_data(&row.check_id, &row.raw_data);
    };
    if source == browser_vitals::BROWSER_NAVIGATION_SOURCE && row.check_id == "performance.ttfb" {
        if entry.hosted != HostedLane::ProbeAdapter {
            return None;
        }
        let transport_ttfb = row.raw_data.get("transport_ttfb_ms")?;
        let raw = serde_json::json!({ "ttfb_ms": transport_ttfb });
        return from_result_raw_data(&row.check_id, &raw);
    }
    let producing_lane = match source {
        ttfb::HTTP_PROBE_SOURCE => HostedLane::ProbeAdapter,
        browser_vitals::BROWSER_NAVIGATION_SOURCE => HostedLane::Browser,
        _ => return None,
    };
    if entry.hosted != producing_lane {
        return None;
    }
    from_result_raw_data(&row.check_id, &row.raw_data)
}

fn finding_source(source: ScanEvidenceSource) -> FindingSource {
    match source {
        ScanEvidenceSource::WebScan => FindingSource::Web,
        ScanEvidenceSource::CodeScan => FindingSource::Code,
    }
}

fn group_entry(
    group: &super::BootstrapGroup,
    fingerprint_key: Option<&ProjectFingerprintKey>,
) -> Result<Option<GroupEntry>, DbError> {
    if is_measurement(&group.check_id) {
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
        BootstrapState::Blocked { reason } => (
            ClientGroupState::Dismissed,
            Some(DismissalPolicy::Blocked {
                reason: reason.clone(),
            }),
        ),
        BootstrapState::Verified { .. } => (ClientGroupState::ClaimedFixed, None),
    };
    let mut last_known_occurrences = Vec::new();
    for occurrence in &group.last_known_occurrences {
        match &occurrence.identity.location {
            OccurrenceLocation::Page { url } => {
                let identity = parse_url_route(url)?;
                let mut scope_routes = occurrence
                    .authored_page_urls
                    .iter()
                    .map(|authored_url| parse_url_route(authored_url).map(|route| route.route))
                    .collect::<Result<BTreeSet<_>, _>>()?;
                if scope_routes.is_empty() {
                    scope_routes.insert(identity.route.clone());
                }
                last_known_occurrences.push(LastKnownOccurrence::Web(LastKnownWebOccurrence {
                    identity,
                    scope_routes: scope_routes.into_iter().collect(),
                }));
            }
            OccurrenceLocation::File { rule, path } => {
                if let Some(key) = fingerprint_key {
                    last_known_occurrences.push(LastKnownOccurrence::Code {
                        location_hash: key.location_hash(rule, path),
                    });
                }
            }
            // A site- or project-scoped occurrence has no route or private
            // path to identify. Omitting it is conservative: the service waits
            // for fresh evidence instead of checking a fabricated location.
            OccurrenceLocation::Whole => {}
        }
    }
    Ok(Some(GroupEntry {
        check: group.check_id.clone(),
        state,
        dismissal,
        state_changed_at: group.state_changed_at,
        sources: group.sources.iter().copied().map(finding_source).collect(),
        last_known_occurrences,
    }))
}

fn canonical_coverage(
    manifests: &[&RunMaterial],
    route_scoped: bool,
) -> Result<WireCoverage, DbError> {
    let complete = manifests.iter().all(|run| run.coverage.successful);
    let mut checks = BTreeSet::new();
    let mut routes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut global_exceptions: BTreeMap<CoverageExceptionReason, BTreeSet<String>> =
        BTreeMap::new();
    for run in manifests {
        checks.extend(run.coverage.checks.iter().cloned());
        for page_url in &run.coverage.page_urls {
            let canonical = parse_url_route(page_url)?.route;
            routes.entry(canonical).or_default().push(page_url.clone());
        }
        for exception in &run.coverage.exceptions {
            if exception.route.is_none() {
                global_exceptions
                    .entry(exception.reason)
                    .or_default()
                    .extend(exception.checks_not_run.iter().cloned());
            }
        }
    }
    let global_checks = global_exceptions
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut exceptions = Vec::new();
    if route_scoped {
        for (route, observed_urls) in &routes {
            let missing = checks
                .iter()
                .filter(|check| {
                    !global_checks.contains(*check)
                        && !manifests.iter().any(|run| {
                            observed_urls
                                .iter()
                                .any(|url| run.coverage.covers(Some(url), check))
                        })
                })
                .cloned()
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                exceptions.push(WireCoverageException {
                    route: Some(route.clone()),
                    checks_not_run: missing,
                    reason: CoverageExceptionReason::CheckSkipped,
                });
            }
        }
    }
    exceptions.extend(global_exceptions.into_iter().map(|(reason, checks)| {
        WireCoverageException {
            route: None,
            checks_not_run: checks.into_iter().collect(),
            reason,
        }
    }));
    let kind = if route_scoped {
        if routes.len() > 1
            || manifests
                .iter()
                .any(|run| run.run_kind == ScanRunKind::MultiParent)
        {
            ScanCoverageKind::PageSet
        } else {
            ScanCoverageKind::Page
        }
    } else {
        ScanCoverageKind::Project
    };
    Ok(WireCoverage {
        kind,
        complete,
        routes: routes.into_keys().collect(),
        checks: checks.into_iter().collect(),
        exceptions,
    })
}

fn merge_profile(runs: &[&RunMaterial]) -> Result<WireExecutionProfile, DbError> {
    let mut profile = WireExecutionProfile::default();
    let mut layers = BTreeSet::new();
    for run in runs {
        let candidate = WireExecutionProfile::from_execution(&run.stamp.execution);
        macro_rules! merge_field {
            ($field:ident) => {
                match (&profile.$field, &candidate.$field) {
                    (None, Some(value)) => profile.$field = Some(value.clone()),
                    (Some(left), Some(right)) if left != right => {
                        return Err(DbError::Other(format!(
                            "runs in one snapshot disagree on {}",
                            stringify!($field)
                        )))
                    }
                    _ => {}
                }
            };
        }
        merge_field!(browser);
        merge_field!(axe_version);
        merge_field!(resolver);
        merge_field!(transport_adapter);
        merge_field!(tls_adapter);
        merge_field!(trust_authority);
        merge_field!(scan_profile);
        layers.extend(candidate.layers_run);
    }
    profile.layers_run = layers.into_iter().collect();
    Ok(profile)
}

fn shared_stamp<'a>(
    runs: &'a [&RunMaterial],
) -> Result<&'a sitecmd_engine::release::ReleaseStamp, DbError> {
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

fn stack_facts(runs: &[&RunMaterial]) -> Option<StackFacts> {
    runs.iter().find_map(|run| {
        let raw = run.diagnostics.detected_stack.as_deref()?;
        let stack: DetectedStack = serde_json::from_str(raw).ok()?;
        let framework = stack.framework.or(stack.cms).or(stack.js_framework)?;
        Some(StackFacts {
            framework: Some(framework),
            framework_version: None,
        })
    })
}

fn measurement_samples(runs: &[&RunMaterial]) -> Result<Vec<MeasurementSample>, DbError> {
    let mut samples = BTreeMap::new();
    for row in runs.iter().flat_map(|run| &run.measurements) {
        let Some((value, unit)) = connected_measurement(row) else {
            continue;
        };
        let route = row
            .page_url
            .as_deref()
            .map(parse_url_route)
            .transpose()?
            .map(|route| route.route);
        samples.insert(
            (row.check_id.clone(), route.clone()),
            MeasurementSample {
                check: row.check_id.clone(),
                route,
                value,
                unit: unit.as_str().into(),
            },
        );
    }
    Ok(samples.into_values().collect())
}

fn web_occurrences(
    occurrence: &ObservedOccurrence,
    runs: &[&RunMaterial],
) -> Result<Vec<WebOccurrence>, DbError> {
    if is_measurement(&occurrence.identity.check_id) {
        return Ok(Vec::new());
    }
    let route = match &occurrence.identity.location {
        OccurrenceLocation::Page { url } => Some(parse_url_route(url)?),
        OccurrenceLocation::Whole => None,
        OccurrenceLocation::File { .. } => return Ok(Vec::new()),
    };
    let Some(final_route) = route.as_ref() else {
        return Ok(vec![WebOccurrence {
            check: occurrence.identity.check_id.clone(),
            scope_route: None,
            route: None,
            severity: occurrence.severity,
            confidence: Some(occurrence.confidence),
        }]);
    };
    let occurrence_key = (
        occurrence.identity.check_id.clone(),
        final_route.route.clone(),
    );
    let mut scope_routes = BTreeSet::new();
    for run in runs {
        if !run.web_occurrence_keys.contains(&occurrence_key) {
            continue;
        }
        if let Some(authored_url) = run.diagnostics.page_url.as_deref() {
            scope_routes.insert(parse_url_route(authored_url)?.route);
        }
    }
    if scope_routes.is_empty() {
        scope_routes.insert(final_route.route.clone());
    }
    Ok(scope_routes
        .into_iter()
        .map(|scope_route| WebOccurrence {
            check: occurrence.identity.check_id.clone(),
            scope_route: Some(scope_route),
            route: route.clone(),
            severity: occurrence.severity,
            confidence: Some(occurrence.confidence),
        })
        .collect())
}

fn code_occurrence(
    occurrence: &ObservedOccurrence,
    key: &ProjectFingerprintKey,
    basis: &ConnectedCodeBasis,
) -> Option<CodeOccurrence> {
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
        check: occurrence.identity.check_id.clone(),
        location_hash: key.location_hash(rule, path),
        instance_count: occurrence.identity.instance_count,
        severity: occurrence.severity,
        confidence: Some(occurrence.confidence),
        provenance: CodeProvenance {
            commit_sha: basis.commit_sha.clone(),
            kind: provenance_kind,
        },
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
            let Some((run_kind, started_at, coverage_json, diagnostics_json)) = conn
                .query_row(
                    "SELECT run_kind, started_at, coverage_json, diagnostics_json
                     FROM scan_runs WHERE id = ?1 AND status = 'complete'",
                    [run_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
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
            let mut statement = conn.prepare(
                "SELECT canonical_check_id, page_url, raw_data
                 FROM scan_findings WHERE run_id = ?1 AND raw_data IS NOT NULL",
            )?;
            let rows = statement
                .query_map([run_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let measurements = rows
                .into_iter()
                .filter(|(check_id, _, _)| is_measurement(check_id))
                .map(|(check_id, page_url, raw)| {
                    Ok(MeasurementRow {
                        check_id,
                        page_url,
                        raw_data: serde_json::from_str(&raw)?,
                    })
                })
                .collect::<Result<Vec<_>, DbError>>()?;
            let mut occurrence_statement = conn.prepare(
                "SELECT canonical_check_id, page_url
                   FROM scan_findings
                  WHERE run_id = ?1
                    AND verdict IN ('fail', 'warn')
                    AND location_kind = 'page'
                    AND page_url IS NOT NULL",
            )?;
            let occurrence_rows = occurrence_statement
                .query_map([run_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let web_occurrence_keys = occurrence_rows
                .into_iter()
                .map(|(check_id, page_url)| Ok((check_id, parse_url_route(&page_url)?.route)))
                .collect::<Result<BTreeSet<_>, DbError>>()?;
            Ok(RunMaterial {
                run_kind: run_kind.parse().map_err(DbError::Other)?,
                started_at,
                coverage: serde_json::from_str(&coverage_json)?,
                diagnostics: serde_json::from_str(&diagnostics_json)?,
                stamp,
                measurements,
                web_occurrence_keys,
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

    /// Build an unsequenced code snapshot for gates and CI submissions.
    /// `None` means the environment has no code evidence.
    pub fn build_connected_code_snapshot(
        &self,
        project_id: i64,
        environment_scope_key: &str,
        request: ConnectedSubmissionRequest,
    ) -> Result<Option<sitecmd_engine::sync::CodeSnapshot>, DbError> {
        let request = ConnectedSubmissionRequest {
            // No envelope means no sequence reservation or bootstrap claim.
            submission_sequence: UNSEQUENCED_ENVELOPE,
            include_groups: false,
            ..request
        };
        Ok(self
            .build_connected_submission(project_id, environment_scope_key, request)?
            .snapshots
            .code)
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
        let mut submission = DesktopSubmission::new(request.site_id, request.submission_sequence);
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
            let owned_runs = self.connected_source_runs(evidence)?;
            let runs = owned_runs.iter().collect::<Vec<_>>();
            let stamp = shared_stamp(&runs)?;
            let evaluation_time = runs
                .iter()
                .map(|run| run.started_at)
                .min()
                .unwrap_or(evidence.observed_at);
            match evidence.source {
                ScanEvidenceSource::WebScan => {
                    let occurrences = evidence
                        .occurrences
                        .iter()
                        .map(|occurrence| web_occurrences(occurrence, &runs))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten()
                        .collect();
                    submission.snapshots.web = Some(WebSnapshot {
                        observed_at: evidence.observed_at,
                        based_on_event_sequence: evidence.based_on_event_sequence,
                        versions: WebVersions {
                            engine_release: stamp.engine_release.clone(),
                            fingerprint_schema: FINGERPRINT_SCHEMA,
                            canonicalizer: stamp.canonicalizer,
                            crawl_profile: stamp.crawl_profile,
                        },
                        manifest_digest: stamp.manifest_digest.clone(),
                        evaluation_time,
                        execution_profile: merge_profile(&runs)?,
                        stack_facts: stack_facts(&runs),
                        coverage: canonical_coverage(&runs, true)?,
                        occurrences,
                        measurement_samples: measurement_samples(&runs)?,
                    });
                }
                ScanEvidenceSource::CodeScan => {
                    let Some(current_key) = request.fingerprint_key.as_ref() else {
                        continue;
                    };
                    let Some(code_basis) =
                        connected_code_basis(&runs, request.deployed_commit.as_deref())
                    else {
                        continue;
                    };
                    let coverage = canonical_coverage(&runs, false)?;
                    // The epoch this snapshot travels under. The pending key
                    // is used only for a snapshot that can actually complete
                    // the rotation; the current key keeps governing
                    // everything else, exactly as the service enforces.
                    let completion_shaped = coverage.kind
                        == sitecmd_engine::coverage::ScanCoverageKind::Project
                        && coverage.complete
                        && coverage.exceptions.is_empty();
                    let (key, key_version) = match request.pending_rotation.as_ref() {
                        Some(pending) if completion_shaped => (&pending.key, pending.version),
                        _ => (current_key, request.fingerprint_key_version),
                    };
                    let occurrences = evidence
                        .occurrences
                        .iter()
                        .filter_map(|occurrence| code_occurrence(occurrence, key, &code_basis))
                        .collect();
                    submission.snapshots.code = Some(CodeSnapshot {
                        observed_at: evidence.observed_at,
                        based_on_event_sequence: evidence.based_on_event_sequence,
                        versions: CodeVersions {
                            engine_release: stamp.engine_release.clone(),
                            fingerprint_schema: FINGERPRINT_SCHEMA,
                            fingerprint_key_version: key_version,
                            canonicalizer: stamp.canonicalizer,
                        },
                        manifest_digest: stamp.manifest_digest.clone(),
                        evaluation_time,
                        execution_profile: merge_profile(&runs)?,
                        key_commitment: key.commitment(),
                        code_basis: CodeBasis {
                            commit_sha: code_basis.commit_sha,
                            kind: code_basis.kind,
                            unvouched: Vec::new(),
                        },
                        coverage,
                        occurrences,
                    });
                }
            }
        }
        Ok(submission)
    }
}

#[cfg(test)]
#[path = "connected_payload_tests.rs"]
mod tests;
