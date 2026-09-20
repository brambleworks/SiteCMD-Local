//! Inspect the exact connected payload from the standalone CLI.

use std::io::Read;
use std::path::PathBuf;

use sitecmd_engine::sync::ProjectFingerprintKey;
use zeroize::Zeroizing;

use crate::connected_export::{
    decrypt_site_connection, ImportedSiteConnection, MAX_CONNECTION_EXPORT_BYTES,
};
use crate::connected_workflow::proposed_submission_sequence;
use crate::core::code_provenance::CodeCheckoutProvenance;
use crate::db::{ConnectedSubmissionRequest, Database};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedArgs {
    pub dry_run: bool,
    pub connection_export: PathBuf,
    pub passphrase_env: String,
    pub db_path: Option<PathBuf>,
}

pub fn build_dry_run_payload(
    db: &Database,
    connection: &ImportedSiteConnection,
) -> Result<String, String> {
    // Any epoch the service coordinated is usable; the snapshot below is
    // stamped with the export's own version. Zero never named a key.
    if connection.fingerprint_key_version < 1 {
        return Err("the connection export carries an invalid fingerprint key version".into());
    }
    let project_id = db
        .find_project_for_url_result(&connection.environment_scope_key)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "no local SiteCMD project contains environment {}",
                connection.environment_scope_key
            )
        })?;
    let binding = db
        .get_connected_site(project_id, &connection.environment_scope_key)
        .map_err(|error| error.to_string())?;
    if binding
        .as_ref()
        .is_some_and(|site| site.site_id != connection.site_id)
    {
        return Err(
            "the connection export belongs to a different connected site than this environment"
                .into(),
        );
    }
    let include_groups = binding
        .as_ref()
        .is_none_or(|site| site.bootstrapped_at.is_none());
    let producer = db
        .get_producer_identity()
        .map_err(|error| error.to_string())?;
    let submission_sequence = proposed_submission_sequence(producer.as_ref())?;
    let submission = db
        .build_connected_submission(
            project_id,
            &connection.environment_scope_key,
            ConnectedSubmissionRequest {
                site_id: connection.site_id.clone(),
                submission_sequence,
                include_groups,
                fingerprint_key: Some(ProjectFingerprintKey::from_bytes(
                    connection.fingerprint_key,
                )),
                fingerprint_key_version: connection.fingerprint_key_version,
                pending_rotation: None,
                deployed_commit: None,
            },
        )
        .map_err(|error| error.to_string())?;
    submission
        .render_for_inspection()
        .map_err(|error| format!("failed to render connected payload: {error}"))
}

pub(crate) fn read_connection_export(path: &std::path::Path) -> Result<String, String> {
    crate::app_identity::validate_private_file_target(path)
        .map_err(|error| format!("refused unsafe connection export: {error}"))?;
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_CONNECTION_EXPORT_BYTES as u64 {
        return Err("connection export is not a bounded regular file".into());
    }
    let mut serialized = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut serialized)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Ok(serialized)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateArgs {
    pub connection_export: PathBuf,
    pub passphrase_env: String,
    pub token_env: String,
    pub db_path: Option<PathBuf>,
    pub project_path: Option<PathBuf>,
    pub threshold: String,
    pub strict: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CheckoutAuditSummary {
    pub ignored_findings: usize,
    pub stale_suppressions: usize,
    pub configured_suppressions: usize,
}

impl CheckoutAuditSummary {
    pub fn notice(self) -> Option<String> {
        (self.configured_suppressions > 0).then(|| {
            format!(
                "Local suppressions: {} finding(s) ignored; {} stale or expired suppression(s).",
                self.ignored_findings, self.stale_suppressions
            )
        })
    }
}

/// Evaluate a desktop-shaped candidate without mutating connected site state.
pub async fn run_gate(args: GateArgs) -> Result<(u8, String), String> {
    let serialized = read_connection_export(&args.connection_export)?;
    let passphrase = Zeroizing::new(std::env::var(&args.passphrase_env).map_err(|_| {
        format!(
            "set {} to the connection export passphrase",
            args.passphrase_env
        )
    })?);
    let token = Zeroizing::new(std::env::var(&args.token_env).map_err(|_| {
        format!(
            "set {} to the CI token minted for this site",
            args.token_env
        )
    })?);
    if token.trim().is_empty() {
        return Err(format!("{} is empty", args.token_env));
    }
    let connection = decrypt_site_connection(&serialized, &passphrase)?;
    let db_path = args
        .db_path
        .or_else(crate::cli::default_desktop_db_path)
        .ok_or_else(|| "could not locate the SiteCMD desktop database".to_string())?;
    crate::app_identity::validate_private_file_target(&db_path)
        .map_err(|error| format!("refused unsafe SiteCMD database path: {error}"))?;
    let db = Database::open(db_path)?;

    // Audit the current checkout so the gate grades the tree being merged, not
    // stale or absent database state.
    let audit_summary = scan_this_checkout(&db, &connection, args.project_path.as_deref())?;
    // No deployed commit: a gate grades a branch, and a branch is not a
    // deployment. The basis is therefore unknown, which resolves nothing - and
    // the gate resolves nothing anyway.
    let snapshot = build_candidate_snapshot(&db, &connection, None)?;
    let client = crate::connected_service::ConnectedServiceClient::configured(token.trim())
        .map_err(|error| error.to_string())?;
    let verdict = client
        .gate(
            &connection.site_id,
            &crate::connected_service::GateRequest {
                policy: crate::connected_service::GatePolicy {
                    severity_threshold: args.threshold.clone(),
                    strict_detector_changes: args.strict,
                },
                schema_version: sitecmd_engine::sync::SCHEMA_VERSION,
                site_id: connection.site_id.clone(),
                snapshot,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    let failed = verdict.failed();
    let mut rendered = render_verdict(&verdict);
    if let Some(notice) = audit_summary.notice() {
        rendered.push('\n');
        rendered.push_str(&notice);
    }
    Ok((u8::from(failed), rendered))
}

/// Audit the working tree against the environment named by the connection.
pub(super) fn scan_this_checkout(
    db: &Database,
    connection: &ImportedSiteConnection,
    project_path: Option<&std::path::Path>,
) -> Result<CheckoutAuditSummary, String> {
    let root = match project_path {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|error| format!("could not read the working directory: {error}"))?,
    };
    let root = std::fs::canonicalize(&root)
        .map_err(|error| format!("cannot resolve project path: {error}"))?;
    let display = root.to_string_lossy().to_string();
    let name = root
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    let project_id = db
        .upsert_project(&name, &display, None)
        .map_err(|error| error.to_string())?;
    db.add_environment(
        project_id,
        &connection.environment_scope_key,
        "Production",
        "production",
        "cli",
    )
    .map_err(|error| error.to_string())?;

    let before = CodeCheckoutProvenance::capture(&display);
    let started = std::time::Instant::now();
    let report = crate::core::code_scan::audit_project(&root)?;
    let audit = super::audit_suppressions::apply_project_suppressions(
        &root,
        report,
        chrono::Utc::now().date_naive(),
    )?;
    let summary = CheckoutAuditSummary {
        ignored_findings: audit.ignored_findings.len(),
        stale_suppressions: audit.stale_suppression_count(),
        configured_suppressions: audit.suppressions.len(),
    };
    let provenance = before.confirm_unchanged(CodeCheckoutProvenance::capture(&display));
    db.save_code_scan_with_provenance(
        project_id,
        Some(connection.environment_scope_key.clone()),
        display,
        &audit.report,
        started.elapsed().as_millis() as u64,
        provenance,
    )
    .map_err(|error| error.to_string())?;
    Ok(summary)
}

/// Build gate and CI code evidence with the canonical payload builder.
/// A deployed commit upgrades a clean checkout to `exact_checkout` evidence.
pub(super) fn build_candidate_snapshot(
    db: &Database,
    connection: &ImportedSiteConnection,
    deployed_commit: Option<&str>,
) -> Result<sitecmd_engine::sync::CodeSnapshot, String> {
    // Any epoch the service coordinated is usable; the snapshot below is
    // stamped with the export's own version. Zero never named a key.
    if connection.fingerprint_key_version < 1 {
        return Err("the connection export carries an invalid fingerprint key version".into());
    }
    let project_id = db
        .find_project_for_url_result(&connection.environment_scope_key)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "no local SiteCMD project contains environment {}",
                connection.environment_scope_key
            )
        })?;
    let snapshot = db
        // These callers build snapshots, not submissions; the builder supplies
        // sequence and bootstrap values.
        .build_connected_code_snapshot(
            project_id,
            &connection.environment_scope_key,
            ConnectedSubmissionRequest {
                site_id: connection.site_id.clone(),
                submission_sequence: 0,
                include_groups: false,
                fingerprint_key: Some(ProjectFingerprintKey::from_bytes(
                    connection.fingerprint_key,
                )),
                fingerprint_key_version: connection.fingerprint_key_version,
                pending_rotation: None,
                deployed_commit: deployed_commit.map(str::to_string),
            },
        )
        .map_err(|error| error.to_string())?;
    // The audit already ran; report an empty result rather than suggesting a
    // web-only scan type.
    snapshot.ok_or_else(|| {
        format!(
            "the audit of this checkout produced no code snapshot for {}; there is nothing here to gate",
            connection.environment_scope_key
        )
    })
}

/// CI-native output: counts, the threshold that produced the verdict, and the
/// identities. No evidence, because the service sent none and the gate is not
/// a way to read a site's findings from a runner.
fn render_verdict(verdict: &crate::connected_service::GateVerdict) -> String {
    let mut lines = vec![format!(
        "{}: {} new finding(s), {} at or above {}, {} warned",
        if verdict.failed() { "FAIL" } else { "PASS" },
        verdict.counts.new,
        verdict.counts.failing,
        verdict.threshold,
        verdict.counts.warned,
    )];
    for finding in &verdict.new_findings {
        let suffix = finding
            .warned_because
            .as_deref()
            .map(|reason| format!(" (warned: {reason})"))
            .unwrap_or_default();
        lines.push(format!(
            "  {} {} {}{}",
            finding.severity, finding.check, finding.identity, suffix
        ));
    }
    for warning in &verdict.warnings {
        lines.push(format!("  note: {warning}"));
    }
    lines.join("\n")
}

pub fn run(args: ConnectedArgs) -> Result<String, String> {
    if !args.dry_run {
        return Err("connected currently requires --dry-run".into());
    }
    let serialized = read_connection_export(&args.connection_export)?;
    let passphrase = Zeroizing::new(std::env::var(&args.passphrase_env).map_err(|_| {
        format!(
            "set {} to the connection export passphrase",
            args.passphrase_env
        )
    })?);
    let connection = decrypt_site_connection(&serialized, &passphrase)?;
    let db_path = args
        .db_path
        .or_else(crate::cli::default_desktop_db_path)
        .ok_or_else(|| "could not locate the SiteCMD desktop database".to_string())?;
    crate::app_identity::validate_private_file_target(&db_path)
        .map_err(|error| format!("refused unsafe SiteCMD database path: {error}"))?;
    if !db_path.is_file() {
        return Err(format!(
            "SiteCMD desktop database does not exist at {}",
            db_path.display()
        ));
    }
    let db = Database::open(db_path)?;
    build_dry_run_payload(&db, &connection)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const ENVIRONMENT_URL: &str = "https://example.com";
    const SITE_ID: &str = "site_cli_preview";

    fn fixture() -> (tempfile::TempDir, Database, i64, ImportedSiteConnection) {
        let directory = tempfile::tempdir().expect("tempdir");
        let db = Database::open(directory.path().join("sitecmd.db")).expect("database");
        let project_id = db
            .upsert_project(
                "CLI Preview",
                directory.path().to_str().expect("path"),
                None,
            )
            .expect("project");
        db.add_environment(
            project_id,
            ENVIRONMENT_URL,
            "Production",
            "production",
            "test",
        )
        .expect("environment");
        let connection = ImportedSiteConnection {
            site_id: SITE_ID.into(),
            environment_scope_key: ENVIRONMENT_URL.into(),
            fingerprint_key_version: 1,
            fingerprint_key: [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
        };
        (directory, db, project_id, connection)
    }

    #[test]
    fn dry_run_renders_the_exact_submission_without_allocating_a_sequence() {
        let (_directory, db, _project_id, connection) = fixture();
        assert_eq!(db.get_producer_identity().expect("producer"), None);

        let rendered = build_dry_run_payload(&db, &connection).expect("dry run");
        let payload: Value = serde_json::from_str(&rendered).expect("payload JSON");

        assert_eq!(payload["site_id"], SITE_ID);
        assert_eq!(payload["submission_sequence"], 1);
        assert_eq!(payload["groups"]["mode"], "bootstrap");
        assert_eq!(db.get_producer_identity().expect("producer"), None);
    }

    #[test]
    fn dry_run_uses_the_next_sequence_and_omits_groups_after_bootstrap() {
        let (_directory, db, project_id, connection) = fixture();
        db.connect_site(project_id, ENVIRONMENT_URL, SITE_ID, 10)
            .expect("connect");
        db.mark_site_bootstrapped(project_id, ENVIRONMENT_URL, 11)
            .expect("bootstrap");
        db.allocate_submission_sequence(12).expect("allocate setup");

        let rendered = build_dry_run_payload(&db, &connection).expect("dry run");
        let payload: Value = serde_json::from_str(&rendered).expect("payload JSON");

        assert_eq!(payload["submission_sequence"], 2);
        assert!(payload.get("groups").is_none());
        assert_eq!(
            db.get_producer_identity()
                .expect("producer")
                .expect("identity")
                .last_submission_sequence,
            1
        );
    }

    #[test]
    fn dry_run_refuses_an_export_for_a_different_bound_site() {
        let (_directory, db, project_id, connection) = fixture();
        db.connect_site(project_id, ENVIRONMENT_URL, "site_other", 10)
            .expect("connect");

        let error = build_dry_run_payload(&db, &connection).expect_err("site mismatch");

        assert!(error.contains("different connected site"), "{error}");
    }
}
