//! Inspect the exact connected payload from the standalone CLI.

use crate::time::now_millis;

use std::io::Read;
use std::path::PathBuf;

use sitecmd_protocol::sync::ProjectFingerprintKey;
use zeroize::Zeroizing;

use crate::connected_export::{
    decrypt_site_connection, ImportedSiteConnection, MAX_CONNECTION_EXPORT_BYTES,
};
use crate::connected_service::ConnectedServiceClient;
use crate::connected_workflow::proposed_submission_sequence;
use crate::core::audit::connected_audit_at;
use crate::core::code_provenance::CodeCheckoutProvenance;
use crate::db::{ConnectedSubmissionRequest, Database, ObservedOccurrence};

use super::{settle, ConnectStop};

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
    /// Where to write `verdict=` and `new=` lines for a workflow to read, so
    /// it never parses the printed summary.
    pub outputs: Option<PathBuf>,
}

pub(super) struct CheckoutAuditSummary {
    run_id: i64,
    occurrences: Vec<ObservedOccurrence>,
    pub ignored_findings: usize,
    pub stale_suppressions: usize,
    pub configured_suppressions: usize,
}

impl CheckoutAuditSummary {
    pub fn notice(&self) -> Option<String> {
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
    run_gate_with(args, ConnectedServiceClient::configured).await
}

/// `run_gate` through the client `connect` builds from the CI token, which is
/// what lets the wire tests point it at a local double.
pub(super) async fn run_gate_with(
    args: GateArgs,
    connect: impl Fn(&str) -> Result<ConnectedServiceClient, String>,
) -> Result<(u8, String), String> {
    let outputs = args.outputs.clone();
    let outcome = gate(args, connect).await;
    if let Some(outputs) = &outputs {
        // The workflow reads the verdict here rather than from the summary
        // printed for people, and a gate that could not run names none.
        let signal = match &outcome {
            Ok(graded) => Some((if graded.failed { "fail" } else { "pass" }, graded.new)),
            Err(ConnectStop::AccountInactive { .. }) => Some(("inactive", 0)),
            Err(ConnectStop::Failed(_)) => None,
        };
        if let Some((verdict, new)) = signal {
            std::fs::write(outputs, format!("verdict={verdict}\nnew={new}\n"))
                .map_err(|error| format!("{} could not be written: {error}", outputs.display()))?;
        }
    }
    settle(
        outcome.map(|graded| (u8::from(graded.failed), graded.summary)),
        |notice| (0, notice),
    )
}

/// The verdict the gate door gave, as the command reports it.
struct Graded {
    failed: bool,
    new: u32,
    summary: String,
}

async fn gate(
    args: GateArgs,
    connect: impl Fn(&str) -> Result<ConnectedServiceClient, String>,
) -> Result<Graded, ConnectStop> {
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
        return Err(format!("{} is empty", args.token_env).into());
    }
    let connection = decrypt_site_connection(&serialized, &passphrase)?;
    let db_path = args
        .db_path
        .or_else(crate::cli::default_desktop_db_path)
        .ok_or_else(|| {
            "could not locate the local SiteCMD SQLite database (sitecmd.db)".to_string()
        })?;
    crate::app_identity::validate_private_file_target(&db_path)
        .map_err(|error| format!("refused unsafe SiteCMD database path: {error}"))?;
    let db = Database::open(db_path)?;

    // Audit the current checkout so the gate grades the tree being merged, not
    // stale or absent database state.
    let audit_summary = scan_this_checkout(&db, &connection, args.project_path.as_deref())?;
    // No deployed commit: a gate grades a branch, and a branch is not a
    // deployment. The basis is therefore unknown, which resolves nothing - and
    // the gate resolves nothing anyway.
    let snapshot = build_candidate_snapshot(&db, &connection, &audit_summary, None)?;
    let client = connect(token.trim())?;
    let verdict = client
        .gate(
            &connection.site_id,
            &crate::connected_service::GateRequest {
                policy: crate::connected_service::GatePolicy {
                    severity_threshold: args.threshold.as_str().try_into()?,
                    strict_detector_changes: args.strict,
                },
                schema_version: sitecmd_protocol::sync::SCHEMA_VERSION,
                site_id: connection.site_id.as_str().try_into()?,
                snapshot,
            },
        )
        .await
        .map_err(|error| ConnectStop::refused(&error, ToString::to_string).ungraded())?;
    let mut summary = render_verdict(&verdict);
    if let Some(notice) = audit_summary.notice() {
        summary.push('\n');
        summary.push_str(&notice);
    }
    Ok(Graded {
        failed: verdict.failed(),
        new: verdict.counts.new,
        summary,
    })
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
    let now_ms = now_millis();
    let (wire, report) = connected_audit_at(&root, now_ms).map_err(|error| error.to_string())?;
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    let audit = super::audit_suppressions::apply_project_suppressions_at(&root, report, now_ms)?;
    let occurrences =
        super::connected_submit::submission_observations(&wire, &audit, engine.info())?;
    let provenance = before.confirm_unchanged(CodeCheckoutProvenance::capture(&display));
    let run_id = db
        .save_code_scan_with_provenance(
            project_id,
            Some(connection.environment_scope_key.clone()),
            display,
            &audit.report,
            started.elapsed().as_millis() as u64,
            provenance,
        )
        .map_err(|error| error.to_string())?;
    Ok(CheckoutAuditSummary {
        run_id,
        occurrences,
        ignored_findings: audit.ignored_findings.len(),
        stale_suppressions: audit.stale_suppression_count(),
        configured_suppressions: audit.suppressions.len(),
    })
}

/// A deployed commit upgrades a clean checkout to exact-checkout evidence.
pub(super) fn build_candidate_snapshot(
    db: &Database,
    connection: &ImportedSiteConnection,
    audit: &CheckoutAuditSummary,
    deployed_commit: Option<&str>,
) -> Result<sitecmd_protocol::sync::CodeSnapshot, String> {
    if connection.fingerprint_key_version < 1 {
        return Err("the connection export carries an invalid fingerprint key version".into());
    }
    db.build_audited_code_snapshot(
        audit.run_id,
        audit.occurrences.clone(),
        ProjectFingerprintKey::from_bytes(connection.fingerprint_key),
        connection.fingerprint_key_version,
        deployed_commit,
    )
    .map_err(|error| error.to_string())
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
        .ok_or_else(|| {
            "could not locate the local SiteCMD SQLite database (sitecmd.db)".to_string()
        })?;
    crate::app_identity::validate_private_file_target(&db_path)
        .map_err(|error| format!("refused unsafe SiteCMD database path: {error}"))?;
    if !db_path.is_file() {
        return Err(format!(
            "The local SiteCMD SQLite database does not exist at {}",
            db_path.display()
        ));
    }
    let db = Database::open(db_path)?;
    build_dry_run_payload(&db, &connection)
}

#[cfg(feature = "test-support")]
pub struct CheckoutSuppressionCounts {
    pub ignored_findings: usize,
    pub stale_suppressions: usize,
    pub configured_suppressions: usize,
}

#[cfg(feature = "test-support")]
pub fn audit_checkout_snapshot(
    db: &Database,
    connection: &ImportedSiteConnection,
    path: &std::path::Path,
) -> Result<
    (
        sitecmd_protocol::sync::CodeSnapshot,
        CheckoutSuppressionCounts,
    ),
    String,
> {
    let audit = scan_this_checkout(db, connection, Some(path))?;
    let snapshot = build_candidate_snapshot(db, connection, &audit, None)?;
    let counts = CheckoutSuppressionCounts {
        ignored_findings: audit.ignored_findings,
        stale_suppressions: audit.stale_suppressions,
        configured_suppressions: audit.configured_suppressions,
    };
    Ok((snapshot, counts))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::cli::test_support::{clean_checkout, exported_site, through, ENVIRONMENT_URL};
    use crate::connected_service::test_double::{
        request_line, respond_in_sequence, ACCOUNT_INACTIVE_PROBLEM, ENTITLEMENT_SUSPENDED_PROBLEM,
    };
    use crate::connected_service::ACCOUNT_INACTIVE_GATE_NOTICE;

    const SITE_ID: &str = "site_cli_preview";
    const GATE_SITE_ID: &str = "site_cli_gate";

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
            fingerprint_key: [7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN],
        };
        (directory, db, project_id, connection)
    }

    fn seed_binding(
        db: &Database,
        project_id: i64,
        site_id: &'static str,
        bootstrapped_at: Option<i64>,
    ) {
        db.execute(move |conn| {
            conn.execute(
                "INSERT INTO connected_sites (project_id, env_url, site_id, connected_at, bootstrapped_at)
                 VALUES (?1, ?2, ?3, 10, ?4)",
                rusqlite::params![project_id, ENVIRONMENT_URL, site_id, bootstrapped_at],
            )
        }).unwrap().unwrap();
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
        seed_binding(&db, project_id, SITE_ID, Some(11));
        db.execute(|conn| {
            conn.execute(
                "INSERT INTO connected_producer
                    (id, installation_id, submission_sequence, minted_at)
                 VALUES (1, 'test-installation', 1, 12)",
                [],
            )
        })
        .unwrap()
        .unwrap();

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
        seed_binding(&db, project_id, "site_other", None);

        let error = build_dry_run_payload(&db, &connection).expect_err("site mismatch");

        assert!(error.contains("different connected site"), "{error}");
    }

    #[test]
    fn dry_run_names_the_missing_local_sqlite_database() {
        // A missing local database was reported as belonging to the desktop app.
        let directory = tempfile::tempdir().expect("tempdir");
        let (connection_export, passphrase_env, _) =
            exported_site(directory.path(), SITE_ID, "SITECMD_TEST_MISSING_PREVIEW_DB");
        let db_path = directory.path().join("sitecmd.db");
        let error = run(ConnectedArgs {
            dry_run: true,
            connection_export,
            passphrase_env,
            db_path: Some(db_path.clone()),
        })
        .expect_err("database is missing");
        assert_eq!(
            error,
            format!(
                "The local SiteCMD SQLite database does not exist at {}",
                db_path.display()
            )
        );
    }

    fn gate_args(
        workspace: &std::path::Path,
        variable_prefix: &str,
        project_path: PathBuf,
    ) -> GateArgs {
        let (connection_export, passphrase_env, token_env) =
            exported_site(workspace, GATE_SITE_ID, variable_prefix);
        GateArgs {
            connection_export,
            passphrase_env,
            token_env,
            db_path: Some(workspace.join("sitecmd.db")),
            project_path: Some(project_path),
            threshold: "high".into(),
            strict: false,
            outputs: Some(workspace.join("outputs.txt")),
        }
    }

    /// A verdict as the gate door answers one, naming its new findings.
    fn gate_verdict(verdict: &str, new: u32) -> String {
        serde_json::json!({
            "verdict": verdict,
            "threshold": "high",
            "counts": { "new": new, "failing": if verdict == "fail" { new } else { 0 }, "warned": 0 },
            "new_findings": [],
            "warnings": [],
        })
        .to_string()
    }

    fn written_outputs(workspace: &std::path::Path) -> Option<String> {
        std::fs::read_to_string(workspace.join("outputs.txt")).ok()
    }

    #[tokio::test]
    async fn a_graded_gate_writes_its_verdict_and_new_count_for_the_workflow() {
        let (_repo, root, _head) = clean_checkout();
        for (verdict, new, code) in [("fail", 2, 1), ("pass", 0, 0)] {
            let workspace = tempfile::tempdir().expect("workspace");
            let args = gate_args(
                workspace.path(),
                &format!("SITECMD_TEST_GATE_{}", verdict.to_uppercase()),
                root.clone(),
            );
            let (origin, _captured) =
                respond_in_sequence(vec![(gate_verdict(verdict, new), "200 OK")]).await;

            let (exit, _summary) = run_gate_with(args, through(&origin))
                .await
                .expect("a graded gate");

            assert_eq!(exit, code, "{verdict}");
            assert_eq!(
                written_outputs(workspace.path()).as_deref(),
                Some(format!("verdict={verdict}\nnew={new}\n").as_str())
            );
        }
    }

    #[tokio::test]
    async fn a_gate_for_an_inactive_account_exits_zero_saying_nothing_was_graded() {
        let (_repo, root, _head) = clean_checkout();
        let workspace = tempfile::tempdir().expect("workspace");
        let args = gate_args(workspace.path(), "SITECMD_TEST_GATE_INACTIVE", root);
        let (origin, captured) =
            respond_in_sequence(vec![(ACCOUNT_INACTIVE_PROBLEM.into(), "403 Forbidden")]).await;

        let (code, output) = run_gate_with(args, through(&origin))
            .await
            .expect("an inactive account is not a failure");

        assert_eq!(code, 0);
        // The gate records nothing even for an active account, so its
        // sentence says what did not happen: grading.
        assert!(output.starts_with(ACCOUNT_INACTIVE_GATE_NOTICE), "{output}");
        // Its own verdict, so a workflow never reads a gate that did not run
        // as a pass; nothing was graded, so nothing was new.
        assert_eq!(
            written_outputs(workspace.path()).as_deref(),
            Some("verdict=inactive\nnew=0\n")
        );
        let requests = captured.await.expect("capture");
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert_eq!(
            request_line(&requests[0]),
            "POST /v1/sites/site_cli_gate/gate HTTP/1.1"
        );
    }

    #[tokio::test]
    async fn a_suspended_subscription_still_fails_the_gate() {
        let (_repo, root, _head) = clean_checkout();
        let workspace = tempfile::tempdir().expect("workspace");
        let args = gate_args(workspace.path(), "SITECMD_TEST_GATE_SUSPENDED", root);
        let (origin, _captured) = respond_in_sequence(vec![(
            ENTITLEMENT_SUSPENDED_PROBLEM.into(),
            "403 Forbidden",
        )])
        .await;

        let error = run_gate_with(args, through(&origin))
            .await
            .expect_err("a suspended subscription still fails the gate");

        assert!(
            error.starts_with("connected service entitlement_suspended:"),
            "{error}"
        );
        // A gate that could not run leaves no verdict for the workflow to read.
        assert_eq!(written_outputs(workspace.path()), None);
    }
}
