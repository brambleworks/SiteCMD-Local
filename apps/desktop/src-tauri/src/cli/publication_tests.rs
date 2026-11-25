use super::*;
use crate::cli::autofix::{artifact, brief, brief_publish, exit_check, publish_job, template_plan};
use crate::connected_ci::{ci_submission_body, DeploymentFacts};
use crate::connected_export::ImportedSiteConnection;
use crate::connected_service::ClaimedJob;
use crate::core::audit::{audit_project, CodeIssue, CodeScanReport};
use crate::db::Database;
use sitecmd_protocol::engine_abi::{Brief, FixTextTarget};
use sitecmd_protocol::sync::ProjectFingerprintKey;
use std::path::Path;

#[test]
fn standin_publication_omits_source_from_reports_prompts_and_briefs() {
    // A module finding or suppression can carry checkout source into published output.
    let root = tempfile::tempdir().unwrap();
    let path = "fixture-evidence.txt";
    let markers = ["PRIVATE_FIXTURE_EXCERPT_8zKx", "PRIVATE_FIXTURE_EXCERPT"];
    let source = format!("\n{}\n", markers[0]);
    std::fs::write(root.path().join(path), &source).unwrap();
    let report = audit_project(root.path()).unwrap();
    assert_eq!(report.issues.len(), 1);
    let issue = &report.issues[0];
    assert_eq!(issue.relative_path, path);
    assert_eq!(issue.line, Some(2));
    assert_eq!(issue.evidence.as_deref(), Some(markers[0]));
    assert_eq!(
        [
            Some(issue.title.as_str()),
            Some(issue.description.as_str()),
            issue.why_now.as_deref(),
            issue.likely_fix.as_deref(),
            issue.verify_hint.as_deref(),
            issue.confidence_reason.as_deref(),
        ],
        [Some(markers[0]); 6],
        "the raw module finding must carry the marker in every prose field"
    );

    let mut outputs = Vec::new();
    collect_report_outputs(root.path(), &report, &mut outputs);
    collect_autofix_outputs(root.path(), issue, &source, markers[0], &mut outputs);
    collect_connected_outputs(root.path(), &mut outputs);

    let config = root.path().join(".sitecmd/config.json");
    std::fs::create_dir(config.parent().unwrap()).unwrap();
    std::fs::write(
        config,
        serde_json::json!({
            "version": 1, "url": "https://example.com", "name": "canary",
            "code_scan": { "suppressions": [{
                "match": { "rule": "code_scan.standin.rule" }, "reason": markers[0]
            }] }
        })
        .to_string(),
    )
    .unwrap();
    for &(format, name) in CodeScanReportFormat::ALL {
        let mut args = report_args(root.path(), format);
        args.fail_on = Some(Severity::Low);
        let outcome = run_with_output(&args, output_context(false, true)).unwrap();
        assert!(
            !outcome.threshold_failed,
            "suppression must apply in {name}"
        );
        outputs.push((format!("suppressed CI {name}"), outcome.rendered));
    }

    let leaked: Vec<_> = outputs
        .iter()
        .filter(|(_, output)| markers.iter().any(|marker| output.contains(marker)))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        leaked.is_empty(),
        "customer source escaped through: {leaked:?}"
    );
}

fn report_args(root: &Path, format: CodeScanReportFormat) -> AuditArgs {
    AuditArgs {
        project_path: root.into(),
        format,
        fail_on: None,
        output: None,
        inspect_local_databases: false,
        baseline: None,
    }
}

fn output_context(terminal: bool, ci: bool) -> super::super::output::OutputContext {
    super::super::output::OutputContext { terminal, ci }
}

fn collect_report_outputs(
    root: &Path,
    report: &CodeScanReport,
    outputs: &mut Vec<(String, String)>,
) {
    let engine = sitecmd_engine_host::load().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    for &(format, name) in CodeScanReportFormat::ALL {
        let rendered = format_report(report, engine.info(), root, format).unwrap();
        assert!(rendered.contains("fixture-evidence.txt"));
        outputs.push((format!("format_report {name}"), rendered));
        let mut args = report_args(root, format);
        for (terminal, ci) in [(false, false), (false, true), (true, true), (true, false)] {
            let rendered = run_with_output(&args, output_context(terminal, ci))
                .unwrap()
                .rendered;
            assert!(rendered.contains("fixture-evidence.txt"));
            outputs.push((format!("CLI {name} terminal={terminal} ci={ci}"), rendered));
        }
        let file = output_dir.path().join(name);
        args.output = Some(file.clone());
        run_with_output(&args, output_context(true, false)).unwrap();
        outputs.push((
            format!("--output {name}"),
            std::fs::read_to_string(file).unwrap(),
        ));
    }
}

fn collect_autofix_outputs(
    root: &Path,
    issue: &CodeIssue,
    source: &str,
    marker: &str,
    outputs: &mut Vec<(String, String)>,
) {
    let prompt = crate::core::fixes::one_fix_text(FixTextTarget::Code {
        issue: Box::new(issue.clone()),
        framework: "fixture".into(),
    })
    .unwrap();
    assert!(!prompt.is_empty());
    outputs.push(("code fix prompt".into(), prompt));

    let key = ProjectFingerprintKey::from_bytes([7; 32]);
    let identity = key.location_hash("standin.rule", &issue.relative_path);
    let check_id = "code_scan.standin.rule";
    let matched =
        brief::locate_findings(root, &key, &[(check_id.into(), identity.clone())]).unwrap();
    let brief = brief::brief_artifact("job_0123456789abcdef", 1, &matched);
    outputs.push((
        "brief artifact".into(),
        serde_json::to_string(&brief).unwrap(),
    ));
    let claimed: ClaimedJob = serde_json::from_value(serde_json::json!({
        "agent":"claude", "attempt":1, "base_sha":"a".repeat(40), "default_branch":"main",
        "expires_at":"x", "job_id":brief.job_id, "job_token":"test", "purpose":"publish",
        "repository":"example/site", "site_url":"https://example.com",
        "findings":[{"category":"operations","check_id":check_id,"class":"agent-easy","identity":identity}]
    }))
    .unwrap();
    let mut handed = exit_check::HandedLines::default();
    let verified = brief_publish::verify_brief(root, &brief, &mut handed).unwrap();
    assert_eq!(verified.len(), 1);
    outputs.push((
        "verified finding".into(),
        serde_json::to_string(&verified[0].issue).unwrap(),
    ));
    let (rendered, target) = brief_publish::render_issue(&claimed, &verified, None).unwrap();
    outputs.push((
        "brief renderer input".into(),
        serde_json::to_string(&target).unwrap(),
    ));
    assert!(rendered.body.contains("`fixture-evidence.txt:2`"));
    let checked = exit_check::check_brief(rendered.clone(), &handed, &[]).unwrap();
    outputs.push((
        "checked fix brief".into(),
        format!("{}\n{}", checked.title, checked.body),
    ));
    let Brief { title, body } = exit_check::check_hosted_brief(rendered, &handed, &target).unwrap();
    outputs.push(("GitHub issue".into(), format!("{title}\n{body}")));

    let manifest = artifact::Manifest {
        schema_version: artifact::ARTIFACT_SCHEMA_VERSION,
        job_id: brief.job_id.clone(),
        attempt: 1,
        base_sha: claimed.base_sha.clone(),
        outcome_code: None,
        write_set: vec![],
        findings: vec![artifact::ManifestFinding {
            check_id: check_id.into(),
            identity,
            outcome: Some("issue_opened".into()),
        }],
        brief: Some(brief),
    };
    let dir = tempfile::tempdir().unwrap();
    artifact::write_artifact(dir.path(), &manifest, "").unwrap();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        outputs.push((
            format!("artifact {}", entry.file_name().to_string_lossy()),
            std::fs::read_to_string(entry.path()).unwrap(),
        ));
    }
    artifact::write_artifact(dir.path(), &manifest, source).unwrap();
    outputs.push((
        "patch.diff".into(),
        std::fs::read_to_string(dir.path().join("patch.diff")).unwrap(),
    ));

    let mut changed = issue.clone();
    changed.evidence = Some("different fixture evidence".into());
    assert_eq!(
        super::super::audit_suppressions::issue_fingerprint(issue),
        super::super::audit_suppressions::issue_fingerprint(&changed)
    );
    let mut pull_request = manifest;
    pull_request.findings[0].outcome = Some("applied".into());
    let (title, body) =
        publish_job::pull_request_text(&claimed, &pull_request, &template_plan::catalog().unwrap());
    assert!(body.contains(check_id));
    assert!(body.contains(&pull_request.findings[0].identity));
    outputs.push(("GitHub pull request".into(), format!("{title}\n{body}")));
    let mut tampered = pull_request;
    tampered.findings[0].outcome = Some(marker.into());
    assert!(publish_job::manifest_matches_claim(&tampered, &claimed).is_err());
    outputs.push((
        "connected job outcomes".into(),
        serde_json::to_string(&publish_job::finding_reports(&tampered, marker)).unwrap(),
    ));
}

fn collect_connected_outputs(root: &Path, outputs: &mut Vec<(String, String)>) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(dir.path().join("canary.db")).unwrap();
    let connection = ImportedSiteConnection {
        site_id: "site_canary".into(),
        environment_scope_key: "https://example.com".into(),
        fingerprint_key_version: 1,
        fingerprint_key: [7; 32],
    };
    let audit = super::super::connected::scan_this_checkout(&db, &connection, Some(root)).unwrap();
    let snapshot =
        super::super::connected::build_candidate_snapshot(&db, &connection, &audit, None).unwrap();
    assert_eq!(snapshot.occurrences.len(), 1);
    assert_eq!(snapshot.occurrences[0].check, "code_scan.standin.rule");
    outputs.push((
        "connected gate".into(),
        serde_json::to_string(&snapshot).unwrap(),
    ));
    outputs.push((
        "connected submission".into(),
        ci_submission_body(
            &connection.site_id,
            &snapshot,
            &DeploymentFacts {
                provider_deployment_id: "run_canary".parse().unwrap(),
                commit_sha: "a".repeat(40).parse().unwrap(),
                git_ref: None,
                target: None,
                previous_sha: None,
                provider_created_at: None,
                published: false,
                ordering: None,
            },
        )
        .unwrap(),
    ));
}
