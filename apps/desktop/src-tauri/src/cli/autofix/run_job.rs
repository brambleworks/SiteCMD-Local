//! `sitecmd autofix run-job`: the untrusted half of a fix job. It claims the
//! job with the runner's own OIDC witness, applies the template fixes it can,
//! locates the code findings an agent will fix, proves the build, and leaves
//! the trusted publish job an artifact. It never holds an installation token.

use std::path::{Path, PathBuf};

use sitecmd_engine::sync::ProjectFingerprintKey;

use super::artifact::{
    has_something_to_publish, write_artifact, write_outputs, Manifest, ManifestFinding,
    ARTIFACT_SCHEMA_VERSION,
};
use super::brief::{brief_artifact, code_slug, locate_findings};
use super::redact;
use super::repo;
use super::secrets::{read_env_secret, read_export, ExportSource};
use crate::connected_export::decrypt_site_connection;
use crate::connected_service::deployment_ordering::CiSubmissionAttestation;
use crate::connected_service::{
    ClaimedJob, ConnectedServiceClient, FindingOutcomeReport, ResultReport,
};
use crate::core::fix_templates::build_check::BuildOutcome;
use crate::core::fix_templates::{apply, build_check, fixer_for, hosts, Finding, Patch};

/// What a job reports when it cannot read its own secrets. The fix never
/// started, so the summary names the repair instead of the failure, and it
/// names no variable the repository chose.
const MISSING_SECRETS_SUMMARY: &str = "The connection export or passphrase is missing or could not be decrypted; run sitecmd connect --rotate and update the repository secrets";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunJobArgs {
    pub job_id: String,
    pub connect_origin: String,
    pub export: ExportSource,
    pub passphrase_env: String,
    pub artifact_dir: PathBuf,
    pub outputs: Option<PathBuf>,
    pub path: PathBuf,
}

pub(super) fn parse(mut args: impl Iterator<Item = String>) -> Result<RunJobArgs, String> {
    let job_id = args
        .next()
        .filter(|id| super::is_job_id(id))
        .ok_or("run-job needs a job id like job_0123456789abcdef")?;
    let mut connect_origin = None;
    let mut export = None;
    let mut passphrase_env = "SITECMD_CONNECTION_PASSPHRASE".to_string();
    let mut artifact_dir = None;
    let mut outputs = None;
    let mut path = PathBuf::from(".");
    while let Some(token) = args.next() {
        match token.as_str() {
            "--connect-origin" => {
                connect_origin = Some(super::next_value(&mut args, "--connect-origin")?)
            }
            "--connection-export" => {
                export = Some(ExportSource::File(PathBuf::from(super::next_value(
                    &mut args,
                    "--connection-export",
                )?)))
            }
            "--connection-export-env" => {
                export = Some(ExportSource::Env(super::next_value(
                    &mut args,
                    "--connection-export-env",
                )?))
            }
            "--passphrase-env" => {
                passphrase_env = super::next_value(&mut args, "--passphrase-env")?
            }
            "--artifact-dir" => {
                artifact_dir = Some(PathBuf::from(super::next_value(
                    &mut args,
                    "--artifact-dir",
                )?))
            }
            "--outputs" => {
                outputs = Some(PathBuf::from(super::next_value(&mut args, "--outputs")?))
            }
            "--path" => path = PathBuf::from(super::next_value(&mut args, "--path")?),
            other => return Err(format!("Unknown option: {other}")),
        }
    }
    Ok(RunJobArgs {
        artifact_dir: artifact_dir.ok_or("run-job needs --artifact-dir")?,
        connect_origin: connect_origin.ok_or("run-job needs --connect-origin")?,
        export: export
            .ok_or("run-job needs --connection-export <path> or --connection-export-env <NAME>")?,
        job_id,
        outputs,
        passphrase_env,
        path,
    })
}

/// What one attempt produced: the artifact for the publish job, and the
/// result to report when there is nothing to publish.
#[derive(Debug)]
pub struct FixJobExecution {
    pub manifest: Manifest,
    pub patch: String,
    pub publish: bool,
    pub result: Option<ResultReport>,
}

fn manifest_for(claimed: &ClaimedJob) -> Manifest {
    Manifest {
        attempt: claimed.attempt,
        base_sha: claimed.base_sha.clone(),
        brief: None,
        findings: claimed
            .findings
            .iter()
            .map(|f| ManifestFinding {
                check_id: f.check_id.clone(),
                identity: f.identity.clone(),
                outcome: None,
            })
            .collect(),
        job_id: claimed.job_id.clone(),
        outcome_code: None,
        schema_version: ARTIFACT_SCHEMA_VERSION,
        summary: String::new(),
        write_set: Vec::new(),
    }
}

fn set_outcome(manifest: &mut Manifest, check_id: &str, identity: &str, outcome: &str) {
    if let Some(finding) = manifest
        .findings
        .iter_mut()
        .find(|f| f.check_id == check_id && f.identity == identity)
    {
        finding.outcome = Some(outcome.to_string());
    }
}

/// The attempt failed rather than declined. The result door refuses a finding
/// outcome under a failure code, so a failure carries the code alone.
fn failure_result(manifest: &Manifest, code: &str, summary: String) -> ResultReport {
    ResultReport {
        attempt: manifest.attempt,
        findings: Vec::new(),
        issue_number: None,
        outcome_code: code.to_string(),
        pull_request: None,
        summary,
        token_revoked: false,
    }
}

/// The attempt ran and published nothing, so every finding reports what it
/// reached. Nothing crossed to the publish job, so an outcome that claims a
/// pull request or an issue is reported as unsupported.
fn declined_result(manifest: &Manifest, code: &str, summary: String) -> ResultReport {
    ResultReport {
        attempt: manifest.attempt,
        findings: manifest
            .findings
            .iter()
            .map(|f| FindingOutcomeReport {
                check_id: f.check_id.clone(),
                identity: f.identity.clone(),
                outcome: match f.outcome.as_deref() {
                    None | Some("applied") | Some("issue_opened") => "unsupported".to_string(),
                    Some(outcome) => outcome.to_string(),
                },
            })
            .collect(),
        issue_number: None,
        outcome_code: code.to_string(),
        pull_request: None,
        summary,
        token_revoked: false,
    }
}

/// What a failed build tells SiteCMD: the step and its status, never the log.
/// The build's own output stays in the Actions run, which only the
/// repository's own people can read.
fn build_failure_summary(outcome: &BuildOutcome) -> String {
    match (outcome.failed_step, outcome.exit_status) {
        (Some(step), Some(status)) => {
            format!("Build failed at {step} with exit status {status}; see the Actions log")
        }
        (Some(step), None) => {
            format!("Build failed at {step} without an exit status; see the Actions log")
        }
        (None, _) => "Build failed before install; see the Actions log".to_string(),
    }
}

/// One attempt on a checkout, with no network of its own: template fixes
/// applied and proved by the build, code findings located for the brief, and
/// the manifest the publish job reads. Each build step reaches `out` as it
/// finishes, which is the workflow log a maintainer reads after a failure.
pub fn execute_fix_job(
    claimed: &ClaimedJob,
    root: &Path,
    key: Option<&ProjectFingerprintKey>,
    out: &mut dyn std::io::Write,
) -> Result<FixJobExecution, String> {
    let mut manifest = manifest_for(claimed);
    let head = repo::head_sha(root)?;
    if head != claimed.base_sha {
        manifest.outcome_code = Some("stale_base".into());
        manifest.summary = format!("checkout is at {head}, job expects {}", claimed.base_sha);
        let result = failure_result(&manifest, "stale_base", manifest.summary.clone());
        return Ok(FixJobExecution {
            manifest,
            patch: String::new(),
            publish: false,
            result: Some(result),
        });
    }

    let targets = hosts::detect(root);
    let mut patches: Vec<Patch> = Vec::new();
    let mut write_set: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut had_fixer = false;
    let mut wanted_code: Vec<(String, String)> = Vec::new();

    for finding in &claimed.findings {
        if code_slug(&finding.check_id).is_some() {
            had_fixer = true;
            wanted_code.push((finding.check_id.clone(), finding.identity.clone()));
            continue;
        }
        let Some(fixer) = fixer_for(&finding.check_id) else {
            set_outcome(
                &mut manifest,
                &finding.check_id,
                &finding.identity,
                "no_template",
            );
            notes.push(format!("{}: no template fixer", finding.check_id));
            continue;
        };
        had_fixer = true;
        let template_finding = Finding {
            check_id: finding.check_id.clone(),
            identity: finding.identity.clone(),
        };
        // The host the checkout declares first is the one a fix is planned
        // against; every answer it gives, including a refusal, is the answer.
        let planned =
            targets
                .first()
                .map(|target| match fixer.plan(&template_finding, target, root) {
                    Ok(Some(patch)) => Ok((patch, fixer.write_set(target))),
                    Ok(None) => Err(format!(
                        "{}: {} already sets it",
                        finding.check_id,
                        target.config_path.display()
                    )),
                    Err(unsupported) => {
                        Err(format!("{}: {}", finding.check_id, unsupported.reason))
                    }
                });
        match planned {
            Some(Ok((patch, allowed))) => {
                for path in allowed {
                    let text = path.to_string_lossy().to_string();
                    if !write_set.contains(&text) {
                        write_set.push(text);
                    }
                }
                patches.push(patch);
                set_outcome(
                    &mut manifest,
                    &finding.check_id,
                    &finding.identity,
                    "applied",
                );
            }
            Some(Err(reason)) => {
                set_outcome(
                    &mut manifest,
                    &finding.check_id,
                    &finding.identity,
                    "unsupported",
                );
                notes.push(reason);
            }
            None => {
                set_outcome(
                    &mut manifest,
                    &finding.check_id,
                    &finding.identity,
                    "unsupported",
                );
                notes.push(format!(
                    "{}: no recognized host configuration",
                    finding.check_id
                ));
            }
        }
    }

    if !wanted_code.is_empty() {
        match key {
            Some(key) => {
                let matches = locate_findings(root, key, &wanted_code)?;
                let brief = brief_artifact(&claimed.job_id, claimed.attempt, &matches);
                for (check_id, identity) in &wanted_code {
                    let located = brief
                        .findings
                        .iter()
                        .any(|f| &f.check_id == check_id && &f.identity == identity);
                    set_outcome(
                        &mut manifest,
                        check_id,
                        identity,
                        if located {
                            "issue_opened"
                        } else {
                            "unsupported"
                        },
                    );
                    if !located {
                        notes.push(format!("{check_id}: not present at {}", claimed.base_sha));
                    }
                }
                if brief.findings.iter().any(|f| !f.locations.is_empty()) {
                    manifest.brief = Some(brief);
                }
            }
            None => {
                for (check_id, identity) in &wanted_code {
                    set_outcome(&mut manifest, check_id, identity, "unsupported");
                    notes.push(format!("{check_id}: no fingerprint key to match locations"));
                }
            }
        }
    }

    let mut patch = String::new();
    if !patches.is_empty() {
        apply(&patches, root)?;
        repo::stage(root, &write_set)?;
        let build = build_check::run_build_check_with_output(root, out)?;
        if !build.success {
            manifest.outcome_code = Some("build_failed".into());
            manifest.summary = build_failure_summary(&build);
            manifest.write_set = write_set;
            let result = failure_result(&manifest, "build_failed", manifest.summary.clone());
            return Ok(FixJobExecution {
                manifest,
                patch: String::new(),
                publish: false,
                result: Some(result),
            });
        }
        notes.push(if build.ran {
            "build passed".into()
        } else {
            build.log.clone()
        });
        patch = repo::staged_patch(root)?;
    }
    manifest.write_set = write_set;
    manifest.summary = redact::summary(root, &notes.join("\n"));

    let publish = has_something_to_publish(&manifest, &patch);
    let result = if publish {
        None
    } else {
        let code = if had_fixer {
            "unsupported"
        } else {
            "no_template"
        };
        manifest.outcome_code = Some(code.into());
        Some(declined_result(&manifest, code, manifest.summary.clone()))
    };
    Ok(FixJobExecution {
        manifest,
        patch,
        publish,
        result,
    })
}

/// The checkout this job runs against, resolved once so every path the job
/// writes or redacts is absolute.
fn checkout_root(args: &RunJobArgs) -> Result<PathBuf, String> {
    std::fs::canonicalize(&args.path)
        .map_err(|error| format!("cannot resolve {}: {error}", args.path.display()))
}

/// The site's fingerprint key, copied out of the decrypted connection so
/// everything else the export carries is dropped where it was read.
fn site_fingerprint_key(args: &RunJobArgs) -> Result<ProjectFingerprintKey, String> {
    let serialized = read_export(&args.export)?;
    let passphrase = read_env_secret(&args.passphrase_env)?;
    let connection = decrypt_site_connection(&serialized, &passphrase)?;
    let key = ProjectFingerprintKey::from_bytes(connection.fingerprint_key);
    drop(connection);
    Ok(key)
}

/// Report one result under the execute token and answer with the state the
/// job moved to.
async fn report_result(
    args: &RunJobArgs,
    claimed: &ClaimedJob,
    result: &ResultReport,
    allow_http_loopback: bool,
) -> Result<String, String> {
    let job_client = ConnectedServiceClient::for_endpoint(
        &args.connect_origin,
        Some(&claimed.job_token),
        allow_http_loopback,
    )?;
    job_client
        .report_job_result(&claimed.job_id, result)
        .await
        .map(|receipt| receipt.state)
        .map_err(|error| format!("result refused: {} ({})", error.code, error.message))
}

/// `publish=false` for the workflow, whenever the step was asked for it.
fn refuse_publish(args: &RunJobArgs) -> Result<(), String> {
    match &args.outputs {
        Some(outputs) => write_outputs(outputs, false),
        None => Ok(()),
    }
}

/// Claim this job with the runner's witness, run the attempt and leave the
/// publish job an artifact, or report why there is nothing to publish.
pub async fn run(args: &RunJobArgs) -> Result<(u8, String), String> {
    // A checkout that cannot be resolved must not cost the job an attempt,
    // so the path is proved before the claim.
    checkout_root(args)?;
    let claim_client = ConnectedServiceClient::for_origin(&args.connect_origin, None)?;
    let witness = claim_client
        .github_actions_oidc_token(CiSubmissionAttestation::GithubOidc)
        .await?
        .ok_or("run-job runs inside GitHub Actions with id-token: write")?;
    run_with_witness(args, &witness, false).await
}

/// Everything from the claim onward, with the witness already in hand.
/// `allow_http_loopback` is what lets the wire test point both clients at a
/// local double; the command itself always passes `false`.
pub(crate) async fn run_with_witness(
    args: &RunJobArgs,
    witness: &str,
    allow_http_loopback: bool,
) -> Result<(u8, String), String> {
    let root = checkout_root(args)?;
    let claim_client =
        ConnectedServiceClient::for_endpoint(&args.connect_origin, None, allow_http_loopback)?;
    let claimed = match claim_client
        .claim_job(&args.job_id, "execute", witness)
        .await
    {
        Ok(claimed) => claimed,
        // The job already moved on, so this run has nothing to do and nothing
        // has gone wrong.
        Err(error) if error.status == 409 => {
            refuse_publish(args)?;
            return Ok((
                0,
                format!(
                    "job {} is not waiting for an execute claim; nothing to do",
                    args.job_id
                ),
            ));
        }
        Err(error) => return Err(format!("claim refused: {} ({})", error.code, error.message)),
    };

    let Ok(key) = site_fingerprint_key(args) else {
        let result = failure_result(
            &manifest_for(&claimed),
            "secrets_missing",
            MISSING_SECRETS_SUMMARY.to_string(),
        );
        report_result(args, &claimed, &result, allow_http_loopback).await?;
        refuse_publish(args)?;
        return Ok((1, MISSING_SECRETS_SUMMARY.to_string()));
    };

    // The build's output belongs in the workflow log as each step finishes,
    // and the lock is released before the result goes back over the network.
    let execution = {
        let mut log = std::io::stdout().lock();
        execute_fix_job(&claimed, &root, Some(&key), &mut log)?
    };
    write_artifact(&args.artifact_dir, &execution.manifest, &execution.patch)?;
    if let Some(outputs) = &args.outputs {
        write_outputs(outputs, execution.publish)?;
    }

    let mut summary = execution.manifest.summary.clone();
    let mut code = 0_u8;
    if let Some(result) = &execution.result {
        let state = report_result(args, &claimed, result, allow_http_loopback).await?;
        summary.push_str(&format!(
            "\nreported {} for {}; job is {state}",
            result.outcome_code, claimed.job_id
        ));
        if matches!(result.outcome_code.as_str(), "build_failed" | "stale_base") {
            code = 1;
        }
    } else {
        summary.push_str(&format!(
            "\nartifact ready for the publish job of {}",
            claimed.job_id
        ));
    }
    Ok((code, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::autofix::repo::init_test_repo;
    use crate::connected_service::test_double::respond_in_sequence;
    use crate::connected_service::{ClaimedFinding, ClaimedJob};
    use sitecmd_engine::sync::ProjectFingerprintKey;

    const CLAIM: &str = r#"{"job_id":"job_0123456789abcdef","attempt":1,"purpose":"execute","job_token":"sitecmd_job_execute_00000000000000000000000000000000","expires_at":"2026-09-20T10:30:00.000Z","base_sha":"0123456789abcdef0123456789abcdef01234567","site_url":"https://loop.example.com","repository":"example-org/example-site","default_branch":"main","agent":"claude","findings":[{"check_id":"security.headers.x_content_type_options","identity":"/","class":"template","category":"security","fallback_class":null}]}"#;

    const RESULT_RECEIPT: &str = r#"{"job_id":"job_0123456789abcdef","state":"blocked"}"#;

    fn claimed(base_sha: &str, findings: Vec<ClaimedFinding>) -> ClaimedJob {
        ClaimedJob {
            agent: "claude".into(),
            attempt: 1,
            base_sha: base_sha.into(),
            committer: None,
            default_branch: "main".into(),
            expires_at: "x".into(),
            findings,
            job_id: "job_0123456789abcdef".into(),
            job_token: "sitecmd_job_execute_00000000000000000000000000000000".into(),
            opt_in_fixers: vec![],
            previous_failure: None,
            purpose: "execute".into(),
            repository: "example-org/example-site".into(),
            site_url: "https://loop.example.com".into(),
        }
    }

    fn header_finding() -> ClaimedFinding {
        ClaimedFinding {
            category: "security".into(),
            check_id: "security.headers.x_content_type_options".into(),
            class: "template".into(),
            fallback_class: None,
            identity: "/".into(),
        }
    }

    const ROUTE: &str = "export async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const returnTo = searchParams.get(\"returnTo\") ?? \"/\";\n  return Response.redirect(new URL(returnTo, request.url), 302);\n}\n";

    #[test]
    fn a_template_finding_becomes_a_staged_patch_for_the_publish_job() {
        let (repo, head) = init_test_repo(&[
            ("vercel.json", "{\n  \"cleanUrls\": true\n}\n"),
            ("package.json", "{\"name\":\"loop\"}"),
        ])
        .unwrap();
        let execution = execute_fix_job(
            &claimed(&head, vec![header_finding()]),
            repo.path(),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(execution.publish);
        assert!(execution.result.is_none());
        assert!(
            execution.patch.contains("+++ b/vercel.json"),
            "{}",
            execution.patch
        );
        assert!(execution.patch.contains("nosniff"));
        assert_eq!(
            execution.manifest.write_set,
            vec!["vercel.json".to_string()]
        );
        assert_eq!(
            execution.manifest.findings[0].outcome.as_deref(),
            Some("applied")
        );
        assert_eq!(execution.manifest.outcome_code, None);
        assert_eq!(execution.manifest.base_sha, head);
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_build_reports_build_failed_and_publishes_nothing() {
        let (repo, head) = init_test_repo(&[
            ("vercel.json", "{}\n"),
            (
                "package.json",
                "{\"scripts\":{\"build\":\"node -e \\\"console.error('refused'); process.exit(1)\\\"\"}}",
            ),
        ])
        .unwrap();
        let mut log = Vec::new();
        let execution = execute_fix_job(
            &claimed(&head, vec![header_finding()]),
            repo.path(),
            None,
            &mut log,
        )
        .unwrap();
        assert!(!execution.publish);
        let result = execution.result.expect("a result to report");
        assert_eq!(result.outcome_code, "build_failed");
        assert_eq!(
            result.summary,
            "Build failed at build with exit status 1; see the Actions log"
        );
        assert!(!result.summary.contains("refused"));
        assert!(result.findings.is_empty());
        assert!(String::from_utf8_lossy(&log).contains("refused"));
        assert_eq!(
            execution.manifest.outcome_code.as_deref(),
            Some("build_failed")
        );
        assert!(execution.patch.is_empty());
    }

    #[test]
    fn a_checkout_not_at_the_base_sha_is_stale() {
        let (repo, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
        let execution = execute_fix_job(
            &claimed(&"1".repeat(40), vec![header_finding()]),
            repo.path(),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(execution.result.unwrap().outcome_code, "stale_base");
        assert!(!execution.publish);
    }

    #[test]
    fn an_agent_finding_becomes_a_brief_with_its_location() {
        let (repo, head) = init_test_repo(&[
            ("package.json", "{\"name\":\"loop\"}"),
            ("app/api/signin/route.ts", ROUTE),
        ])
        .unwrap();
        let key = ProjectFingerprintKey::from_bytes([7_u8; 32]);
        let identity = key.location_hash("open-redirect", "app/api/signin/route.ts");
        let finding = ClaimedFinding {
            category: "security".into(),
            check_id: "code_scan.open-redirect".into(),
            class: "agent-easy".into(),
            fallback_class: None,
            identity,
        };
        let execution = execute_fix_job(
            &claimed(&head, vec![finding]),
            repo.path(),
            Some(&key),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(execution.publish);
        assert!(execution.patch.is_empty());
        let brief = execution.manifest.brief.expect("brief");
        assert_eq!(
            brief.findings[0].locations[0].path,
            "app/api/signin/route.ts"
        );
        assert_eq!(
            execution.manifest.findings[0].outcome.as_deref(),
            Some("issue_opened")
        );
    }

    #[test]
    fn a_finding_without_a_fixer_is_declined_with_a_result() {
        let (repo, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
        let finding = ClaimedFinding {
            category: "security".into(),
            check_id: "security.headers.hsts".into(),
            class: "template".into(),
            fallback_class: None,
            identity: "/".into(),
        };
        let execution = execute_fix_job(
            &claimed(&head, vec![finding]),
            repo.path(),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!execution.publish);
        assert_eq!(execution.result.unwrap().outcome_code, "no_template");
    }

    #[tokio::test]
    async fn the_command_claims_then_reports_missing_secrets() {
        let (repo, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let artifact_dir = workspace.path().join("artifact");
        let outputs = workspace.path().join("outputs.txt");
        let (origin, captured) =
            respond_in_sequence(vec![(CLAIM, "200 OK"), (RESULT_RECEIPT, "200 OK")]).await;
        let args = RunJobArgs {
            artifact_dir: artifact_dir.clone(),
            connect_origin: origin,
            export: ExportSource::Env("SITECMD_TEST_RUN_JOB_MISSING_EXPORT".into()),
            job_id: "job_0123456789abcdef".into(),
            outputs: Some(outputs.clone()),
            passphrase_env: "SITECMD_TEST_RUN_JOB_MISSING_PASSPHRASE".into(),
            path: repo.path().to_path_buf(),
        };

        let (code, summary) = run_with_witness(&args, "witness-token", true)
            .await
            .expect("the command to report rather than fail");

        assert_eq!(code, 1);
        assert_eq!(summary, MISSING_SECRETS_SUMMARY);
        assert_eq!(
            std::fs::read_to_string(&outputs).expect("outputs"),
            "publish=false\n"
        );
        assert!(!artifact_dir.join("manifest.json").exists());

        let requests = captured.await.expect("capture");
        assert_eq!(requests.len(), 2);
        let claim = requests[0].to_ascii_lowercase();
        assert!(
            claim.starts_with("post /v1/fix-jobs/job_0123456789abcdef/claim http/1.1"),
            "{claim}"
        );
        assert!(
            claim.contains("x-github-oidc-token: witness-token\r\n"),
            "{claim}"
        );
        assert!(!claim.contains("authorization:"), "{claim}");
        assert!(claim.ends_with(r#"{"purpose":"execute"}"#), "{claim}");
        let report = requests[1].to_ascii_lowercase();
        assert!(
            report.starts_with("post /v1/fix-jobs/job_0123456789abcdef/result http/1.1"),
            "{report}"
        );
        assert!(
            report.contains(
                "authorization: bearer sitecmd_job_execute_00000000000000000000000000000000\r\n"
            ),
            "{report}"
        );
        assert!(
            requests[1].contains(r#""outcome_code":"secrets_missing""#),
            "{}",
            requests[1]
        );
        assert!(requests[1].contains(r#""findings":[]"#), "{}", requests[1]);
        assert!(
            requests[1].contains(MISSING_SECRETS_SUMMARY),
            "{}",
            requests[1]
        );
    }
}
