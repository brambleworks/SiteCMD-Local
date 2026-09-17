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
const MISSING_SECRETS_SUMMARY: &str = "The connection export or passphrase is missing or could not be decrypted; rotate the connection export from the SiteCMD app and update the repository secrets";

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
        // The note is the binary's own sentence either way: a check that ran
        // nothing still logs why, and its log names the checkout's own files
        // while the summary crosses back to SiteCMD.
        notes.push(
            if build.ran {
                "build passed"
            } else {
                "no build to run"
            }
            .to_string(),
        );
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
///
/// A failure answers with a reason built here rather than the underlying
/// error: it names the variable that is missing or says the export could not
/// be decrypted, and never any part of a value.
fn site_fingerprint_key(args: &RunJobArgs) -> Result<ProjectFingerprintKey, String> {
    let serialized = read_export(&args.export).map_err(|_| match &args.export {
        ExportSource::Env(name) => format!("{name} is missing or empty"),
        ExportSource::File(_) => "the connection export could not be read".to_string(),
    })?;
    let passphrase = read_env_secret(&args.passphrase_env)
        .map_err(|_| format!("{} is missing or empty", args.passphrase_env))?;
    let connection = decrypt_site_connection(&serialized, &passphrase)
        .map_err(|_| "could not decrypt the connection export".to_string())?;
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

    let key = match site_fingerprint_key(args) {
        Ok(key) => key,
        Err(reason) => {
            // The workflow reads `publish` whatever happens next, so it is
            // written before the report, which can fail on the network.
            refuse_publish(args)?;
            let result = failure_result(
                &manifest_for(&claimed),
                "secrets_missing",
                MISSING_SECRETS_SUMMARY.to_string(),
            );
            report_result(args, &claimed, &result, allow_http_loopback).await?;
            // SiteCMD is told the fixed sentence; the Actions log, which only
            // the repository's own people can read, is told which secret.
            return Ok((1, format!("{MISSING_SECRETS_SUMMARY}\n{reason}")));
        }
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
#[path = "run_job_tests.rs"]
mod tests;
