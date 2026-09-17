//! `sitecmd autofix publish-job`: the trusted half of a fix job. It runs on a
//! fresh runner inside SiteCMD's reusable workflow, claims the job with its
//! own OIDC witness, checks the artifact against the binary's own write set
//! and its own checkout, and is the only place a repository write token
//! exists. It runs no command the repository controls.

use std::path::{Path, PathBuf};

use super::artifact::{read_artifact, Manifest};
use super::github_api::GitHubApi;
use super::redact;
use super::repo;
use crate::connected_service::deployment_ordering::CiSubmissionAttestation;
use crate::connected_service::{
    ClaimedJob, ConnectedServiceClient, FindingOutcomeReport, PullRequestReport, ResultReport,
};
use crate::core::fix_templates::{fixer_for, hosts, slug};
use crate::core::git::HttpsTransport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishJobArgs {
    pub job_id: String,
    pub connect_origin: String,
    pub artifact_dir: PathBuf,
    pub path: PathBuf,
}

pub(super) fn parse(mut args: impl Iterator<Item = String>) -> Result<PublishJobArgs, String> {
    let job_id = args
        .next()
        .filter(|id| super::is_job_id(id))
        .ok_or("publish-job needs a job id like job_0123456789abcdef")?;
    let mut connect_origin = None;
    let mut artifact_dir = None;
    let mut path = PathBuf::from(".");
    while let Some(token) = args.next() {
        match token.as_str() {
            "--connect-origin" => {
                connect_origin = Some(super::next_value(&mut args, "--connect-origin")?)
            }
            "--artifact-dir" => {
                artifact_dir = Some(PathBuf::from(super::next_value(
                    &mut args,
                    "--artifact-dir",
                )?))
            }
            "--path" => path = PathBuf::from(super::next_value(&mut args, "--path")?),
            other => return Err(format!("Unknown option: {other}")),
        }
    }
    Ok(PublishJobArgs {
        artifact_dir: artifact_dir.ok_or("publish-job needs --artifact-dir")?,
        connect_origin: connect_origin.ok_or("publish-job needs --connect-origin")?,
        job_id,
        path,
    })
}

/// The checkout this job publishes from, resolved once so every path it
/// redacts is absolute.
fn checkout_root(args: &PublishJobArgs) -> Result<PathBuf, String> {
    std::fs::canonicalize(&args.path)
        .map_err(|error| format!("cannot resolve {}: {error}", args.path.display()))
}

/// The artifact crossed an untrusted boundary, so it has to name the very job,
/// attempt and base commit this runner just claimed.
pub fn manifest_matches_claim(manifest: &Manifest, claimed: &ClaimedJob) -> Result<(), String> {
    if manifest.job_id != claimed.job_id {
        return Err("manifest names another job id".into());
    }
    if manifest.base_sha != claimed.base_sha {
        return Err("manifest names another base sha".into());
    }
    if manifest.attempt != claimed.attempt {
        return Err("manifest names another attempt".into());
    }
    Ok(())
}

/// Every file the claimed checks are allowed to touch, derived from the job's
/// check ids and the binary's own fixers. The artifact never contributes: a
/// write set it named would be the patch vouching for itself.
pub fn allowed_write_set(claimed: &ClaimedJob, root: &Path) -> Vec<String> {
    let targets = hosts::detect(root);
    let mut allowed: Vec<String> = Vec::new();
    for finding in &claimed.findings {
        if let Some(fixer) = fixer_for(&finding.check_id) {
            for target in &targets {
                for path in fixer.write_set(target) {
                    let text = path.to_string_lossy().to_string();
                    if !allowed.contains(&text) {
                        allowed.push(text);
                    }
                }
            }
        }
    }
    allowed
}

/// A path outside the allowed set is a violation, and so is anything under
/// `.github/workflows/` whatever the set says: a fix must never rewrite the
/// workflow that runs it.
pub fn write_set_violations(changed: &[String], allowed: &[String]) -> Vec<String> {
    changed
        .iter()
        .filter(|path| path.starts_with(".github/workflows/") || !allowed.contains(path))
        .cloned()
        .collect()
}

pub fn branch_name(claimed: &ClaimedJob) -> String {
    let first = claimed
        .findings
        .iter()
        .find(|f| fixer_for(&f.check_id).is_some())
        .or(claimed.findings.first());
    let short = claimed
        .job_id
        .strip_prefix("job_")
        .unwrap_or(&claimed.job_id)
        .chars()
        .take(6)
        .collect::<String>();
    format!(
        "sitecmd/{}-{short}",
        first.map_or_else(|| "fix".to_string(), |f| slug(&f.check_id))
    )
}

pub fn pull_request_text(claimed: &ClaimedJob, manifest: &Manifest) -> (String, String) {
    let title = claimed
        .findings
        .iter()
        .find_map(|f| fixer_for(&f.check_id).map(|fixer| fixer.title().to_string()))
        .unwrap_or_else(|| "Apply SiteCMD template fixes".to_string());
    let mut body = String::from(
        "SiteCMD found the following on the production site and fixed it in the repository:\n\n",
    );
    for finding in manifest
        .findings
        .iter()
        .filter(|f| f.outcome.as_deref() == Some("applied"))
    {
        body.push_str(&format!(
            "- `{}` at `{}`\n",
            finding.check_id, finding.identity
        ));
    }
    body.push_str(&format!(
        "\nSiteCMD verifies this change on the preview deployment before you merge. Job `{}`.\n",
        claimed.job_id
    ));
    (title, body)
}

/// What each finding reached. `published` is the outcome the ones this run
/// actually published carry, so a run that published nothing reports them all
/// as unsupported rather than claiming a pull request it never opened.
pub fn finding_reports(manifest: &Manifest, published: &str) -> Vec<FindingOutcomeReport> {
    manifest
        .findings
        .iter()
        .map(|f| FindingOutcomeReport {
            check_id: f.check_id.clone(),
            identity: f.identity.clone(),
            outcome: match f.outcome.as_deref() {
                Some("applied") | Some("issue_opened") => published.to_string(),
                Some(other) => other.to_string(),
                None => "unsupported".to_string(),
            },
        })
        .collect()
}

fn report(
    attempt: u32,
    code: &str,
    summary: String,
    findings: Vec<FindingOutcomeReport>,
    pull_request: Option<PullRequestReport>,
    issue_number: Option<u64>,
    token_revoked: bool,
) -> ResultReport {
    ResultReport {
        attempt,
        findings,
        issue_number,
        outcome_code: code.to_string(),
        pull_request,
        summary,
        token_revoked,
    }
}

/// Apply the fix job's patch and publish it: the paths it touches checked
/// against the binary's write set, the commit made as the App's bot, the
/// branch pushed with a per-operation installation token, the pull request
/// opened, and the token handed back before anything is reported.
async fn publish_patch(
    args: &PublishJobArgs,
    root: &Path,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    job_client: &ConnectedServiceClient,
) -> Result<(u8, ResultReport), String> {
    let patch_path = args.artifact_dir.join("patch.diff");
    let changed = repo::patch_paths(root, &patch_path)?;
    let violations = write_set_violations(&changed, &allowed_write_set(claimed, root));
    let declined = |code: &str, summary: String| {
        (
            1_u8,
            report(
                claimed.attempt,
                code,
                redact::summary(root, &summary),
                finding_reports(manifest, "unsupported"),
                None,
                None,
                true,
            ),
        )
    };
    if !violations.is_empty() {
        return Ok(declined(
            "patch_rejected",
            format!(
                "patch reaches outside the fixer's write set: {}",
                violations.join(", ")
            ),
        ));
    }
    if let Err(error) = repo::apply_patch(root, &patch_path) {
        return Ok(declined("patch_rejected", error));
    }
    let committer = claimed
        .committer
        .as_ref()
        .ok_or("publish claim carried no committer")?;
    let (title, body) = pull_request_text(claimed, manifest);
    let head_sha = repo::commit(root, &changed, &committer.name, &committer.email, &title)?;
    let branch = branch_name(claimed);
    let minted = job_client
        .publish_token(&claimed.job_id)
        .await
        .map_err(|error| format!("publish token refused: {} ({})", error.code, error.message))?;
    let transport = HttpsTransport::for_token(&minted.token);
    let api = GitHubApi::new();
    let remote = format!("https://github.com/{}.git", claimed.repository);
    let pushed = if repo::is_shallow(root) {
        repo::unshallow(root, &transport)
    } else {
        Ok(())
    }
    .and_then(|_| repo::push_branch(root, &remote, &branch, &transport));
    let outcome = match pushed {
        Err(error) => Err(("push_failed", error)),
        Ok(()) => match api
            .create_pull_request(
                &minted.token,
                &claimed.repository,
                &branch,
                &claimed.default_branch,
                &title,
                &body,
            )
            .await
        {
            Ok(created) => Ok(created),
            Err(error) => Err((
                "push_failed",
                format!("branch pushed, pull request refused: {error}"),
            )),
        },
    };
    let revoked = api.revoke_installation_token(&minted.token).await;
    match outcome {
        Ok(created) => Ok((
            0,
            report(
                claimed.attempt,
                "applied",
                redact::summary(root, &format!("opened pull request #{}", created.number)),
                finding_reports(manifest, "applied"),
                Some(PullRequestReport {
                    branch,
                    head_sha: if created.head_sha.is_empty() {
                        head_sha
                    } else {
                        created.head_sha
                    },
                    number: created.number,
                }),
                None,
                revoked,
            ),
        )),
        Err((code, error)) => Ok((
            1,
            report(
                claimed.attempt,
                code,
                redact::summary(root, &error),
                finding_reports(manifest, "unsupported"),
                None,
                None,
                revoked,
            ),
        )),
    }
}

/// Claim this job with the runner's own witness, publish what the fix job
/// left, and report the outcome.
pub async fn run(args: &PublishJobArgs) -> Result<(u8, String), String> {
    // A checkout that cannot be resolved must not cost the job an attempt,
    // so the path is proved before the claim.
    checkout_root(args)?;
    let claim_client = ConnectedServiceClient::for_origin(&args.connect_origin, None)?;
    let witness = claim_client
        .github_actions_oidc_token(CiSubmissionAttestation::GithubOidc)
        .await?
        .ok_or("publish-job runs inside GitHub Actions with id-token: write")?;
    run_with_witness(args, &witness, false).await
}

/// Everything from the claim onward, with the witness already in hand.
/// `allow_http_loopback` is what lets the wire tests point both clients at a
/// local double; the command itself always passes `false`.
pub(crate) async fn run_with_witness(
    args: &PublishJobArgs,
    witness: &str,
    allow_http_loopback: bool,
) -> Result<(u8, String), String> {
    let root = checkout_root(args)?;
    let claim_client =
        ConnectedServiceClient::for_endpoint(&args.connect_origin, None, allow_http_loopback)?;
    let claimed = claim_client
        .claim_job(&args.job_id, "publish", witness)
        .await
        .map_err(|error| format!("publish claim refused: {} ({})", error.code, error.message))?;
    // The runner writes only what it can see, and it can only see its own
    // checkout, so a checkout that is not the commit the claim names is
    // refused before the artifact is even read.
    let head = repo::head_sha(&root)?;
    if head != claimed.base_sha {
        return Err(format!(
            "refusing to publish: checkout is at {head}, the claim names {}",
            claimed.base_sha
        ));
    }
    let job_client = ConnectedServiceClient::for_endpoint(
        &args.connect_origin,
        Some(&claimed.job_token),
        allow_http_loopback,
    )?;
    let (manifest, patch) = read_artifact(&args.artifact_dir)?;
    let (code, result) = match manifest_matches_claim(&manifest, &claimed) {
        Err(reason) => (
            1,
            report(
                claimed.attempt,
                "patch_rejected",
                reason,
                finding_reports(&manifest, "unsupported"),
                None,
                None,
                true,
            ),
        ),
        Ok(()) if !patch.trim().is_empty() => {
            publish_patch(args, &root, &claimed, &manifest, &job_client).await?
        }
        // Publishing an agent's brief as an issue arrives with the agent path.
        Ok(()) if manifest.brief.is_some() => (
            1,
            report(
                claimed.attempt,
                "brief_rejected",
                "agent publication arrives in the next task".into(),
                finding_reports(&manifest, "unsupported"),
                None,
                None,
                true,
            ),
        ),
        Ok(()) => (
            1,
            report(
                claimed.attempt,
                "unsupported",
                "artifact carries nothing to publish".into(),
                finding_reports(&manifest, "unsupported"),
                None,
                None,
                true,
            ),
        ),
    };
    let receipt = job_client
        .report_job_result(&claimed.job_id, &result)
        .await
        .map_err(|error| format!("result refused: {} ({})", error.code, error.message))?;
    Ok((
        code,
        format!(
            "{}\nreported {} for {}; job is {}",
            result.summary, result.outcome_code, claimed.job_id, receipt.state
        ),
    ))
}

#[cfg(test)]
#[path = "publish_job_tests.rs"]
mod tests;
