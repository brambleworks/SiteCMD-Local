//! `sitecmd autofix publish-job`: the trusted half of a fix job. It runs on a
//! fresh runner inside SiteCMD's reusable workflow, claims the job with its
//! own OIDC witness, checks the artifact against the binary's own write set
//! and its own checkout, and is the only place a repository write token
//! exists. It runs no command the repository controls.

use std::path::{Path, PathBuf};

use super::artifact::{read_artifact, Manifest, TEMPLATE_PLAN};
use super::exit_check::{check_publish_brief, HandedLines};
use super::github_api::GitHubApi;
use super::repo;
use super::secrets::ExportSource;
use crate::cli::{settle, ConnectStop};
use crate::connected_service::deployment_ordering::CiSubmissionAttestation;
use crate::connected_service::{
    ClaimedJob, ConnectedServiceClient, FindingOutcomeReport, PullRequestReport, ResultReport,
};
use crate::core::fix_templates::{hosts, slug};
use crate::core::project_listing::list_project;
use sitecmd_protocol::engine_abi::{Brief, FixerInfo};

use super::apply::write_patches;
use super::template_plan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishJobArgs {
    pub job_id: String,
    pub connect_origin: String,
    pub artifact_dir: PathBuf,
    pub path: PathBuf,
    pub export: ExportSource,
    pub passphrase_env: String,
}

pub(super) fn parse(mut args: impl Iterator<Item = String>) -> Result<PublishJobArgs, String> {
    let job_id = args
        .next()
        .filter(|id| super::is_job_id(id))
        .ok_or("publish-job needs a job id like job_0123456789abcdef")?;
    let mut connect_origin = None;
    let mut artifact_dir = None;
    let mut path = PathBuf::from(".");
    let mut export = ExportSource::Env("SITECMD_CONNECTION_EXPORT".into());
    let mut passphrase_env = "SITECMD_CONNECTION_PASSPHRASE".into();
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
            "--connection-export-env" => {
                export = ExportSource::Env(super::next_value(&mut args, "--connection-export-env")?)
            }
            "--passphrase-env" => {
                passphrase_env = super::next_value(&mut args, "--passphrase-env")?
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
        export,
        passphrase_env,
    })
}

/// The checkout this job publishes from, resolved once so every path it
/// redacts is absolute.
fn checkout_root(args: &PublishJobArgs) -> Result<PathBuf, String> {
    std::fs::canonicalize(&args.path)
        .map_err(|error| format!("cannot resolve {}: {error}", args.path.display()))
}

/// The publish job audits its own checkout for anything the patch did not
/// declare, so an artifact downloaded inside that checkout would make its own
/// files the evidence against the patch and decline every publish. The
/// refusal comes before the claim, so a misconfigured workflow costs the job
/// no attempt. A directory that cannot be resolved is left to the artifact
/// read, which names what is missing.
fn refuse_an_artifact_inside_the_checkout(root: &Path, artifact_dir: &Path) -> Result<(), String> {
    let Ok(artifact) = std::fs::canonicalize(artifact_dir) else {
        return Ok(());
    };
    if artifact.starts_with(root) {
        return Err("artifact directory must be outside the checkout".into());
    }
    Ok(())
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
    if manifest.findings.iter().any(|finding| {
        !matches!(
            finding.outcome.as_deref(),
            None | Some("applied" | "issue_opened" | "unsupported" | "no_template")
        )
    }) {
        return Err("manifest names an unsupported finding outcome".into());
    }
    // The pull request body and the finding outcomes are read out of the
    // manifest, so the manifest may not name a finding the claim never did.
    let mut claimed_findings: Vec<(&str, &str)> = claimed
        .findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.identity.as_str()))
        .collect();
    let mut manifest_findings: Vec<(&str, &str)> = manifest
        .findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.identity.as_str()))
        .collect();
    claimed_findings.sort_unstable();
    manifest_findings.sort_unstable();
    if manifest_findings != claimed_findings {
        return Err("manifest names other findings than the claim".into());
    }
    if let Some(brief) = &manifest.brief {
        if brief.job_id != claimed.job_id
            || brief.attempt != claimed.attempt
            || brief.findings.iter().any(|finding| {
                !claimed_findings.contains(&(finding.check_id.as_str(), finding.identity.as_str()))
            })
        {
            return Err("brief names another job, attempt, or finding".into());
        }
    }
    Ok(())
}

/// Every file the claimed checks are allowed to touch, derived from the job's
/// check ids and the binary's own fixers. The artifact never contributes: a
/// write set it named would be the patch vouching for itself.
fn allowed_write_set(claimed: &ClaimedJob, root: &Path, catalog: &[FixerInfo]) -> Vec<String> {
    let targets = hosts::detect(root);
    let mut allowed: Vec<String> = Vec::new();
    for finding in &claimed.findings {
        if let Some(fixer) = catalog
            .iter()
            .find(|fixer| fixer.check_id == finding.check_id)
        {
            for path in &fixer.write_set {
                let text = path.as_str();
                if targets
                    .iter()
                    .any(|target| target.config_path == Path::new(text))
                    && !allowed.iter().any(|allowed| allowed == text)
                {
                    allowed.push(text.to_owned());
                }
            }
        }
    }
    allowed
}

pub(super) fn branch_name(claimed: &ClaimedJob, catalog: &[FixerInfo]) -> String {
    let first = claimed
        .findings
        .iter()
        .find(|f| catalog.iter().any(|fixer| fixer.check_id == f.check_id))
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

pub fn pull_request_text(
    claimed: &ClaimedJob,
    manifest: &Manifest,
    catalog: &[FixerInfo],
) -> (String, String) {
    let title = claimed
        .findings
        .iter()
        .find_map(|finding| {
            catalog
                .iter()
                .find(|fixer| fixer.check_id == finding.check_id)
                .map(|fixer| fixer.title.clone())
        })
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
///
/// Which results carry this at all is fixed: a failure code (`patch_rejected`,
/// `push_failed`, `brief_rejected`, `issue_failed`) carries no finding
/// outcomes, a decline (`unsupported`, `no_template`) carries each finding's
/// non-published outcome, and a published result (`applied`, `issue_opened`)
/// carries the published one.
pub fn finding_reports(manifest: &Manifest, published: &str) -> Vec<FindingOutcomeReport> {
    manifest
        .findings
        .iter()
        .filter_map(|f| {
            FindingOutcomeReport::new(
                &f.check_id,
                &f.identity,
                &(promoted_outcome(f.outcome.as_deref(), published)),
            )
        })
        .collect()
}

/// One finding's reported outcome. Each path publishes one kind of outcome and
/// only that kind survives: the patch path opens no issue and the brief path
/// opens no pull request, so a manifest outcome the path never published is
/// reported unsupported rather than promoted into a claim this run cannot make.
fn promoted_outcome(outcome: Option<&str>, published: &str) -> String {
    match outcome {
        Some("applied") if published == "applied" => "applied".into(),
        Some("issue_opened") if published == "issue_opened" => "issue_opened".into(),
        Some("no_template") => "no_template".into(),
        _ => "unsupported".into(),
    }
}

/// Whether the manifest's brief names anywhere to open an issue about.
fn brief_names_a_location(manifest: &Manifest) -> bool {
    manifest
        .brief
        .as_ref()
        .is_some_and(|brief| brief.findings.iter().any(|f| !f.locations.is_empty()))
}

pub(super) struct PublishOutcome {
    pub result: ResultReport,
    pub message: String,
}

/// One result for the connected service. `token_revoked` is true on a path
/// that minted no token at all as well as on one that handed its token back:
/// either way none is outstanding, and Connect acts only when a publish
/// result reports false.
fn report(
    attempt: u32,
    code: &str,
    message: String,
    findings: Vec<FindingOutcomeReport>,
    pull_request: Option<PullRequestReport>,
    issue_number: Option<u64>,
    token_revoked: bool,
) -> PublishOutcome {
    PublishOutcome {
        message,
        result: ResultReport {
            attempt,
            findings,
            issue_number,
            outcome_code: code.parse().expect("fixed outcome code"),
            pull_request,
            token_revoked,
        },
    }
}

/// Regenerate the template locally and publish it, checking its paths
/// against the binary's write set, the commit made as the App's bot, the
/// branch pushed with a per-operation installation token, the pull request
/// opened, and the token handed back before anything is reported.
async fn publish_patch(
    root: &Path,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    job_client: &ConnectedServiceClient,
) -> Result<(u8, PublishOutcome), ConnectStop> {
    let declined = |code: &str, summary: String| {
        (
            1_u8,
            report(claimed.attempt, code, summary, Vec::new(), None, None, true),
        )
    };
    let catalog = template_plan::catalog()?;
    let project = list_project(root).map_err(|error| error.to_string())?;
    let mut handed = HandedLines::default();
    let patches =
        match template_plan::regenerate(&project, claimed, manifest, &catalog, &mut handed) {
            Ok(patches) => patches,
            Err(error) => return Ok(declined("patch_rejected", error)),
        };
    let (title, body) = pull_request_text(claimed, manifest, &catalog);
    let brief = match check_publish_brief(project.wire(), Brief { title, body }, &handed, &patches)
    {
        Ok(brief) => brief,
        Err(refusal) => return Ok(declined("patch_rejected", refusal.to_string())),
    };
    let changed: Vec<String> = patches
        .iter()
        .map(|patch| patch.path.as_str().to_owned())
        .collect();
    let allowed = allowed_write_set(claimed, root, &catalog);
    let baseline = repo::changed_paths(root)?;
    if let Err(error) = write_patches(project.wire(), root, patches, |path| {
        allowed.iter().any(|allowed| allowed == path.as_str())
    }) {
        return Ok(declined("patch_rejected", error));
    }
    let undeclared = repo::undeclared_paths(&baseline, &repo::changed_paths(root)?, &changed);
    if !undeclared.is_empty() {
        return Ok(declined(
            "patch_rejected",
            "template changed undeclared paths".into(),
        ));
    }
    let committer = claimed
        .committer
        .as_ref()
        .ok_or("publish claim carried no committer")?;
    let head_sha = repo::commit(
        root,
        &changed,
        &committer.name,
        &committer.email,
        &brief.as_brief().title,
    )?;
    let branch = branch_name(claimed, &catalog);
    let minted = job_client
        .publish_token(&claimed.job_id)
        .await
        .map_err(|error| ConnectStop::refused_as(&error, "publish token").unrecorded(""))?;
    let api = GitHubApi::new();
    let pushed = api.push_branch(root, &minted.token, &claimed.repository, &branch);
    let outcome = match pushed {
        Err(error) => Err(("push_failed", error)),
        Ok(()) => match api
            .create_pull_request(
                &minted.token,
                &claimed.repository,
                &branch,
                &claimed.default_branch,
                &brief,
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
    let failed = |code: &str, summary: String| {
        (
            1_u8,
            report(
                claimed.attempt,
                code,
                summary,
                Vec::new(),
                None,
                None,
                revoked,
            ),
        )
    };
    let created = match outcome {
        Ok(created) => created,
        Err((code, error)) => return Ok(failed(code, error)),
    };
    // The pull request has to be the commit this job pushed, or something
    // else moved the branch between the push and the answer.
    if created.head_sha != head_sha {
        return Ok(failed(
            "push_failed",
            "pull request head is not the pushed commit".to_string(),
        ));
    }
    Ok((
        0,
        report(
            claimed.attempt,
            "applied",
            format!("opened pull request #{}", created.number),
            finding_reports(manifest, "applied"),
            Some(PullRequestReport {
                branch: branch.try_into()?,
                head_sha: head_sha.try_into()?,
                number: created.number,
            }),
            None,
            revoked,
        ),
    ))
}

/// Which of the two publish paths an artifact takes, or the refusal that
/// replaces both. A patch and a brief are the two classes a fix job produces
/// and one job is only ever one of them.
async fn publish_artifact(
    args: &PublishJobArgs,
    root: &Path,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    patch: &str,
    job_client: &ConnectedServiceClient,
) -> Result<(u8, PublishOutcome), ConnectStop> {
    let rejected = |summary: String| {
        (
            1_u8,
            report(
                claimed.attempt,
                "patch_rejected",
                summary,
                Vec::new(),
                None,
                None,
                true,
            ),
        )
    };
    if let Err(reason) = manifest_matches_claim(manifest, claimed) {
        return Ok(rejected(reason));
    }
    let carries_a_patch = !patch.trim().is_empty();
    // A fix job is single-class by construction, so an artifact carrying both
    // halves is one this binary never wrote, and the dispatch below would
    // silently drop one of them.
    if carries_a_patch && brief_names_a_location(manifest) {
        return Ok(rejected("artifact carries both a patch and a brief".into()));
    }
    if carries_a_patch {
        if patch != TEMPLATE_PLAN {
            return Ok(rejected("source-bearing patches are not accepted".into()));
        }
        return publish_patch(root, claimed, manifest, job_client).await;
    }
    if manifest.brief.is_some() {
        return super::brief_publish::publish_brief(args, root, claimed, manifest, job_client)
            .await;
    }
    // A decline, like every other, exits zero: nothing failed, and there was
    // nothing here for this job to publish.
    Ok((
        0,
        report(
            claimed.attempt,
            "unsupported",
            "artifact carries nothing to publish".into(),
            finding_reports(manifest, "unsupported"),
            None,
            None,
            true,
        ),
    ))
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
    settle(
        publish(args, witness, allow_http_loopback).await,
        |notice| (0, notice),
    )
}

async fn publish(
    args: &PublishJobArgs,
    witness: &str,
    allow_http_loopback: bool,
) -> Result<(u8, String), ConnectStop> {
    let root = checkout_root(args)?;
    refuse_an_artifact_inside_the_checkout(&root, &args.artifact_dir)?;
    let claim_client =
        ConnectedServiceClient::for_endpoint(&args.connect_origin, None, allow_http_loopback)?;
    let claimed = claim_client
        .claim_job(&args.job_id, "publish", witness)
        .await
        .map_err(|error| ConnectStop::refused_as(&error, "publish claim"))?;
    // The runner writes only what it can see, and it can only see its own
    // checkout, so a checkout that is not the commit the claim names is
    // refused before the artifact is even read.
    let head = repo::head_sha(&root)?;
    if head != claimed.base_sha {
        return Err(format!(
            "refusing to publish: checkout is at {head}, the claim names {}",
            claimed.base_sha
        )
        .into());
    }
    let job_client = ConnectedServiceClient::for_endpoint(
        &args.connect_origin,
        Some(&claimed.job_token),
        allow_http_loopback,
    )?;
    // The artifact is the fix job's own doing, so one this job cannot read at
    // all is a rejection it reports rather than an operational failure that
    // would leave the job waiting out its window.
    let (code, result) = match read_artifact(&args.artifact_dir) {
        Ok((manifest, patch)) => {
            publish_artifact(args, &root, &claimed, &manifest, &patch, &job_client).await?
        }
        Err(error) => (
            1,
            report(
                claimed.attempt,
                "patch_rejected",
                error,
                Vec::new(),
                None,
                None,
                true,
            ),
        ),
    };
    let receipt = job_client
        .report_job_result(&claimed.job_id, &result.result)
        .await
        .map_err(|error| {
            ConnectStop::refused_as(&error, "result").unrecorded(result.message.clone())
        })?;
    Ok((
        code,
        format!(
            "{}\nreported {} for {}; job is {}",
            result.message, result.result.outcome_code, claimed.job_id, receipt.state
        ),
    ))
}

#[cfg(test)]
#[path = "publish_job_tests.rs"]
mod tests;
