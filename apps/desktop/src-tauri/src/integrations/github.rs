//! GitHub workflow, deployment, and pull-request status client.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// GitHub deploy/CI data returned to the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubData {
    pub repo: String,
    pub workflow_runs: Vec<WorkflowRun>,
    pub deployments: Vec<Deployment>,
    pub open_prs: Vec<PullRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct WorkflowRun {
    pub id: u64,
    pub name: String,
    pub head_branch: String,
    pub head_sha: String,
    pub status: String,             // "completed" | "in_progress" | "queued"
    pub conclusion: Option<String>, // "success" | "failure" | "cancelled" | etc.
    pub run_number: u32,
    pub created_at: String,
    pub updated_at: String,
    pub html_url: String,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: u64,
    pub environment: String,
    pub sha: String,
    pub description: Option<String>,
    pub status: String, // from deployment statuses
    pub created_at: String,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub number: u32,
    pub title: String,
    pub state: String,
    pub user: String,
    pub head_branch: String,
    pub created_at: String,
    pub updated_at: String,
    pub html_url: String,
    pub draft: bool,
    pub additions: u32,
    pub deletions: u32,
    pub changed_files: u32,
    /// File paths changed in this PR, populated by `fetch_pr_files`.
    /// Empty until explicitly enriched - callers that need paths should
    /// call `enrich_pr_with_files` after the PR list is fetched.
    #[serde(default)]
    pub changed_file_paths: Vec<String>,
}

/// Raw API response types (internal)
#[derive(Deserialize)]
struct GhWorkflowRunsResponse {
    workflow_runs: Vec<GhWorkflowRun>,
}

#[derive(Deserialize)]
struct GhWorkflowRun {
    id: u64,
    name: String,
    head_branch: Option<String>,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
    run_number: u32,
    created_at: String,
    updated_at: String,
    html_url: String,
    run_started_at: Option<String>,
}

#[derive(Deserialize)]
struct GhDeployment {
    id: u64,
    environment: String,
    sha: String,
    description: Option<String>,
    created_at: String,
    creator: GhUser,
}

#[derive(Deserialize)]
struct GhDeploymentStatus {
    state: String,
}

#[derive(Deserialize)]
struct GhPullRequest {
    number: u32,
    title: String,
    state: String,
    user: GhUser,
    head: GhPrHead,
    created_at: String,
    updated_at: String,
    html_url: String,
    draft: Option<bool>,
    additions: Option<u32>,
    deletions: Option<u32>,
    changed_files: Option<u32>,
}

#[derive(Deserialize)]
struct GhUser {
    login: String,
}

#[derive(Deserialize)]
struct GhPrHead {
    #[serde(rename = "ref")]
    ref_name: String,
}

const API_BASE: &str = "https://api.github.com";

/// The immutable identity GitHub assigns to a repository, plus the canonical
/// owner/name spelling its OIDC token will carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRepositoryIdentity {
    pub id: String,
    pub full_name: String,
}

pub(crate) fn parse_repository_identity(
    body: &serde_json::Value,
) -> Option<GitHubRepositoryIdentity> {
    let id = body.get("id")?.as_u64()?.to_string();
    let full_name = body.get("full_name")?.as_str()?.to_string();
    if full_name.is_empty() {
        return None;
    }
    Some(GitHubRepositoryIdentity { id, full_name })
}

/// Resolve the immutable repository id before minting an attested CI token.
/// Public repositories work without a token; a configured GitHub integration
/// supplies the credential required for a private repository.
#[tracing::instrument(skip(token), fields(repository = %repo))]
pub async fn fetch_repository_identity(
    token: Option<&str>,
    repo: &str,
) -> Result<GitHubRepositoryIdentity, String> {
    let repo = super::validation::normalize_github_repo_slug(repo)?;
    let url = format!("{API_BASE}/repos/{repo}");
    let response = github_get(
        crate::http_client::credentialed_service_client(),
        token.unwrap_or_default(),
        &url,
    )
    .await?;
    if !response.status().is_success() {
        return Err(format!(
            "GitHub could not resolve {repo} ({}). For a private repository, connect GitHub to this project first.",
            response.status()
        ));
    }
    let body: serde_json::Value = crate::http_client::read_json_limited(
        response,
        crate::constants::MAX_BODY_SIZE,
        crate::constants::API_TIMEOUT_SHORT,
    )
    .await
    .map_err(|error| format!("GitHub repository identity could not be read: {error}"))?;
    let identity = parse_repository_identity(&body)
        .ok_or_else(|| "GitHub returned an invalid repository identity".to_string())?;
    if !identity.full_name.eq_ignore_ascii_case(&repo) {
        return Err("GitHub returned a different repository than the one requested".to_string());
    }
    Ok(identity)
}

/// Fetch GitHub CI/deploy data for a repository.
/// `repo` should be "owner/repo" format (e.g. "brambleworks/SiteCMD-Local").
#[tracing::instrument(skip(token, repo))]
pub async fn fetch_github_data(token: &str, repo: &str) -> Result<GitHubData, String> {
    let repo = super::validation::normalize_github_repo_slug(repo)?;
    let client = crate::http_client::credentialed_service_client();

    // Fetch workflow runs, deployments, and PRs in parallel
    let (runs_result, deploys_result, prs_result) = tokio::join!(
        fetch_workflow_runs(client, token, &repo),
        fetch_deployments(client, token, &repo),
        fetch_open_prs(client, token, &repo),
    );

    Ok(GitHubData {
        repo,
        workflow_runs: runs_result.unwrap_or_default(),
        deployments: deploys_result.unwrap_or_default(),
        open_prs: prs_result.unwrap_or_default(),
    })
}

async fn github_get(
    client: &reqwest::Client,
    token: &str,
    url: &str,
) -> Result<reqwest::Response, String> {
    let mut req = client
        .get(url)
        .header("User-Agent", crate::constants::USER_AGENT.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");

    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    req.send()
        .await
        .map_err(|e| format!("GitHub API error: {}", e))
}

/// Compute a workflow-run duration in seconds from RFC 3339 start/end
/// timestamps. Returns None when either timestamp is missing or unparseable;
/// negative durations clamp to 0 (defensive against clock skew on the
/// runners).
#[tracing::instrument(fields(started = ?started, updated = %updated))]
pub(crate) fn calculate_run_duration(started: Option<&str>, updated: &str) -> Option<u64> {
    let started = started?;
    let start = chrono::DateTime::parse_from_rfc3339(started).ok()?;
    let end = chrono::DateTime::parse_from_rfc3339(updated).ok()?;
    Some((end - start).num_seconds().max(0) as u64)
}

/// Truncate a commit SHA to its first `len` chars (or the full string if
/// shorter). Used to display short hashes in the deploy timeline.
#[tracing::instrument(fields(sha = %sha, len))]
pub(crate) fn truncate_sha(sha: &str, len: usize) -> String {
    sha[..len.min(sha.len())].to_string()
}

/// Parse a GitHub `actions/runs` response into the public `WorkflowRun`
/// shape. Pure; tested directly so timestamp + duration handling can be
/// exercised without a live API.
#[tracing::instrument(skip(body))]
pub(crate) fn parse_workflow_runs_response(body: &serde_json::Value) -> Vec<WorkflowRun> {
    let Ok(data) = serde_json::from_value::<GhWorkflowRunsResponse>(body.clone()) else {
        return Vec::new();
    };
    data.workflow_runs
        .into_iter()
        .map(|r| WorkflowRun {
            duration_seconds: calculate_run_duration(r.run_started_at.as_deref(), &r.updated_at),
            id: r.id,
            name: r.name,
            head_branch: r.head_branch.unwrap_or_default(),
            head_sha: r.head_sha,
            status: r.status,
            conclusion: r.conclusion,
            run_number: r.run_number,
            created_at: r.created_at,
            updated_at: r.updated_at,
            html_url: r.html_url,
        })
        .collect()
}

/// Returns the newest deployment status, defaulting to `pending`.
#[tracing::instrument(skip(body))]
pub(crate) fn pick_deployment_status(body: &serde_json::Value) -> String {
    let Ok(statuses) = serde_json::from_value::<Vec<GhDeploymentStatus>>(body.clone()) else {
        return "pending".to_string();
    };
    statuses
        .first()
        .map(|s| s.state.clone())
        .unwrap_or_else(|| "pending".to_string())
}

#[tracing::instrument(skip(client, token), fields(repo = %repo))]
pub(crate) async fn fetch_workflow_runs(
    client: &reqwest::Client,
    token: &str,
    repo: &str,
) -> Result<Vec<WorkflowRun>, String> {
    let url = format!(
        "{}/repos/{}/actions/runs?per_page=20&status=completed",
        API_BASE, repo
    );
    let resp = github_get(client, token, &url).await?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let body: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::GITHUB_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Failed to parse workflow runs: {}", e))?;
    Ok(parse_workflow_runs_response(&body))
}

/// Convert a single parsed GitHub deployment record + a chosen status
/// string into the public `Deployment` shape. SHA is truncated to 7 chars
/// to match the deploy-timeline display convention.
fn build_deployment(d: GhDeployment, status: String) -> Deployment {
    Deployment {
        id: d.id,
        environment: d.environment,
        sha: truncate_sha(&d.sha, 7),
        description: d.description,
        status,
        created_at: d.created_at,
        creator: d.creator.login,
    }
}

/// Parse a GitHub `pulls` response into the public `PullRequest` shape.
/// Pure; defaults all optional metric fields (additions/deletions/etc.) to 0.
#[tracing::instrument(skip(body))]
pub(crate) fn parse_pull_requests_response(body: &serde_json::Value) -> Vec<PullRequest> {
    let Ok(prs) = serde_json::from_value::<Vec<GhPullRequest>>(body.clone()) else {
        return Vec::new();
    };
    prs.into_iter()
        .map(|pr| PullRequest {
            number: pr.number,
            title: pr.title,
            state: pr.state,
            user: pr.user.login,
            head_branch: pr.head.ref_name,
            created_at: pr.created_at,
            updated_at: pr.updated_at,
            html_url: pr.html_url,
            draft: pr.draft.unwrap_or(false),
            additions: pr.additions.unwrap_or(0),
            deletions: pr.deletions.unwrap_or(0),
            changed_files: pr.changed_files.unwrap_or(0),
            changed_file_paths: Vec::new(),
        })
        .collect()
}

async fn fetch_deployments(
    client: &reqwest::Client,
    token: &str,
    repo: &str,
) -> Result<Vec<Deployment>, String> {
    let url = format!("{}/repos/{}/deployments?per_page=15", API_BASE, repo);
    let resp = github_get(client, token, &url).await?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let deployments: Vec<GhDeployment> = crate::http_client::read_json_limited(
        resp,
        crate::constants::GITHUB_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Failed to parse deployments: {}", e))?;

    let mut results = Vec::new();
    for d in deployments {
        let status_url = format!(
            "{}/repos/{}/deployments/{}/statuses?per_page=1",
            API_BASE, repo, d.id
        );
        let status = match github_get(client, token, &status_url).await {
            Ok(resp) => {
                let body: serde_json::Value = crate::http_client::read_json_limited(
                    resp,
                    crate::constants::GITHUB_API_RESPONSE_MAX_BYTES,
                    crate::constants::BODY_READ_TIMEOUT,
                )
                .await
                .unwrap_or(serde_json::json!([]));
                pick_deployment_status(&body)
            }
            Err(_) => "unknown".into(),
        };

        results.push(build_deployment(d, status));
    }

    Ok(results)
}

async fn fetch_open_prs(
    client: &reqwest::Client,
    token: &str,
    repo: &str,
) -> Result<Vec<PullRequest>, String> {
    let url = format!(
        "{}/repos/{}/pulls?state=open&per_page=10&sort=updated&direction=desc",
        API_BASE, repo
    );
    let resp = github_get(client, token, &url).await?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let body: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::GITHUB_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Failed to parse pull requests: {}", e))?;
    Ok(parse_pull_requests_response(&body))
}

/// Fetch up to 100 changed file paths for a pull request.
#[tracing::instrument(skip(client, token, owner, repo), fields(pr_number))]
pub async fn fetch_pr_files(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    pr_number: u32,
    token: &str,
) -> Result<Vec<String>, String> {
    let (owner, repo) = super::validation::split_github_repo_slug(&format!("{owner}/{repo}"))?;
    let url = format!(
        "{}/repos/{}/{}/pulls/{}/files?per_page=100",
        API_BASE, owner, repo, pr_number
    );
    let resp = github_get(client, token, &url).await?;

    if !resp.status().is_success() {
        return Err(format!(
            "GitHub API returned {} for PR files",
            resp.status()
        ));
    }

    let body: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::GITHUB_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Failed to parse PR files response: {}", e))?;

    // Use the shared parser so tests exercise the production extraction path.
    Ok(parse_pr_files_response(&body))
}

/// Parse a PR files API JSON payload into a list of filenames.
/// Pure function shared by `fetch_pr_files` and its deterministic unit tests.
#[tracing::instrument(skip(body))]
pub(crate) fn parse_pr_files_response(body: &serde_json::Value) -> Vec<String> {
    let Ok(files) = serde_json::from_value::<Vec<serde_json::Value>>(body.clone()) else {
        return Vec::new();
    };
    files
        .iter()
        .filter_map(|f| f.get("filename")?.as_str().map(String::from))
        .collect()
}

/// Add changed paths to a pull request, preserving the original on fetch failure.
#[tracing::instrument(skip(client, token, owner, repo), fields(pr_number = pr.number))]
pub async fn enrich_pr_with_files(
    client: &reqwest::Client,
    token: &str,
    owner: &str,
    repo: &str,
    mut pr: PullRequest,
) -> PullRequest {
    if let Ok(paths) = fetch_pr_files(client, owner, repo, pr.number, token).await {
        pr.changed_file_paths = paths;
    }
    pr
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct GithubReleaseSummary {
    pub tag_name: String,
    pub published_at: String,
    pub commits_since: Option<u32>,
}

/// Pure parser for `GET /repos/{owner}/{repo}/releases/latest`.
/// Returns None when the payload is missing either tag or date.
/// Tested directly.
#[tracing::instrument(skip(body))]
pub(crate) fn parse_latest_release_response(
    body: &serde_json::Value,
) -> Option<GithubReleaseSummary> {
    let tag_name = body.get("tag_name").and_then(|v| v.as_str())?.to_string();
    let published_at = body
        .get("published_at")
        .and_then(|v| v.as_str())?
        .to_string();
    if tag_name.is_empty() || published_at.is_empty() {
        return None;
    }
    Some(GithubReleaseSummary {
        tag_name,
        published_at,
        commits_since: None,
    })
}

/// Fetch the latest release from GitHub. Returns None when the repo has no releases yet.
/// `repo` is expected in "owner/name" format (same as `fetch_github_data`).
#[tracing::instrument(skip(token, repo))]
pub async fn fetch_latest_release(
    repo: &str,
    token: &str,
) -> Result<Option<GithubReleaseSummary>, String> {
    let repo = super::validation::normalize_github_repo_slug(repo)?;
    let url = format!("{}/repos/{}/releases/latest", API_BASE, repo);
    let client = crate::http_client::credentialed_service_client();
    let resp = github_get(client, token, &url)
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("GitHub returned {}", resp.status()));
    }
    let body: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::GITHUB_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(parse_latest_release_response(&body))
}

#[cfg(test)]
#[path = "github_tests.rs"]
mod github_tests;
