//! The publish job's unit tests, plus the two that drive the command
//! against a loopback double of the connected service.

use super::*;
use crate::cli::autofix::artifact::{write_artifact, ManifestFinding, ARTIFACT_SCHEMA_VERSION};
use crate::cli::autofix::repo::{self, init_test_repo};
use crate::connected_service::test_double::respond_in_sequence;
use crate::connected_service::{ClaimedFinding, Committer};

const CHECK_ID: &str = "security.headers.x_content_type_options";
const COMMITTER_NAME: &str = "sitecmd-loop[bot]";
const COMMITTER_EMAIL: &str = "1+sitecmd-loop[bot]@users.noreply.github.com";
const PUBLISH_JOB_TOKEN: &str = "sitecmd_job_publish_00000000000000000000000000000000";
const RESULT_RECEIPT: &str = r#"{"job_id":"job_0123456789abcdef","state":"failed"}"#;

fn claimed(base_sha: &str) -> ClaimedJob {
    ClaimedJob {
        agent: "claude".into(),
        attempt: 1,
        base_sha: base_sha.into(),
        committer: Some(Committer {
            email: COMMITTER_EMAIL.into(),
            name: COMMITTER_NAME.into(),
        }),
        default_branch: "main".into(),
        expires_at: "x".into(),
        findings: vec![ClaimedFinding {
            category: "security".into(),
            check_id: CHECK_ID.into(),
            class: "template".into(),
            fallback_class: None,
            identity: "/".into(),
        }],
        job_id: "job_0123456789abcdef".into(),
        job_token: PUBLISH_JOB_TOKEN.into(),
        opt_in_fixers: vec![],
        previous_failure: None,
        purpose: "publish".into(),
        repository: "example-org/example-site".into(),
        site_url: "https://loop.example.com".into(),
    }
}

fn manifest(base_sha: &str) -> Manifest {
    Manifest {
        attempt: 1,
        base_sha: base_sha.into(),
        brief: None,
        findings: vec![ManifestFinding {
            check_id: CHECK_ID.into(),
            identity: "/".into(),
            outcome: Some("applied".into()),
        }],
        job_id: "job_0123456789abcdef".into(),
        outcome_code: None,
        schema_version: ARTIFACT_SCHEMA_VERSION,
        summary: "planned".into(),
        write_set: vec!["vercel.json".into()],
    }
}

/// The publish claim the connected service answers with, as JSON on the
/// wire, so a test can name a base sha its own checkout is at.
fn claim_body(base_sha: &str) -> String {
    serde_json::json!({
        "agent": "claude",
        "attempt": 1,
        "base_sha": base_sha,
        "committer": { "email": COMMITTER_EMAIL, "name": COMMITTER_NAME },
        "default_branch": "main",
        "expires_at": "2026-09-20T10:30:00.000Z",
        "findings": [{
            "category": "security",
            "check_id": CHECK_ID,
            "class": "template",
            "fallback_class": null,
            "identity": "/",
        }],
        "job_id": "job_0123456789abcdef",
        "job_token": PUBLISH_JOB_TOKEN,
        "purpose": "publish",
        "repository": "example-org/example-site",
        "site_url": "https://loop.example.com",
    })
    .to_string()
}

fn args(origin: String, artifact_dir: &std::path::Path, root: &std::path::Path) -> PublishJobArgs {
    PublishJobArgs {
        artifact_dir: artifact_dir.to_path_buf(),
        connect_origin: origin,
        job_id: "job_0123456789abcdef".into(),
        path: root.to_path_buf(),
    }
}

/// Drive the command against a loopback double with a claim the checkout is
/// already at and a manifest that matches it, so the patch is the only thing
/// under test. Answers the outcome and the requests the double captured.
async fn publish_this_patch(
    repo_dir: &std::path::Path,
    artifact_dir: &std::path::Path,
    head: &str,
    patch: &str,
) -> (Result<(u8, String), String>, Vec<String>) {
    write_artifact(artifact_dir, &manifest(head), patch).unwrap();
    let (origin, captured) = respond_in_sequence(vec![
        (claim_body(head), "200 OK"),
        (RESULT_RECEIPT.to_string(), "200 OK"),
    ])
    .await;
    let outcome =
        run_with_witness(&args(origin, artifact_dir, repo_dir), "witness-token", true).await;
    (outcome, captured.await.expect("capture"))
}

#[test]
fn the_manifest_must_name_the_claimed_job_attempt_and_base() {
    let base = "0".repeat(40);
    assert!(manifest_matches_claim(&manifest(&base), &claimed(&base)).is_ok());
    let mut wrong = manifest(&base);
    wrong.job_id = "job_ffffffffffffffff".into();
    assert!(manifest_matches_claim(&wrong, &claimed(&base))
        .unwrap_err()
        .contains("job id"));
    let mut stale = manifest(&base);
    stale.base_sha = "1".repeat(40);
    assert!(manifest_matches_claim(&stale, &claimed(&base))
        .unwrap_err()
        .contains("base"));
    let mut attempt = manifest(&base);
    attempt.attempt = 2;
    assert!(manifest_matches_claim(&attempt, &claimed(&base))
        .unwrap_err()
        .contains("attempt"));
    let mut extra = manifest(&base);
    extra.findings.push(ManifestFinding {
        check_id: "security.headers.content_security_policy".into(),
        identity: "/".into(),
        outcome: Some("applied".into()),
    });
    assert!(manifest_matches_claim(&extra, &claimed(&base))
        .unwrap_err()
        .contains("findings"));
}

#[test]
fn changed_paths_names_every_edited_and_added_file() {
    let (repo_dir, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
    std::fs::write(repo_dir.path().join("vercel.json"), "{\"a\":1}\n").unwrap();
    std::fs::write(repo_dir.path().join("_headers"), "/*\n").unwrap();
    let mut paths = repo::changed_paths(repo_dir.path()).unwrap();
    paths.sort();
    assert_eq!(
        paths,
        vec!["_headers".to_string(), "vercel.json".to_string()]
    );
}

#[test]
fn the_write_set_comes_from_the_binary_and_never_admits_workflows() {
    let (repo, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let allowed = allowed_write_set(&claimed(&head), repo.path());
    assert_eq!(allowed, vec!["vercel.json".to_string()]);
    assert!(write_set_violations(&["vercel.json".into()], &allowed).is_empty());
    assert_eq!(
        write_set_violations(&["vercel.json".into(), "package.json".into()], &allowed),
        vec!["package.json".to_string()]
    );
    assert_eq!(
        write_set_violations(
            &[".github/workflows/deploy.yml".into()],
            &[".github/workflows/deploy.yml".into()]
        ),
        vec![".github/workflows/deploy.yml".to_string()]
    );
}

#[test]
fn names_the_branch_and_the_pull_request() {
    let job = claimed(&"0".repeat(40));
    assert_eq!(branch_name(&job), "sitecmd/x-content-type-options-012345");
    let (title, body) = pull_request_text(&job, &manifest(&"0".repeat(40)));
    assert_eq!(title, "Add the X-Content-Type-Options header");
    assert!(body.contains(CHECK_ID), "{body}");
    assert!(body.contains("job_0123456789abcdef"), "{body}");
}

#[test]
fn applies_the_artifact_patch_and_commits_as_the_bot() {
    let (repo_dir, head) =
        init_test_repo(&[("vercel.json", "{\n  \"cleanUrls\": true\n}\n")]).unwrap();
    // Produce a patch the way the fix job does, then reset the tree.
    let fixer = crate::core::fix_templates::fixer_for(CHECK_ID).unwrap();
    let target = crate::core::fix_templates::hosts::detect(repo_dir.path()).remove(0);
    let patch = fixer
        .plan(
            &crate::core::fix_templates::Finding {
                check_id: fixer.check_id().into(),
                identity: "/".into(),
            },
            &target,
            repo_dir.path(),
        )
        .unwrap()
        .unwrap();
    crate::core::fix_templates::apply(&[patch], repo_dir.path()).unwrap();
    repo::stage(repo_dir.path(), &["vercel.json".into()]).unwrap();
    let diff = repo::staged_patch(repo_dir.path()).unwrap();
    crate::core::git::run_git_command(
        repo_dir.path(),
        &["reset", "--hard", "-q"],
        crate::constants::AUTOFIX_GIT_TIMEOUT,
        None,
    )
    .unwrap();
    let patch_dir = tempfile::tempdir().unwrap();
    let patch_path = patch_dir.path().join("patch.diff");
    std::fs::write(&patch_path, &diff).unwrap();

    let changed = repo::patch_paths(repo_dir.path(), &patch_path).unwrap();
    assert_eq!(changed, vec!["vercel.json".to_string()]);
    repo::apply_patch(repo_dir.path(), &patch_path).unwrap();
    let committed = repo::commit(
        repo_dir.path(),
        &changed,
        COMMITTER_NAME,
        COMMITTER_EMAIL,
        "Add the X-Content-Type-Options header",
    )
    .unwrap();
    assert_ne!(committed, head);
    assert!(std::fs::read_to_string(repo_dir.path().join("vercel.json"))
        .unwrap()
        .contains("nosniff"));
    let author = crate::core::git::run_git_command(
        repo_dir.path(),
        &["log", "-1", "--format=%an <%ae>"],
        crate::constants::AUTOFIX_GIT_TIMEOUT,
        None,
    )
    .unwrap();
    assert_eq!(
        author.stdout.trim(),
        "sitecmd-loop[bot] <1+sitecmd-loop[bot]@users.noreply.github.com>"
    );
}

#[tokio::test]
async fn refuses_a_checkout_that_is_not_the_claimed_base() {
    let (repo_dir, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    let (origin, captured) =
        respond_in_sequence(vec![(claim_body(&"1".repeat(40)), "200 OK")]).await;

    let error = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect_err("a checkout that is not the claimed base must refuse");

    assert!(error.contains("refusing to publish"), "{error}");
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 1, "{requests:?}");
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
    assert!(claim.ends_with(r#"{"purpose":"publish"}"#), "{claim}");
}

#[tokio::test]
async fn reports_patch_rejected_when_the_manifest_names_another_job() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    let mut stale = manifest(&head);
    stale.job_id = "job_ffffffffffffffff".into();
    write_artifact(
        &artifact_dir,
        &stale,
        "diff --git a/vercel.json b/vercel.json\n",
    )
    .unwrap();
    let (origin, captured) = respond_in_sequence(vec![
        (claim_body(&head), "200 OK"),
        (RESULT_RECEIPT.to_string(), "200 OK"),
    ])
    .await;

    let (code, summary) = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect("the command to report rather than fail");

    assert_eq!(code, 1);
    assert_eq!(
        summary,
        "manifest names another job id\nreported patch_rejected for job_0123456789abcdef; job is failed"
    );
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    let report = requests[1].to_ascii_lowercase();
    assert!(
        report.starts_with("post /v1/fix-jobs/job_0123456789abcdef/result http/1.1"),
        "{report}"
    );
    assert!(
        report.contains(
            "authorization: bearer sitecmd_job_publish_00000000000000000000000000000000\r\n"
        ),
        "{report}"
    );
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
    // A failure code reports no per-finding outcomes at all.
    assert!(requests[1].contains(r#""findings":[]"#), "{}", requests[1]);
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}

#[tokio::test]
async fn refuses_a_patch_that_renames_a_file_into_the_write_set() {
    let (repo_dir, head) = init_test_repo(&[
        ("vercel.json", "{}\n"),
        (".github/workflows/deploy.yml", "name: deploy\n"),
    ])
    .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    // `git apply --numstat` reports a rename's destination and nothing else,
    // so the write-set gate would see only `vercel.json`, which it allows,
    // while the workflow left the tree unseen.
    assert!(write_set_violations(
        &["vercel.json".into()],
        &allowed_write_set(&claimed(&head), repo_dir.path())
    )
    .is_empty());
    let renaming = "diff --git a/.github/workflows/deploy.yml b/vercel.json\nsimilarity index 100%\nrename from .github/workflows/deploy.yml\nrename to vercel.json\n";

    let (outcome, requests) =
        publish_this_patch(repo_dir.path(), &artifact_dir, &head, renaming).await;

    let (code, summary) = outcome.expect("the command to report rather than fail");
    assert_eq!(code, 1);
    assert!(summary.contains("renames or copies a file"), "{summary}");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
    // The patch reader is what refuses it, before git ever reads the diff.
    assert!(
        repo::patch_paths(repo_dir.path(), &artifact_dir.join("patch.diff"))
            .unwrap_err()
            .contains("renames or copies a file")
    );
    assert!(
        repo_dir
            .path()
            .join(".github/workflows/deploy.yml")
            .is_file(),
        "the workflow must still be there"
    );
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}

#[tokio::test]
async fn reports_patch_rejected_for_a_patch_with_no_hunks() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");

    let (outcome, requests) = publish_this_patch(
        repo_dir.path(),
        &artifact_dir,
        &head,
        "diff --git a/vercel.json b/vercel.json\n",
    )
    .await;

    let (code, summary) = outcome.expect("a malformed patch is reported, never an exit 2");
    assert_eq!(code, 1);
    assert!(summary.contains("git apply --numstat failed"), "{summary}");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}
