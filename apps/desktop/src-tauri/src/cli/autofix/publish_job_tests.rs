//! The publish job's unit tests, plus the ones that drive the command
//! against a loopback double of the connected service.

use super::*;
use crate::cli::autofix::artifact::{
    write_artifact, BriefArtifact, BriefArtifactLocation, BriefFinding, ManifestFinding,
    ARTIFACT_SCHEMA_VERSION,
};
use crate::cli::autofix::repo::{self, init_test_repo};
use crate::connected_service::autofix_jobs::Committer;
use crate::connected_service::test_double::{
    request_line, respond_in_sequence, ACCOUNT_INACTIVE_PROBLEM, ENTITLEMENT_SUSPENDED_PROBLEM,
};
use crate::connected_service::{
    ClaimedFinding, ACCOUNT_INACTIVE_NOTICE, ACCOUNT_INACTIVE_RESULT_NOTICE,
};

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
        write_set: vec!["vercel.json".into()],
    }
}

fn fixture_claimed(base_sha: &str) -> ClaimedJob {
    let mut claim = claimed(base_sha);
    claim.findings[0].check_id = "standin.rule".into();
    claim
}

fn fixture_manifest(base_sha: &str) -> Manifest {
    let mut manifest = manifest(base_sha);
    manifest.write_set = vec!["vercel.json".into()];
    manifest.findings[0].check_id = "standin.rule".into();
    manifest
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
    write_artifact(artifact_dir, &manifest(head), "").unwrap();
    std::fs::write(artifact_dir.join("patch.diff"), patch).unwrap();
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
    let mut with_brief = manifest(&base);
    with_brief.brief = Some(BriefArtifact {
        job_id: claimed(&base).job_id,
        attempt: 1,
        findings: vec![BriefFinding {
            check_id: CHECK_ID.into(),
            identity: "/".into(),
            locations: vec![],
        }],
    });
    assert!(manifest_matches_claim(&with_brief, &claimed(&base)).is_ok());
    for field in ["job", "attempt", "identity"] {
        let mut tampered = with_brief.clone();
        let brief = tampered.brief.as_mut().unwrap();
        match field {
            "job" => brief.job_id = "job_ffffffffffffffff".into(),
            "attempt" => brief.attempt += 1,
            _ => brief.findings[0].identity = "other".into(),
        }
        assert!(manifest_matches_claim(&tampered, &claimed(&base))
            .unwrap_err()
            .contains("brief"));
    }
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
    // An artifact can expand the module write set or permit a workflow edit.
    let (repo, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let allowed = allowed_write_set(
        &fixture_claimed(&head),
        repo.path(),
        &template_plan::catalog().unwrap(),
    );
    assert_eq!(allowed, vec!["vercel.json".to_string()]);
    use super::super::apply::check_write_set;
    use sitecmd_protocol::engine_abi::{Patch, RelPath};

    let patch = |path| Patch {
        path: RelPath::parse(path).unwrap(),
        base_sha256: Patch::hash_base(b"{}"),
        content: String::new(),
    };
    let admitted = |path: &RelPath| allowed.iter().any(|allowed| allowed == path.as_str());
    assert!(check_write_set(&[patch("vercel.json")], admitted).is_ok());
    assert_eq!(
        check_write_set(&[patch("vercel.json"), patch("package.json")], admitted).unwrap_err(),
        "package.json: template reaches outside the fixer's write set"
    );
    assert_eq!(
        check_write_set(&[patch(".github/workflows/deploy.yml")], |_| true).unwrap_err(),
        ".github/workflows/deploy.yml: template reaches outside the fixer's write set"
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
    assert!(
        summary.contains("source-bearing patches are not accepted"),
        "{summary}"
    );
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}

#[test]
fn only_the_outcome_the_path_published_is_promoted() {
    let base = "0".repeat(40);
    let mut mixed = manifest(&base);
    mixed.findings.push(ManifestFinding {
        check_id: "code_scan.open-redirect".into(),
        identity: "f".repeat(64),
        outcome: Some("issue_opened".into()),
    });
    mixed.findings.push(ManifestFinding {
        check_id: "security.headers.hsts".into(),
        identity: "/".into(),
        outcome: Some("no_template".into()),
    });
    let outcomes = |published: &str| -> Vec<String> {
        finding_reports(&mixed, published)
            .into_iter()
            .map(|f| f.outcome.to_string())
            .collect()
    };
    // The patch path opens no issue, and the brief path opens no pull request.
    assert_eq!(
        outcomes("applied"),
        ["applied", "unsupported", "no_template"]
    );
    assert_eq!(
        outcomes("issue_opened"),
        ["unsupported", "issue_opened", "no_template"]
    );
    assert_eq!(
        outcomes("unsupported"),
        ["unsupported", "unsupported", "no_template"]
    );
}

#[tokio::test]
async fn reports_patch_rejected_when_the_artifact_carries_both_halves() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    let mut both = manifest(&head);
    both.brief = Some(BriefArtifact {
        attempt: 1,
        findings: vec![BriefFinding {
            check_id: "code_scan.open-redirect".into(),
            identity: "f".repeat(64),
            locations: vec![BriefArtifactLocation {
                end_line: 3,
                path: "app/route.ts".into(),
                start_line: 3,
            }],
        }],
        job_id: "job_0123456789abcdef".into(),
    });
    both.findings.push(ManifestFinding {
        check_id: "code_scan.open-redirect".into(),
        identity: "f".repeat(64),
        outcome: Some("issue_opened".into()),
    });
    let mut claim: serde_json::Value = serde_json::from_str(&claim_body(&head)).unwrap();
    claim["findings"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "category": "security", "check_id": "code_scan.open-redirect",
            "class": "agent-easy", "identity": "f".repeat(64)
        }));
    write_artifact(
        &artifact_dir,
        &both,
        "diff --git a/vercel.json b/vercel.json\n",
    )
    .unwrap();
    let (origin, captured) = respond_in_sequence(vec![
        (claim.to_string(), "200 OK"),
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
    assert!(
        summary.starts_with("artifact carries both a patch and a brief"),
        "{summary}"
    );
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
    assert!(requests[1].contains(r#""findings":[]"#), "{}", requests[1]);
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}

#[test]
fn the_post_apply_audit_is_baselined_against_the_checkout() {
    let before = vec!["runner-left-this.log".to_string()];
    let after = vec![
        "runner-left-this.log".to_string(),
        "vercel.json".to_string(),
        "surprise.json".to_string(),
    ];
    let declared = vec!["vercel.json".to_string()];
    assert_eq!(
        repo::undeclared_paths(&before, &after, &declared),
        vec!["surprise.json".to_string()]
    );
    // A rename line names both of its sides, and each is judged on its own.
    let renamed = vec!["old.json".to_string(), "new.json".to_string()];
    assert_eq!(
        repo::undeclared_paths(&[], &renamed, &["old.json".to_string()]),
        vec!["new.json".to_string()]
    );
    assert!(repo::undeclared_paths(&renamed, &renamed, &[]).is_empty());
}

#[tokio::test]
async fn refuses_an_artifact_directory_inside_the_checkout() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    // The audit would see the artifact's own files as paths the patch never
    // declared, so the job is refused before it costs an attempt.
    let artifact_dir = repo_dir.path().join("job");
    write_artifact(&artifact_dir, &manifest(&head), "").unwrap();
    let (origin, captured) = respond_in_sequence(vec![]).await;

    let error = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect_err("an artifact inside the checkout must refuse");

    assert!(error.contains("outside the checkout"), "{error}");
    assert!(captured.await.expect("capture").is_empty());
}

#[tokio::test]
async fn reports_patch_rejected_for_an_artifact_it_cannot_read() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    // A field this binary does not know is an artifact it never wrote.
    std::fs::write(
        artifact_dir.join("manifest.json"),
        r#"{"schema_version":1,"job_id":"job_0123456789abcdef","attempt":1,"base_sha":"0","outcome_code":null,"summary":"","write_set":[],"findings":[],"brief":null,"extra":1}"#,
    )
    .unwrap();
    std::fs::write(artifact_dir.join("patch.diff"), "").unwrap();
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
    .expect("a broken artifact is reported, never an exit 2");

    assert_eq!(code, 1);
    assert!(summary.contains("manifest is not valid"), "{summary}");
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
}

#[tokio::test]
async fn an_artifact_with_nothing_to_publish_declines_with_exit_zero() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");

    let (outcome, requests) = publish_this_patch(repo_dir.path(), &artifact_dir, &head, "").await;

    let (code, summary) = outcome.expect("the command to report rather than fail");
    assert_eq!(code, 0, "a decline exits zero like every other");
    assert!(
        summary.starts_with("artifact carries nothing to publish"),
        "{summary}"
    );
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"unsupported""#),
        "{}",
        requests[1]
    );
    // A decline still reports what each finding reached.
    assert!(
        requests[1].contains(r#""outcome":"unsupported""#),
        "{}",
        requests[1]
    );
}

#[tokio::test]
async fn refuses_a_patch_that_edits_a_workflow_in_place() {
    let (repo_dir, head) = init_test_repo(&[
        ("vercel.json", "{}\n"),
        (".github/workflows/deploy.yml", "name: deploy\n"),
    ])
    .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    // No rename and no second path: a plain hunk against the workflow that
    // runs this very job.
    let workflow_hunk = "diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml\nindex 1111111..2222222 100644\n--- a/.github/workflows/deploy.yml\n+++ b/.github/workflows/deploy.yml\n@@ -1 +1,2 @@\n name: deploy\n+on: push\n";

    let (outcome, requests) =
        publish_this_patch(repo_dir.path(), &artifact_dir, &head, workflow_hunk).await;

    let (code, summary) = outcome.expect("the command to report rather than fail");
    assert_eq!(code, 1);
    assert!(
        summary.contains("source-bearing patches are not accepted"),
        "{summary}"
    );
    // The reason crosses back to SiteCMD, so the path itself stays hidden.
    assert!(!summary.contains(".github/workflows"), "{summary}");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains(r#""outcome_code":"patch_rejected""#),
        "{}",
        requests[1]
    );
    assert_eq!(
        std::fs::read_to_string(repo_dir.path().join(".github/workflows/deploy.yml")).unwrap(),
        "name: deploy\n",
        "nothing may be applied"
    );
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}

#[test]
fn the_unshallow_fetch_names_the_remote_it_pushes_to() {
    // `origin` may be absent or point elsewhere in the publish job's own
    // checkout, so the deepening names the repository by URL.
    assert_eq!(
        repo::unshallow_args("https://github.com/example-org/example-site.git"),
        [
            "fetch",
            "--unshallow",
            "--no-tags",
            "--",
            "https://github.com/example-org/example-site.git",
        ]
    );
}

/// The patch the fix job would leave for the fixture finding, made the same
/// way and then reset, so the checkout is still at its base.
fn fixture_patch(root: &std::path::Path) -> String {
    let project = list_project(root).unwrap();
    let catalog = template_plan::catalog().unwrap();
    let fixer = catalog
        .iter()
        .find(|fixer| fixer.check_id == "standin.rule")
        .unwrap();
    let target = sitecmd_protocol::engine_abi::FixTarget {
        check_id: "standin.rule".into(),
        identity: "/".into(),
    };
    let template_plan::TemplateFix::Patches(patches) =
        template_plan::plan_finding(&project, target, fixer).unwrap()
    else {
        panic!("stand-in fixer did not offer a patch");
    };
    write_patches(project.wire(), root, patches, |path| {
        path.as_str() == "vercel.json"
    })
    .unwrap();
    repo::stage(root, &["vercel.json".into()]).unwrap();
    let diff = repo::staged_patch(root).unwrap();
    crate::core::git::run_git_command(
        root,
        &["reset", "--hard", "-q"],
        crate::constants::AUTOFIX_GIT_TIMEOUT,
        None,
    )
    .unwrap();
    diff
}

#[tokio::test]
async fn an_inactive_account_opens_nothing_and_exits_zero() {
    // An inactive publish claim can touch the checkout or request another endpoint.
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    write_artifact(
        &artifact_dir,
        &fixture_manifest(&head),
        &fixture_patch(repo_dir.path()),
    )
    .unwrap();
    let (origin, captured) = respond_in_sequence(vec![(
        ACCOUNT_INACTIVE_PROBLEM.to_string(),
        "403 Forbidden",
    )])
    .await;

    let (code, summary) = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect("an inactive account is not a failure");

    assert_eq!(code, 0);
    assert!(summary.contains(ACCOUNT_INACTIVE_NOTICE), "{summary}");
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(repo::head_sha(repo_dir.path()).unwrap(), head);
    assert!(repo::changed_paths(repo_dir.path()).unwrap().is_empty());
}

#[tokio::test]
async fn a_suspended_subscription_still_fails_the_publish_claim() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    write_artifact(&artifact_dir, &manifest(&head), "").unwrap();
    let (origin, _captured) = respond_in_sequence(vec![(
        ENTITLEMENT_SUSPENDED_PROBLEM.to_string(),
        "403 Forbidden",
    )])
    .await;

    let error = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect_err("a suspended subscription still fails the job");

    assert_eq!(
        error,
        "publish claim refused: entitlement_suspended (This subscription cannot watch its sites.)"
    );
}

#[tokio::test]
async fn a_publish_token_refused_as_inactive_pushes_nothing_and_exits_zero() {
    // A refused publish token can still cause a push or submit a result.
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    write_artifact(
        &artifact_dir,
        &fixture_manifest(&head),
        &fixture_patch(repo_dir.path()),
    )
    .unwrap();
    let (origin, captured) = respond_in_sequence(vec![
        (
            claim_body(&head).replace(CHECK_ID, "standin.rule"),
            "200 OK",
        ),
        (ACCOUNT_INACTIVE_PROBLEM.to_string(), "403 Forbidden"),
    ])
    .await;

    let (code, summary) = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect("an inactive account is not a failure");

    assert_eq!(code, 0);
    // The claim was accepted, so the job did run; only its result went unrecorded.
    assert!(
        summary.starts_with(ACCOUNT_INACTIVE_RESULT_NOTICE),
        "{summary}"
    );
    // No token came back, so nothing reached GitHub and no result followed.
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        request_line(&requests[1]),
        "POST /v1/fix-jobs/job_0123456789abcdef/publish-token HTTP/1.1"
    );
}

#[tokio::test]
async fn an_issue_token_refused_as_inactive_opens_no_issue_and_exits_zero() {
    // A refused issue token can still open an issue or submit a result.
    let route = "export async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const returnTo = searchParams.get(\"returnTo\") ?? \"/\";\n  return Response.redirect(new URL(returnTo, request.url), 302);\n}\n";
    let (repo_dir, head) = init_test_repo(&[
        ("package.json", "{\"name\":\"loop\"}"),
        ("app/api/signin/fixture-findings.txt", route),
    ])
    .unwrap();
    let key = sitecmd_protocol::sync::ProjectFingerprintKey::from_bytes([7_u8; 32]);
    let identity = key.location_hash("standin.rule", "app/api/signin/fixture-findings.txt");
    let located = crate::cli::autofix::brief::locate_findings(
        repo_dir.path(),
        &key,
        &[("code_scan.standin.rule".into(), identity.clone())],
    )
    .unwrap();
    let mut brief_manifest = manifest(&head);
    brief_manifest.brief = Some(crate::cli::autofix::brief::brief_artifact(
        "job_0123456789abcdef",
        1,
        &located,
    ));
    brief_manifest.findings = vec![ManifestFinding {
        check_id: "code_scan.standin.rule".into(),
        identity: identity.clone(),
        outcome: Some("issue_opened".into()),
    }];
    brief_manifest.write_set = Vec::new();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    write_artifact(&artifact_dir, &brief_manifest, "").unwrap();
    let mut claim: serde_json::Value = serde_json::from_str(&claim_body(&head)).unwrap();
    claim["findings"] = serde_json::json!([{
        "category": "security",
        "check_id": "code_scan.standin.rule",
        "class": "agent-easy",
        "fallback_class": null,
        "identity": identity,
    }]);
    let (origin, captured) = respond_in_sequence(vec![
        (claim.to_string(), "200 OK"),
        (ACCOUNT_INACTIVE_PROBLEM.to_string(), "403 Forbidden"),
    ])
    .await;

    let (code, summary) = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect("an inactive account is not a failure");

    assert_eq!(code, 0);
    // The claim was accepted, so the job did run; only its result went unrecorded.
    assert!(
        summary.starts_with(ACCOUNT_INACTIVE_RESULT_NOTICE),
        "{summary}"
    );
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        request_line(&requests[1]),
        "POST /v1/fix-jobs/job_0123456789abcdef/issue-token HTTP/1.1"
    );
}

#[tokio::test]
async fn a_result_refused_as_inactive_keeps_the_jobs_own_summary() {
    let (repo_dir, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    write_artifact(&artifact_dir, &manifest(&head), "").unwrap();
    let (origin, captured) = respond_in_sequence(vec![
        (claim_body(&head), "200 OK"),
        (ACCOUNT_INACTIVE_PROBLEM.to_string(), "403 Forbidden"),
    ])
    .await;

    let (code, summary) = run_with_witness(
        &args(origin, &artifact_dir, repo_dir.path()),
        "witness-token",
        true,
    )
    .await
    .expect("an inactive account is not a failure");

    assert_eq!(code, 0);
    assert!(
        summary.starts_with(&format!(
            "artifact carries nothing to publish\n{ACCOUNT_INACTIVE_RESULT_NOTICE}"
        )),
        "{summary}"
    );
    assert!(!summary.contains(ACCOUNT_INACTIVE_NOTICE), "{summary}");
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        request_line(&requests[1]),
        "POST /v1/fix-jobs/job_0123456789abcdef/result HTTP/1.1"
    );
}

#[test]
fn names_the_branch_and_pull_request_from_a_module_template() {
    // Publishing can use fallback text even when the module supplies template metadata.
    let job = fixture_claimed(&"0".repeat(40));
    let catalog = template_plan::catalog().unwrap();
    assert_eq!(branch_name(&job, &catalog), "sitecmd/rule-012345");
    let (title, body) = pull_request_text(&job, &fixture_manifest(&"0".repeat(40)), &catalog);
    assert_eq!(title, "Sample finding");
    assert!(body.contains("standin.rule"), "{body}");
    assert!(body.contains("job_0123456789abcdef"), "{body}");
}

#[test]
fn commits_a_regenerated_module_patch_as_the_claimed_bot() {
    // Publishing can commit artifact content or use the checkout owner as the author.
    let (repo_dir, head) =
        init_test_repo(&[("vercel.json", "{\n  \"cleanUrls\": true\n}\n")]).unwrap();
    let project = list_project(repo_dir.path()).unwrap();
    let catalog = template_plan::catalog().unwrap();
    let claimed = fixture_claimed(&head);
    let manifest = fixture_manifest(&head);
    let mut handed = HandedLines::default();
    let patches =
        template_plan::regenerate(&project, &claimed, &manifest, &catalog, &mut handed).unwrap();
    let (title, body) = pull_request_text(&claimed, &manifest, &catalog);
    let brief =
        check_publish_brief(project.wire(), Brief { title, body }, &handed, &patches).unwrap();
    write_patches(project.wire(), repo_dir.path(), patches, |path| {
        path.as_str() == "vercel.json"
    })
    .unwrap();
    let changed = vec!["vercel.json".to_string()];
    let committed = repo::commit(
        repo_dir.path(),
        &changed,
        COMMITTER_NAME,
        COMMITTER_EMAIL,
        &brief.as_brief().title,
    )
    .unwrap();
    assert_ne!(committed, head);
    assert!(std::fs::read_to_string(repo_dir.path().join("vercel.json"))
        .unwrap()
        .contains("\"example\":true"));
    let author = crate::core::git::run_git_command(
        repo_dir.path(),
        &["log", "-1", "--format=%an <%ae>%n%s"],
        crate::constants::AUTOFIX_GIT_TIMEOUT,
        None,
    )
    .unwrap();
    assert_eq!(
        author.stdout.trim(),
        "sitecmd-loop[bot] <1+sitecmd-loop[bot]@users.noreply.github.com>\nSample finding"
    );
}
