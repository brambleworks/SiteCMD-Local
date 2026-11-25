//! Fix-round regressions for catalog-bound copy.

use serde_json::json;

use super::test_support::{fixture, success, Harness, Reply};

const RECOVERY: &str =
    "SiteCMD couldn't finish connecting example-org/example-site. Run the same command again.";
const BASELINE_RECOVERY: &str = "SiteCMD couldn't save this repository's first scan. Nothing was written to example-org/example-site. Try the same command again.";
const SUSPENDED: &str = "The SiteCMD app's access to example-org/example-site is suspended on GitHub. Unsuspend it there, then run the same command again.";

#[tokio::test]
async fn connect_secret_doors_replace_uncatalogued_details_with_w250() {
    // Bug: unauthorized and other documented codes can leak unapproved detail as the complete error.
    for step in [3, 8] {
        for (status, code, detail) in [
            (401, "unauthorized", "This request carried no credential this service accepts."),
            (409, "baseline_recorded", "This connection already sent its baseline."),
            (409, "key_commitment_mismatch", "The key this evidence was hashed under does not match the commitment registered for its claimed version."),
        ] {
            let mut replies = success(1);
            replies[step] = Reply::json(status, json!({"code": code, "detail": detail}));
            let harness = Harness::new(replies).await;
            assert_eq!(harness.run().await.0.unwrap_err(), RECOVERY);
            assert_eq!(harness.routes().len(), step + 1);
        }
    }
}

#[tokio::test]
async fn connect_baseline_uses_w249_for_unapproved_details() {
    // Bug: W25 can quote unauthorized, unavailable or setup details outside its approved catalog range.
    for name in [
        "secrets-unavailable",
        "secrets-setup-ci-token",
        "secrets-setup-setup-pull-request",
        "secrets-setup-unlinking",
        "secrets-installation-suspended",
    ] {
        let mut replies = success(1);
        replies[2] = Reply::fixture(name);
        let harness = Harness::new(replies).await;
        assert_eq!(harness.run().await.0.unwrap_err(), BASELINE_RECOVERY);
        assert_eq!(harness.routes().len(), 3);
    }
    for status in [401, 503] {
        let mut replies = success(1);
        replies[2] = Reply::json(
            status,
            json!({"code":"unauthorized", "detail":"This request carried no credential this service accepts."}),
        );
        let harness = Harness::new(replies).await;
        assert_eq!(harness.run().await.0.unwrap_err(), BASELINE_RECOVERY);
        assert_eq!(harness.routes().len(), 3);
    }
}

#[tokio::test]
async fn connect_baseline_preserves_approved_connection_and_epoch_details() {
    // Bug: narrowing the refusal set can erase approved connection-use and key-epoch recovery details.
    let mut answers: Vec<_> = [
        "baseline-recorded",
        "baseline-required",
        "connection-spent",
        "lookup-not-found",
        "key-commitment-mismatch",
    ]
    .into_iter()
    .map(|name| {
        let wire = fixture(name);
        (
            Reply::fixture(name),
            wire["body"]["detail"].as_str().unwrap().to_string(),
        )
    })
    .collect();
    for (code, detail) in [
        ("unclaimed_key_version", "No claim exists for this key version. Claim the rotation first; versions are assigned by the server, never adopted from a submission."),
        ("stale_key_version", "This evidence was hashed under a retired fingerprint key version. Update the key in this producer's secret store, then resubmit."),
        ("rotation_incomplete", "The rotation to this key version has not completed. Only a complete project snapshot through a governing door completes it; until then the previous version remains current."),
    ] {
        answers.push((Reply::json(409, json!({"code":code, "detail":detail})), detail.to_string()));
    }
    let baseline_required = fixture("baseline-required")["body"].clone();
    for status in [401, 503] {
        answers.push((
            Reply::json(status, baseline_required.clone()),
            baseline_required["detail"].as_str().unwrap().to_string(),
        ));
    }
    for (answer, expected) in answers {
        let mut replies = success(1);
        replies[2] = answer;
        let harness = Harness::new(replies).await;
        let error = harness.run().await.0.unwrap_err();
        assert_eq!(error, format!("SiteCMD couldn't save this repository's first scan: {expected} Nothing was written to example-org/example-site. Run the same command again once that's fixed."));
        assert_eq!(harness.routes().len(), 3);
    }
}

#[tokio::test]
async fn connect_provisioning_does_not_wait_past_the_retry_after_limit() {
    // Bug: deleting the delay ceiling can impose an unbounded wait before another provisioned request.
    let mut replies = success(1);
    let mut unavailable = Reply::fixture("secrets-unavailable");
    unavailable.retry_after = Some(31);
    replies[8] = unavailable;
    let harness = Harness::new(replies).await;
    let result = harness.run().await.0;
    assert_eq!(
        harness
            .routes()
            .iter()
            .filter(|r| r.ends_with("secrets-provisioned"))
            .count(),
        1
    );
    assert!(harness.waits.lock().unwrap().is_empty());
    assert_eq!(result.unwrap_err(), RECOVERY);
}

#[tokio::test]
async fn connect_known_secret_token_codes_choose_recovery_before_detail() {
    // Bug: an empty detail can hide the code-specific W33, W34 or W35 recovery instruction.
    for (name, expected) in [
        ("secrets-not-repository-admin", "Your GitHub account is not an admin of example-org/example-site now, so SiteCMD gave no token for its secrets. An admin of it can run the same command again."),
        ("secrets-installation-suspended", SUSPENDED),
        ("secrets-unavailable", "SiteCMD could not reach GitHub. Run the same command again later."),
    ] {
        let mut replies = success(1);
        let mut refusal = fixture(name);
        refusal["body"]["detail"] = json!("");
        replies[3] = Reply::json(refusal["status"].as_u64().unwrap() as u16, refusal["body"].clone());
        let harness = Harness::new(replies).await;
        assert_eq!(harness.run().await.0.unwrap_err(), expected);
        assert_eq!(harness.routes().len(), 4);
    }
}

#[tokio::test]
async fn connect_suspension_uses_w34_at_both_secret_doors() {
    // Bug: provisioning suspension can print W74 without the W34 recovery step, or fall back on empty detail.
    for step in [3, 8] {
        for empty in [false, true] {
            let mut replies = success(1);
            let mut refusal = fixture("secrets-installation-suspended");
            if empty {
                refusal["body"]["detail"] = json!("");
            }
            replies[step] = Reply::json(409, refusal["body"].clone());
            let harness = Harness::new(replies).await;
            assert_eq!(harness.run().await.0.unwrap_err(), SUSPENDED);
            assert_eq!(harness.routes().len(), step + 1);
        }
    }
}

#[tokio::test]
async fn connect_github_disconnection_prints_w237_at_both_secret_doors() {
    // Bug: an untested GitHub-connection allowlist arm can be removed and replace W237 with W250.
    for step in [3, 8] {
        let mut replies = success(1);
        let detail = "Connect GitHub with your own account first.";
        replies[step] = Reply::json(403, json!({"code":"github_not_connected", "detail":detail}));
        let harness = Harness::new(replies).await;
        assert_eq!(harness.run().await.0.unwrap_err(), detail);
        assert_eq!(harness.routes().len(), step + 1);
    }
}
