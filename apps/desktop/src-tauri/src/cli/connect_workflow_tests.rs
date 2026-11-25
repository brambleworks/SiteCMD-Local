//! Final connection messages follow Connect's workflow receipt.

use serde_json::json;

use super::test_support::{success, Harness, Reply};

#[tokio::test]
async fn connect_installed_workflow_reports_in_place() {
    // Bug: a repository whose workflow is merged still prints the merge instruction.
    let mut replies = success(1);
    replies[8] = Reply::fixture("secrets-provisioned-installed");
    let harness = Harness::new(replies).await;
    let (result, _) = harness.run().await;
    assert_eq!(
        result.unwrap().lines().last().unwrap(),
        "example-org/example-site is connected, and SiteCMD's workflow is in place."
    );
}

#[tokio::test]
async fn connect_open_workflow_reports_merge_instruction() {
    // Bug: an open setup pull request can be reported as an installed workflow.
    let harness = Harness::new(success(1)).await;
    let (result, _) = harness.run().await;
    assert_eq!(result.unwrap().lines().last().unwrap(),
        "example-org/example-site is connected. SiteCMD's workflow runs once you merge its setup pull request.");
}

#[tokio::test]
async fn connect_closed_workflow_reports_fixes_blocked() {
    // Bug: a closed setup pull request still prints the merge instruction.
    let mut replies = success(1);
    replies[8] = Reply::fixture("secrets-provisioned-setup-pr-closed");
    let harness = Harness::new(replies).await;
    let (result, _) = harness.run().await;
    assert_eq!(result.unwrap().lines().last().unwrap(),
        "The setup pull request was closed without merging. SiteCMD cannot run fixes until its workflow is in place.");
}

#[tokio::test]
async fn connect_workflow_fallback_preserves_pending_and_rotation_messages() {
    // Bug: a newer workflow state or incomplete CI write can fail setup or hide a rotation.
    for (state, rotate) in [
        ("setup_pending", false),
        ("future_state", false),
        ("installed", true),
        ("setup_pr_closed", true),
    ] {
        let mut replies = success(if rotate { 2 } else { 1 });
        replies[8] = Reply::json(200, json!({"provisioned":false, "workflow_state":state}));
        let mut harness = Harness::new(replies).await;
        harness.args.rotate = rotate;
        let (result, _) = harness.run().await;
        let output = result.unwrap();
        assert!(output
            .contains("SiteCMD could not write SITECMD_CI_TOKEN yet. It tries again on its own."));
        assert_eq!(
            output.lines().last().unwrap(),
            if rotate {
                "Replaced example.com's connection keys. The old export and passphrase no longer work."
            } else {
                "example-org/example-site is connected. SiteCMD's workflow runs once you merge its setup pull request."
            }
        );
    }
}
