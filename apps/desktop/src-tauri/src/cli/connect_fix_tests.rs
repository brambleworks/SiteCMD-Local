//! Fix-round regressions for setup refusals, reports and display bounds.

use serde_json::json;
use zeroize::Zeroizing;

use super::test_support::{fixture, success, Harness, Reply};
use super::*;

fn dropped() -> Reply {
    Reply {
        status: 0,
        body: Zeroizing::new(String::new()),
        retry_after: None,
    }
}

#[tokio::test]
async fn connect_baseline_transport_failure_uses_w249() {
    // Bug: W25 can quote local transport text as though it were Connect's own detail.
    let mut replies = success(1);
    replies[2] = dropped();
    let harness = Harness::new(replies).await;
    assert_eq!(harness.run().await.0.unwrap_err(), "SiteCMD couldn't save this repository's first scan. Nothing was written to example-org/example-site. Try the same command again.");
    assert_eq!(harness.routes().len(), 3);
}

#[tokio::test]
async fn connect_secrets_token_setup_refusals_print_their_own_detail() {
    // Bug: a recorded baseline can be contradicted by a W25 wrapper around a secrets-token refusal.
    for name in [
        "secrets-setup-ci-token",
        "secrets-setup-setup-pull-request",
        "secrets-setup-unlinking",
        "connection-spent",
        "baseline-required",
    ] {
        let mut replies = success(1);
        replies[3] = Reply::fixture(name);
        let expected = fixture(name)["body"]["detail"]
            .as_str()
            .unwrap()
            .to_string();
        let harness = Harness::new(replies).await;
        let (result, stderr) = harness.run().await;
        assert!(stderr.contains("first code baseline"));
        assert_eq!(result.unwrap_err(), expected);
        assert_eq!(harness.routes().len(), 4);
    }
}

#[tokio::test]
async fn connect_secrets_token_empty_or_transport_failure_uses_approved_recovery() {
    // Bug: a missing secrets-token detail can be presented as a baseline failure or local transport prose.
    for transport in [true, false] {
        let mut replies = success(1);
        let mut empty = fixture("secrets-setup-ci-token");
        empty["body"]["detail"] = json!("");
        replies[3] = if transport {
            dropped()
        } else {
            Reply::json(409, empty["body"].clone())
        };
        let harness = Harness::new(replies).await;
        assert_eq!(
            harness.run().await.0.unwrap_err(),
            "SiteCMD couldn't finish connecting example-org/example-site. Run the same command again."
        );
        assert_eq!(harness.routes().len(), 4);
    }
}

#[tokio::test]
async fn connect_provisioning_refusals_preserve_detail_after_revocation() {
    // Bug: the provisioned report can discard Connect's complete permission-recovery sentence.
    for name in [
        "secrets-setup-ci-token",
        "secrets-setup-setup-pull-request",
        "secrets-setup-unlinking",
    ] {
        let mut replies = success(1);
        replies[8] = Reply::fixture(name);
        let expected = fixture(name)["body"]["detail"]
            .as_str()
            .unwrap()
            .to_string();
        let harness = Harness::new(replies).await;
        assert_eq!(harness.run().await.0.unwrap_err(), expected);
        let routes = harness.routes();
        assert_eq!(routes[7], "DELETE /installation/token");
        assert_eq!(routes.len(), 9);
    }
}

#[tokio::test]
async fn connect_provisioning_empty_or_transport_failure_uses_approved_recovery() {
    // Bug: missing provisioning detail can falsely claim the secrets were not recorded and request a rotation.
    for transport in [true, false] {
        let mut replies = success(1);
        let mut empty = fixture("secrets-setup-ci-token");
        empty["body"]["detail"] = json!("");
        replies[8] = if transport {
            dropped()
        } else {
            Reply::json(409, empty["body"].clone())
        };
        let harness = Harness::new(replies).await;
        assert_eq!(
            harness.run().await.0.unwrap_err(),
            "SiteCMD couldn't finish connecting example-org/example-site. Run the same command again."
        );
        assert_eq!(harness.routes().len(), 9);
    }
}

#[tokio::test]
async fn connect_provisioning_retries_unavailable_with_retry_after() {
    // Bug: a retryable provisioning refusal can force an unnecessary rerun and key rotation.
    let mut replies = success(1);
    let mut unavailable = Reply::fixture("secrets-unavailable");
    unavailable.retry_after = Some(2);
    replies[8] = unavailable;
    replies.push(Reply::fixture("secrets-provisioned"));
    let harness = Harness::new(replies).await;
    assert!(harness
        .run()
        .await
        .0
        .unwrap()
        .starts_with("Wrote SITECMD_CONNECTION_EXPORT"));
    let requests = harness.requests.lock().unwrap();
    assert_eq!(requests.len(), 10);
    assert_eq!(requests[8].route, "POST /v1/connect/secrets-provisioned");
    assert_eq!(requests[9].route, requests[8].route);
    assert!(requests[9].body.as_bytes() == requests[8].body.as_bytes());
    assert_eq!(
        harness
            .waits
            .lock()
            .unwrap()
            .iter()
            .map(std::time::Duration::as_secs)
            .collect::<Vec<_>>(),
        vec![2]
    );
}

#[tokio::test]
async fn connect_provisioning_retries_are_bounded_and_end_with_approved_recovery() {
    // Bug: persistent unavailable reports can retry forever or print uncatalogued detail.
    let mut replies = success(1);
    let unavailable = || {
        let mut reply = Reply::fixture("secrets-unavailable");
        reply.retry_after = Some(0);
        reply
    };
    replies[8] = unavailable();
    replies.extend([unavailable(), unavailable()]);
    let harness = Harness::new(replies).await;
    assert_eq!(
        harness.run().await.0.unwrap_err(),
        "SiteCMD couldn't finish connecting example-org/example-site. Run the same command again."
    );
    assert_eq!(harness.routes().len(), 11);
}

#[test]
fn connect_rejects_addresses_with_ports() {
    // Bug: dropping a site address's port can connect a different origin than the person supplied.
    for address in [
        "https://example.com:8443",
        "https:/example.com:8443/?next=https://a",
        "https:example.com:8443/#://x",
        r"https:\\example.com:8443/a://b",
        "https:\\example.com:8443/a://b",
        "https:example.com:8443",
        "https:///example.com:8443",
        "https:////example.com:8443/x",
        "https://\\example.com:8443",
    ] {
        assert_eq!(
            normalized_origin(address).unwrap_err(),
            "The address must be the site's https address, such as https://example.com."
        );
    }
}

#[test]
fn connect_display_text_enforces_the_printable_character_cap() {
    // Bug: invalid-repository rejection can make a claimed display-cap assertion vacuous.
    let value = format!("\u{1b}\n{}", "界".repeat(201));
    let display = printable(&value, 200);
    assert_eq!(display.chars().count(), 200);
    assert!(display.chars().all(|c| c == '界'));
}
