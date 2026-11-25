//! Connection setup contract exercised only against local HTTP doubles.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::test_support::{success, Harness, Reply, REPOSITORY, SITE_URL};
use super::*;
use crate::cli::connect_repo::github_repository;
use crate::cli::connect_seal::seal_for_github;

#[test]
fn connect_repository_accepts_github_remotes_only() {
    // Bug: SSH origins or non-GitHub remotes can identify the wrong repository.
    for remote in [
        "https://github.com/o/r",
        "https://github.com/o/r.git",
        "git@github.com:o/r.git",
        "ssh://git@github.com/o/r.git",
    ] {
        assert_eq!(github_repository(remote).as_deref(), Some("o/r"));
    }
    for remote in [
        "https://gitlab.com/o/r.git",
        "https://github.com.evil.test/o/r",
        "git@github.com.evil.com:o/r",
        "ssh://git@github.com.evil.com/o/r",
        "https://user@github.com/o/r",
        "https://github.com/o/r/extra",
        "git@github.com:o/../r",
        "https://user:secret@github.com/o/r",
    ] {
        assert!(github_repository(remote).is_none());
    }
}

#[test]
fn connect_origin_normalization_has_one_project_key() {
    // Bug: an audit registered with a trailing slash cannot be found for the snapshot.
    for address in [
        "https://Example.com/",
        "https://example.com",
        "https://EXAMPLE.com/path?query#hash",
    ] {
        assert_eq!(normalized_origin(address).unwrap(), "https://example.com");
    }
    for address in [
        "http://example.com",
        "example.com",
        "https://user:secret@example.com",
        "file:///tmp/project",
    ] {
        assert_eq!(
            normalized_origin(address).unwrap_err(),
            "The address must be the site's https address, such as https://example.com."
        );
    }
}

#[test]
fn connect_seal_opens_as_a_github_sealed_box() {
    // Bug: generic authenticated encryption is incompatible with GitHub's sealed box API.
    let key = crypto_box::SecretKey::from_bytes([41; 32]);
    let value = Zeroizing::new(String::from("in-memory test value"));
    let sealed = seal_for_github(
        &STANDARD.encode(key.public_key().as_bytes()),
        value.as_bytes(),
    )
    .unwrap();
    let opened = Zeroizing::new(key.unseal(&STANDARD.decode(sealed).unwrap()).unwrap());
    assert!(opened.as_slice() == value.as_bytes());
    assert!(seal_for_github("invalid", value.as_bytes()).is_err());
    assert!(seal_for_github(&STANDARD.encode([0; 31]), value.as_bytes()).is_err());
}

#[tokio::test]
async fn connect_orders_baseline_secrets_revocation_and_report_and_exports_the_approved_key() {
    // Bug: setup can write secrets before a baseline or write an export unrelated to its passphrase.
    let harness = Harness::new(success(1)).await;
    let (result, stderr) = harness.run().await;
    let output = result.unwrap();
    assert_eq!(
        harness.routes(),
        [
            "POST /v1/cli/codes",
            "POST /v1/cli/token",
            "POST /v1/connect/baseline",
            "POST /v1/connect/secrets-token",
            "GET /repos/example-org/example-site/actions/secrets/public-key",
            "PUT /repos/example-org/example-site/actions/secrets/SITECMD_CONNECTION_EXPORT",
            "PUT /repos/example-org/example-site/actions/secrets/SITECMD_CONNECTION_PASSPHRASE",
            "DELETE /installation/token",
            "POST /v1/connect/secrets-provisioned",
        ]
    );
    assert!(stderr.starts_with("Auditing this checkout.\n"));
    assert!(stderr.contains("To connect example-org/example-site to example.com, open https://app.sitecmd.com/device and enter this code:\nBCDF-GHJK\nThe code works for 15 minutes. Waiting for you to approve it."));
    assert!(stderr.contains("Sent this checkout's findings as example.com's first code baseline."));
    assert_eq!(output, "Wrote SITECMD_CONNECTION_EXPORT and SITECMD_CONNECTION_PASSPHRASE to example-org/example-site's Actions secrets.\nexample-org/example-site is connected. SiteCMD's workflow runs once you merge its setup pull request.");
    let export = harness.opened_secret("SITECMD_CONNECTION_EXPORT");
    let passphrase = harness.opened_secret("SITECMD_CONNECTION_PASSPHRASE");
    let connection = crate::connected_export::decrypt_site_connection(
        std::str::from_utf8(&export).unwrap(),
        std::str::from_utf8(&passphrase).unwrap(),
    )
    .unwrap();
    assert_eq!(connection.site_id, "site-repo");
    assert_eq!(connection.fingerprint_key_version, 1);
    assert_eq!(connection.environment_scope_key, SITE_URL);
    assert_eq!(passphrase.len(), 43);
    let requests = harness.requests.lock().unwrap();
    let code: Value = serde_json::from_str(&requests[0].body).unwrap();
    let baseline: Value = serde_json::from_str(&requests[2].body).unwrap();
    assert_eq!(code["url"], "https://example.com");
    assert_eq!(code["repository"], REPOSITORY);
    assert_eq!(code["rotate"], false);
    assert_eq!(baseline["schema_version"], 1);
    assert_eq!(baseline["site_id"], "site-repo");
    assert_eq!(
        baseline["snapshot"]["versions"]["fingerprint_key_version"],
        1
    );
    assert_eq!(baseline["snapshot"]["key_commitment"], code["commitment"]);
    assert!(
        code["commitment"]
            == sitecmd_protocol::sync::ProjectFingerprintKey::from_bytes(
                connection.fingerprint_key
            )
            .commitment()
    );
    assert!(requests[2..4].iter().all(|r| r.connection_bearer));
    assert!(requests[4..8].iter().all(|r| r.github_bearer));
    assert!(requests[8].connection_bearer);
    assert_eq!(
        serde_json::from_str::<Value>(&requests[8].body).unwrap(),
        json!({"token_revoked":true})
    );
    let basis = baseline["snapshot"]["code_basis"].to_string();
    assert!(basis.contains(&harness.head));
    for forbidden in [
        std::str::from_utf8(&export).unwrap(),
        std::str::from_utf8(&passphrase).unwrap(),
        "ghs_FIXTURE",
        "sitecmd_cnx_FIXTURE",
    ] {
        assert!(!output.contains(forbidden) && !stderr.contains(forbidden));
    }
}

#[tokio::test]
async fn connect_refused_baseline_never_requests_or_writes_secrets() {
    // Bug: a refused baseline can leave secrets for a key Connect never completed.
    for refusal in ["key-commitment-mismatch", "secrets-setup-unlinking"] {
        let mut replies = success(1);
        replies[2] = Reply::fixture(refusal);
        let harness = Harness::new(replies).await;
        let (result, _) = harness.run().await;
        let error = result.unwrap_err();
        let refusal = super::test_support::fixture(refusal);
        if refusal["body"]["code"] != "key_commitment_mismatch" {
            assert_eq!(error, "SiteCMD couldn't save this repository's first scan. Nothing was written to example-org/example-site. Try the same command again.");
        } else {
            assert!(error.starts_with("SiteCMD couldn't save this repository's first scan: "));
            assert!(error.ends_with("Nothing was written to example-org/example-site. Run the same command again once that's fixed."));
            assert!(error.contains(refusal["body"]["detail"].as_str().unwrap()));
        }
        assert_eq!(harness.routes().len(), 3);
    }
}

#[tokio::test]
async fn connect_admin_refusal_can_be_retried_without_rotate() {
    // Bug: a baseline accepted before an admin refusal can strand the site permanently.
    let mut replies = success(1);
    replies[3] = Reply::fixture("secrets-not-repository-admin");
    let harness = Harness::new(replies).await;
    let (result, stderr) = harness.run().await;
    assert!(stderr.contains("first code baseline"));
    assert_eq!(result.unwrap_err(), "Your GitHub account is not an admin of example-org/example-site now, so SiteCMD gave no token for its secrets. An admin of it can run the same command again.");
    assert_eq!(harness.routes().len(), 4);
    let retry = Harness::new(success(2)).await;
    let (result, stderr) = retry.run().await;
    let output = result.unwrap();
    assert!(output.contains("Wrote SITECMD_CONNECTION_EXPORT"));
    assert!(output.ends_with("example-org/example-site is connected. SiteCMD's workflow runs once you merge its setup pull request."));
    assert!(stderr.contains("Sent this checkout's findings under the new key."));
    let export = retry.opened_secret("SITECMD_CONNECTION_EXPORT");
    let passphrase = retry.opened_secret("SITECMD_CONNECTION_PASSPHRASE");
    let connection = crate::connected_export::decrypt_site_connection(
        std::str::from_utf8(&export).unwrap(),
        std::str::from_utf8(&passphrase).unwrap(),
    )
    .unwrap();
    assert_eq!(connection.fingerprint_key_version, 2);
    let requests = retry.requests.lock().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&requests[0].body).unwrap()["rotate"],
        false
    );
    assert_eq!(
        serde_json::from_str::<Value>(&requests[2].body).unwrap()["snapshot"]["versions"]
            ["fingerprint_key_version"],
        2
    );
}

#[tokio::test]
async fn connect_secret_refusals_revoke_and_never_report_provisioned() {
    // Bug: a failed public-key read or either secret PUT can report success or leak the installation token.
    for step in [4, 5, 6] {
        let mut replies = success(1);
        replies[step] = Reply::json(
            403,
            json!({"message":"ghs_FIXTURE must never be displayed"}),
        );
        replies[step + 1] = Reply {
            status: 204,
            body: Zeroizing::new(String::new()),
            retry_after: None,
        };
        let harness = Harness::new(replies).await;
        let (result, stderr) = harness.run().await;
        let error = result.unwrap_err();
        assert_eq!(error, "GitHub refused to write the secrets. Check that the SiteCMD app may manage this repository's secrets, then run the same command again.");
        assert_eq!(super::failure_exit_code(&error), 2);
        assert!(!stderr.contains("ghs_FIXTURE"));
        let routes = harness.routes();
        assert_eq!(routes.last().unwrap(), "DELETE /installation/token");
        assert!(!routes.iter().any(|r| r.ends_with("secrets-provisioned")));
    }
}

#[tokio::test]
async fn connect_records_both_receipts_and_reports_the_actual_revoke_result() {
    // Bug: an accepted incomplete provisioning receipt can be reported as a failure or misstate revocation.
    for report in [true, false] {
        let mut replies = success(1);
        replies[7] = Reply::json(503, json!({}));
        replies[8] = Reply::json(
            200,
            json!({"provisioned":report,"workflow_state":"setup_pr_open"}),
        );
        let harness = Harness::new(replies).await;
        let (result, _) = harness.run().await;
        let output = result.unwrap();
        assert!(
            output.starts_with("Wrote SITECMD_CONNECTION_EXPORT and SITECMD_CONNECTION_PASSPHRASE")
        );
        assert_eq!(
            output.contains(
                "SiteCMD could not write SITECMD_CI_TOKEN yet. It tries again on its own."
            ),
            !report
        );
        let requests = harness.requests.lock().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&requests[8].body).unwrap(),
            json!({"token_revoked":false})
        );
    }
}

#[tokio::test]
async fn connect_rotate_sends_rotate_and_reports_replaced_keys() {
    // Bug: the rotate flag can be lost or a rotation can be described as an initial connection.
    let mut harness = Harness::new(success(2)).await;
    harness.args.rotate = true;
    let (result, stderr) = harness.run().await;
    assert!(stderr.contains("To replace example.com's connection keys, open https://app.sitecmd.com/device and enter this code:"));
    assert!(result.unwrap().ends_with(
        "Replaced example.com's connection keys. The old export and passphrase no longer work."
    ));
    let requests = harness.requests.lock().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&requests[0].body).unwrap()["rotate"],
        true
    );
}

#[tokio::test]
async fn connect_maps_secrets_refusals_without_issuing_github_requests() {
    // Bug: suspended or unavailable installations can fall through to secret writes or expose raw errors.
    for (fixture, expected) in [
        ("secrets-installation-suspended", "The SiteCMD app's access to example-org/example-site is suspended on GitHub. Unsuspend it there, then run the same command again."),
        ("secrets-unavailable", "SiteCMD could not reach GitHub. Run the same command again later."),
    ] {
        let mut replies = success(1);
        replies[3] = Reply::fixture(fixture);
        let harness = Harness::new(replies).await;
        assert_eq!(harness.run().await.0.unwrap_err(), expected);
        assert_eq!(harness.routes().len(), 4);
    }
}

#[tokio::test]
async fn connect_validates_checkout_repository_and_url_before_contacting_connect() {
    // Bug: bad local inputs can request a code for an unrelated checkout or repository.
    let mut harness = Harness::new(success(1)).await;
    harness.args.url = "http://example.com".into();
    assert!(harness
        .run()
        .await
        .0
        .unwrap_err()
        .starts_with("The address must"));
    harness.args.url = "https://example.com".into();
    let checkout = harness.args.path.clone();
    let empty = tempfile::tempdir().unwrap();
    harness.args.path = Some(empty.path().to_path_buf());
    assert_eq!(
        harness.run().await.0.unwrap_err(),
        "Run sitecmd connect from a checkout of the site's repository."
    );
    harness.args.path = checkout;
    harness.args.repository = Some("owner/repo/extra".into());
    assert!(harness
        .run()
        .await
        .0
        .unwrap_err()
        .starts_with("Could not tell which GitHub repository this is."));
    assert!(harness.routes().is_empty());
}

#[tokio::test]
async fn connect_approval_fields_cannot_inject_terminal_output_or_invalid_keys() {
    // Bug: untrusted approval fields can inject terminal controls or wrap an invalid key version.
    for (field, value) in [
        (
            "repository",
            json!(format!("bad\u{1b}[2J\n{}", "x".repeat(300))),
        ),
        ("site_url", json!("https://site.example/\u{1b}\n")),
        ("key_version", json!(0)),
        ("key_version", json!(65536)),
    ] {
        let mut replies = success(1);
        let mut approved: Value = serde_json::from_str(&replies[1].body).unwrap();
        approved[field] = value;
        replies[1] = Reply::json(200, approved);
        let harness = Harness::new(replies).await;
        let (result, stderr) = harness.run().await;
        let error = result.unwrap_err();
        assert!(!error.contains('\u{1b}') && !stderr.contains('\u{1b}'));
        assert_eq!(harness.routes().len(), 2);
    }
}

#[tokio::test]
async fn connect_token_repository_mismatch_and_bad_public_key_still_revoke() {
    // Bug: a mismatched repository or malformed sealing key can leak an already issued token.
    for step in [3, 4] {
        let mut replies = success(1);
        if step == 3 {
            let mut token: Value = serde_json::from_str(&replies[3].body).unwrap();
            token["repository"] = json!("other/repository");
            replies[3] = Reply::json(200, token);
        } else {
            replies[4] = Reply::json(200, json!({"key_id":"key-id", "key":"invalid"}));
        }
        replies[step + 1] = Reply {
            status: 204,
            body: Zeroizing::new(String::new()),
            retry_after: None,
        };
        let harness = Harness::new(replies).await;
        assert!(harness.run().await.0.is_err());
        assert_eq!(
            harness.routes().last().unwrap(),
            "DELETE /installation/token"
        );
    }
}

#[tokio::test]
async fn connect_empty_baseline_detail_uses_the_owner_approved_sentence() {
    // Bug: an empty Connect detail can expose a pending-copy placeholder instead of a recovery instruction.
    let mut replies = success(1);
    let mut refusal = super::test_support::fixture("key-commitment-mismatch");
    refusal["body"]["detail"] = json!("");
    replies[2] = Reply::json(409, refusal["body"].clone());
    let harness = Harness::new(replies).await;
    assert_eq!(harness.run().await.0.unwrap_err(), "SiteCMD couldn't save this repository's first scan. Nothing was written to example-org/example-site. Try the same command again.");
    assert_eq!(harness.routes().len(), 3);
}
