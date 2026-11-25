use super::*;
use crate::connected_service::test_double::respond_in_sequence;

pub(super) fn fixture(name: &str) -> (String, &'static str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/connect/code-flow");
    let wire: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(format!("{name}.json"))).unwrap()).unwrap();
    let status = match wire["status"].as_u64().unwrap() {
        200 => "200 OK",
        400 => "400 Bad Request",
        503 => "503 Service Unavailable",
        _ => panic!("unexpected fixture status"),
    };
    (wire["body"].to_string(), status)
}

pub(super) fn stored(value: &str) -> StoredToken {
    StoredToken {
        token_id: "old-id".into(),
        token: zeroize::Zeroizing::new(value.into()),
    }
}

fn file_store(origin: &str, path: &std::path::Path) -> Arc<CredentialStore> {
    Arc::new(CredentialStore::for_test(
        origin,
        OriginSource::Repository,
        None,
        Some(path.into()),
    ))
}

pub(super) fn assert_private(output: &str) {
    for secret in [
        "DEVICECODEFIXTURE",
        "sitecmd_pat_FIXTURE",
        "old-bearer",
        "environment-bearer",
    ] {
        assert!(!output.contains(secret), "output exposed a credential");
    }
}

#[tokio::test]
async fn login_waits_saves_and_displays_exact_copy() {
    // Bug: login can finish before approval or print its bearer instead of the user code.
    let (origin, captured) = respond_in_sequence(vec![
        fixture("issued"),
        fixture("pending"),
        fixture("login"),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let store = file_store(&origin, &path);
    let mut stderr = Vec::new();
    let sleeps = std::cell::RefCell::new(Vec::new());
    let output = login_with(&origin, &store, &mut stderr, |delay| {
        sleeps.borrow_mut().push(delay.as_secs());
        Box::pin(async {})
    })
    .await
    .unwrap();
    assert_eq!(*sleeps.borrow(), [5]);
    assert_eq!(String::from_utf8(stderr).unwrap(), "To sign in, open https://app.sitecmd.com/device and enter this code:\nBCDF-GHJK\nThe code works for 15 minutes. Waiting for you to approve it.\n");
    let suffix = if cfg!(unix) {
        ", which only your user account can read"
    } else {
        ""
    };
    assert_eq!(
        output,
        format!(
            "Signed in to your SiteCMD account. The token is saved in {}{suffix}.",
            path.display()
        )
    );
    assert!(
        store.read_stored().unwrap().unwrap().token.as_str() == "sitecmd_pat_FIXTURE",
        "saved bearer mismatch"
    );
    assert_private(&output);
    let requests = captured.await.unwrap();
    assert!(requests[0].contains("\"kind\":\"login\""));
    assert!(requests
        .iter()
        .all(|request| !request.to_lowercase().contains("authorization:")));
}

#[tokio::test]
async fn login_rejects_a_malformed_device_code_before_displaying_the_user_code() {
    // Bug: login can display a user code for an invalid device authorization.
    let (body, status) = fixture("issued");
    let mut body: serde_json::Value = serde_json::from_str(&body).unwrap();
    body["device_code"] = "malformed device code".into();
    let (origin, captured) = respond_in_sequence(vec![(body.to_string(), status)]).await;
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&origin, &dir.path().join("credentials.json"));
    let mut stderr = Vec::new();
    let error = login_with(&origin, &store, &mut stderr, |_| Box::pin(async {}))
        .await
        .unwrap_err();
    assert_eq!(error, "could not request a SiteCMD sign-in code");
    assert!(stderr.is_empty());
    captured.await.unwrap();
}

#[tokio::test]
async fn login_terminal_refusals_save_nothing_and_exit_one() {
    // Bug: denial, expiry or a token limit can discard an earlier sign-in or report success.
    for (answer, expected) in [
        ("denied", "The request was denied in SiteCMD. Nothing was saved."),
        ("expired", "The code expired before it was approved. Run the command again for a new code."),
        ("token-limit", "Your SiteCMD account already holds the most personal tokens it may. Revoke one on your account's Personal tokens page, then sign in again."),
    ] {
        let (origin, captured) = respond_in_sequence(vec![fixture("issued"), fixture(answer)]).await;
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(&origin, &dir.path().join("credentials.json"));
        store.save(&stored("old-bearer"), &|_| {}).unwrap();
        let error = login_with(&origin, &store, &mut Vec::new(), |_| Box::pin(async {})).await.unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(failure_exit_code(&error), 1);
        assert!(store.read_stored().unwrap().unwrap().token.as_str() == "old-bearer", "refusal changed the earlier token");
        let requests = captured.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| !request.starts_with("DELETE ")));
        assert_private(&error);
    }
}

#[tokio::test]
async fn login_saves_replacement_then_retires_old_token_even_when_revoke_fails() {
    // Bug: each re-login can leave a live forgotten token until the account refuses another.
    for (response, notice) in [
        ((String::new(), "204 No Content"), "Revoked this computer's earlier SiteCMD token."),
        (fixture("secrets-unavailable"), "SiteCMD could not revoke this computer's earlier token. Revoke it on your account's Personal tokens page."),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let double = super::test_support::ConnectDouble::serve(vec![fixture("issued"), fixture("login"), response], Some(path.clone()), &["old-bearer"]).await;
        let origin = &double.origin;
        let store = file_store(origin, &path);
        store.save(&stored("old-bearer"), &|_| {}).unwrap();
        let mut stderr = Vec::new();
        let output = login_with(origin, &store, &mut stderr, |_| Box::pin(async {})).await.unwrap();
        assert!(store.read_stored().unwrap().unwrap().token.as_str() == "sitecmd_pat_FIXTURE", "saved bearer mismatch");
        assert!(String::from_utf8(stderr).unwrap().ends_with(&format!("{notice}\n")));
        assert_private(&output);
        let requests = double.captured.await.unwrap();
        assert!(double.replacement_saved.load(std::sync::atomic::Ordering::SeqCst), "earlier token was revoked before the replacement was saved");
        assert!(requests[2].starts_with("DELETE /v1/account/tokens/current "));
        assert!(requests[2].to_lowercase().contains("authorization: bearer old-bearer"), "wrong credential revoked");
    }
}

#[derive(Clone)]
struct RefusingStore;
impl LoginStore for RefusingStore {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        Ok(Vec::new())
    }
    fn save(
        &self,
        _: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        Err("could not save to the system credential store".into())
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        panic!("no saved token")
    }
}

#[tokio::test]
async fn login_failed_save_revokes_fresh_token_and_leaves_no_live_token() {
    // Bug: a failed save, including a locked keychain, can strand a freshly minted live token.
    let double = super::test_support::ConnectDouble::serve(
        vec![
            fixture("issued"),
            fixture("login"),
            (String::new(), "204 No Content"),
        ],
        None,
        &[],
    )
    .await;
    let error = login_with(&double.origin, &RefusingStore, &mut Vec::new(), |_| {
        Box::pin(async {})
    })
    .await
    .unwrap_err();
    assert_eq!(failure_exit_code(&error), 2);
    assert_private(&error);
    let requests = double.captured.await.unwrap();
    assert!(
        double.live.lock().unwrap().is_empty(),
        "minted token remains live on the Connect double"
    );
    assert_eq!(requests.len(), 3);
    assert!(requests[2].starts_with("DELETE /v1/account/tokens/current "));
    assert!(
        requests[2]
            .to_lowercase()
            .contains("authorization: bearer sitecmd_pat_fixture"),
        "fresh credential was not revoked"
    );
}

#[tokio::test]
async fn login_logout_deletes_locally_even_after_failed_revoke() {
    // Bug: logout can retain local credentials after a network revocation failure.
    for (response, success) in [
        ((String::new(), "204 No Content"), true),
        (fixture("secrets-unavailable"), false),
    ] {
        let (origin, captured) = respond_in_sequence(vec![response]).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = file_store(&origin, &path);
        store.save(&stored("old-bearer"), &|_| {}).unwrap();
        let mut stderr = Vec::new();
        let result = logout_with(&origin, &store, &mut stderr).await;
        let output = if success {
            result.unwrap()
        } else {
            let error = result.unwrap_err();
            assert_eq!(failure_exit_code(&error), 2);
            assert_eq!(error, format!("The token was removed from {}, but SiteCMD could not revoke it. Revoke it on your account's Personal tokens page.", path.display()));
            error
        };
        if success {
            assert_eq!(
                output,
                format!(
                    "Signed out. The token is revoked and removed from {}.",
                    path.display()
                )
            );
        }
        assert!(store.read_stored().unwrap().is_none());
        assert!(stderr.is_empty());
        let requests = captured.await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .to_lowercase()
                .contains("authorization: bearer old-bearer"),
            "wrong credential revoked"
        );
        assert_private(&output);
    }
}

#[tokio::test]
async fn login_logout_without_storage_calls_nothing() {
    // Bug: signing out without a saved token can contact Connect.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&origin, &dir.path().join("credentials.json"));
    let mut stderr = Vec::new();
    assert_eq!(
        logout_with(&origin, &store, &mut stderr).await.unwrap(),
        "No SiteCMD sign-in is saved on this computer."
    );
    use futures_util::FutureExt;
    assert!(listener.accept().now_or_never().is_none());
}

#[test]
fn login_origin_precedence() {
    // Bug: login can choose the wrong origin source or omit the unset-origin refusal.
    let cases = [
        (
            Some("https://flag.example"),
            Some("https://env.example"),
            Some("https://build.example"),
            OriginSource::Command,
            "https://flag.example",
        ),
        (
            None,
            Some("https://env.example"),
            Some("https://build.example"),
            OriginSource::Environment,
            "https://env.example",
        ),
        (
            None,
            None,
            Some("https://build.example"),
            OriginSource::Build,
            "https://build.example",
        ),
    ];
    for (flag, env, build, source, expected) in cases {
        let (origin, actual) = resolve_origin(flag, env, build, false).unwrap();
        assert_eq!(origin, expected);
        assert!(actual == source);
    }
    assert_eq!(
        resolve_origin(None, None, None, false).err().unwrap(),
        "No SiteCMD Connect is set. Pass --connect-origin or set SITECMD_CONNECT_ORIGIN."
    );
}
