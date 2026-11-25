use super::test_support::ConnectDouble;
use super::tests::{assert_private, fixture, stored};
use super::*;
use crate::cli::credential_store::test_support::seed_pair;
use std::sync::Arc;

#[tokio::test]
async fn login_logout_environment_is_never_revoked_for_command_or_build_sources() {
    // Bug: logout can consume the shell bearer or omit W39 when the environment-presence check is flipped.
    const CHILD: &str = "SITECMD_LOGOUT_REGRESSION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::login::regression_tests::login_logout_environment_is_never_revoked_for_command_or_build_sources"])
            .env(CHILD, "1").env("SITECMD_TOKEN", "environment-bearer").output().unwrap();
        assert!(result.status.success(), "logout subprocess failed");
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
        return;
    }
    for source in [OriginSource::Command, OriginSource::Build] {
        for seeded in [false, true] {
            let double =
                ConnectDouble::serve(vec![(String::new(), "204 No Content"); 3], None, &[]).await;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("credentials.json");
            let store = Arc::new(CredentialStore::for_test(
                &double.origin,
                source,
                None,
                Some(path.clone()),
            ));
            if seeded {
                store.save(&stored("old-bearer"), &|_| {}).unwrap();
            }
            let mut stderr = Vec::new();
            let output = logout_with(&double.origin, &store, &mut stderr)
                .await
                .unwrap();
            let requests = double.captured.await.unwrap();
            assert_eq!(requests.len(), usize::from(seeded));
            assert!(
                requests
                    .iter()
                    .all(|request| !request.contains("environment-bearer")),
                "logout presented the environment bearer"
            );
            if seeded {
                assert!(
                    requests[0]
                        .to_lowercase()
                        .contains("authorization: bearer old-bearer"),
                    "logout used the wrong stored bearer"
                );
                assert_eq!(
                    output,
                    format!(
                        "Signed out. The token is revoked and removed from {}.",
                        path.display()
                    )
                );
            } else {
                assert_eq!(output, "No SiteCMD sign-in is saved on this computer.");
            }
            assert!(store.read_stored_all().unwrap().is_empty());
            assert_eq!(
                String::from_utf8(stderr).unwrap(),
                format!("{ENVIRONMENT_NOTICE}\n")
            );
        }
    }
}

#[tokio::test]
async fn login_keychain_commit_survives_file_cleanup_failure() {
    // Bug: a committed keychain save can be mistaken for failure, revoking N and forgetting K1.
    let double = ConnectDouble::serve(
        vec![
            fixture("issued"),
            fixture("login"),
            (String::new(), "204 No Content"),
            (String::new(), "204 No Content"),
        ],
        None,
        &["old-bearer", "file-bearer"],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let store = seed_pair(&double.origin, &dir.path().join("credentials.json"));
    store
        .test_faults
        .cleanup
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut stderr = Vec::new();
    let output = login_with(&double.origin, &store, &mut stderr, |_| Box::pin(async {})).await;
    let requests = double.captured.await.unwrap();
    assert!(output.is_ok(), "keychain commit was reported as failure");
    assert_eq!(requests.len(), 4);
    assert!(
        requests[2..]
            .iter()
            .all(|request| !request.contains("Bearer sitecmd_pat_FIXTURE")),
        "new token was revoked after its successful save"
    );
    for bearer in ["old-bearer", "file-bearer"] {
        assert!(
            requests[2..]
                .iter()
                .any(|request| request.contains(&format!("Bearer {bearer}"))),
            "earlier token was not retired"
        );
    }
    assert!(
        store.read_stored().unwrap().unwrap().token.as_str() == "sitecmd_pat_FIXTURE",
        "committed token was shadowed"
    );
    assert_eq!(double.live.lock().unwrap().len(), 1);
    assert!(String::from_utf8(stderr)
        .unwrap()
        .contains("Revoked this computer's earlier SiteCMD token."));
}

#[tokio::test]
async fn login_fallback_retires_keychain_entry_and_newest_file_wins_when_delete_fails() {
    // Bug: an inaccessible keychain write can leave a revoked keychain bearer shadowing the live file token.
    for failed_delete in [false, true] {
        let double = ConnectDouble::serve(
            vec![
                fixture("issued"),
                fixture("login"),
                (String::new(), "204 No Content"),
                (String::new(), "204 No Content"),
            ],
            None,
            &["old-bearer", "file-bearer"],
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = seed_pair(&double.origin, &path);
        store
            .test_faults
            .keyring_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
        store
            .test_faults
            .keyring_delete
            .store(failed_delete, std::sync::atomic::Ordering::SeqCst);
        let output = login_with(&double.origin, &store, &mut Vec::new(), |_| {
            Box::pin(async {})
        })
        .await
        .unwrap();
        assert!(output.contains(path.to_str().unwrap()));
        let requests = double.captured.await.unwrap();
        assert_eq!(requests.len(), 4);
        for bearer in ["old-bearer", "file-bearer"] {
            assert!(
                requests[2..]
                    .iter()
                    .any(|request| request.contains(&format!("Bearer {bearer}"))),
                "fallback did not retire an earlier bearer"
            );
        }
        assert_eq!(double.live.lock().unwrap().len(), 1);
        assert!(
            store.read_stored().unwrap().unwrap().token.as_str() == "sitecmd_pat_FIXTURE",
            "revoked keychain bearer shadows the live fallback"
        );
        let reopened = store.reopen_for_test();
        assert_eq!(
            reopened.read_stored_all().unwrap().len(),
            if failed_delete { 2 } else { 1 }
        );
        assert!(
            reopened.read_stored().unwrap().unwrap().token.as_str() == "sitecmd_pat_FIXTURE",
            "newest-token selection was not persisted"
        );
    }
}

#[tokio::test]
async fn login_keychain_copy_and_pair_revocations_are_printed() {
    // Bug: login can strand a file token or print the file-only privacy suffix for a keychain save.
    let mut named = fixture("login");
    let mut body: serde_json::Value = serde_json::from_str(&named.0).unwrap();
    body["account_name"] = "Example account".into();
    named.0 = body.to_string();
    let double = ConnectDouble::serve(
        vec![
            fixture("issued"),
            named,
            (String::new(), "204 No Content"),
            (String::new(), "204 No Content"),
        ],
        None,
        &["old-bearer", "file-bearer"],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let store = seed_pair(&double.origin, &dir.path().join("credentials.json"));
    let output = login_with(&double.origin, &store, &mut Vec::new(), |_| {
        Box::pin(async {})
    })
    .await
    .unwrap();
    assert_eq!(
        output,
        "Signed in to Example account. The token is saved in your system's keychain."
    );
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 4);
    for bearer in ["old-bearer", "file-bearer"] {
        assert!(
            requests[2..]
                .iter()
                .any(|request| request.contains(&format!("Bearer {bearer}"))),
            "a discarded store bearer was not revoked"
        );
    }
    assert_private(&output);
}

#[tokio::test]
async fn login_logout_names_every_store_that_held_a_token() {
    // Bug: logout can claim cleanup from only one of the stores that held a bearer.
    let double = ConnectDouble::serve(
        vec![(String::new(), "204 No Content"); 2],
        None,
        &["old-bearer", "file-bearer"],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let store = seed_pair(&double.origin, &path);
    let output = logout_with(&double.origin, &store, &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(
        output,
        format!(
            "Signed out. The token is revoked and removed from your system's keychain and {}.",
            path.display()
        )
    );
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 2);
    for bearer in ["old-bearer", "file-bearer"] {
        assert!(
            requests
                .iter()
                .any(|request| request.contains(&format!("Bearer {bearer}"))),
            "stored bearer was not revoked"
        );
    }
    assert!(store.read_stored_all().unwrap().is_empty());
}

#[derive(Clone)]
struct RefusesWithEarlier(Arc<CredentialStore>);
impl LoginStore for RefusesWithEarlier {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.0.read_stored_all()
    }
    fn save(
        &self,
        _: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        Err("could not save to the system credential store".into())
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        panic!("earlier token must remain stored")
    }
}

#[tokio::test]
async fn login_failed_save_preserves_earlier_tokens_and_reports_the_store_reason() {
    // Bug: failed persistence can revoke the earlier sign-in or hide failed-cleanup recovery.
    for failed_revoke in [false, true] {
        let response = if failed_revoke {
            fixture("secrets-unavailable")
        } else {
            (String::new(), "204 No Content")
        };
        let double = ConnectDouble::serve(
            vec![fixture("issued"), fixture("login"), response],
            None,
            &["old-bearer", "file-bearer"],
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let concrete = seed_pair(&double.origin, &dir.path().join("credentials.json"));
        let error = login_with(
            &double.origin,
            &RefusesWithEarlier(concrete.clone()),
            &mut Vec::new(),
            |_| Box::pin(async {}),
        )
        .await
        .unwrap_err();
        if failed_revoke {
            assert_eq!(error, "Couldn't sign you in, because this computer couldn't save your sign-in. Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again.");
        } else {
            assert_eq!(error, "could not save to the system credential store");
        }
        assert_eq!(failure_exit_code(&error), 2);
        assert!(
            concrete.read_stored_all().unwrap().len() == 2,
            "failed save changed the earlier sign-in"
        );
        let requests = double.captured.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(
            requests[2].contains("Bearer sitecmd_pat_FIXTURE"),
            "cleanup did not use the minted bearer"
        );
        assert!(
            requests[2..]
                .iter()
                .all(|request| !request.contains("Bearer old-bearer")
                    && !request.contains("Bearer file-bearer")),
            "failed save revoked the earlier token"
        );
    }
}

#[test]
fn login_blank_environment_falls_back_and_preserves_source() {
    // Bug: a blank origin can suppress fallback, lose its source or pass without executing its subprocess.
    const CHILD: &str = "SITECMD_LOGIN_BLANK_ORIGIN_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let actual = connect_origin(None);
        match option_env!("SITECMD_CONNECTED_ENDPOINT") {
            Some(_) => assert!(actual.unwrap().1 == OriginSource::Build),
            None => assert_eq!(actual.err().unwrap(), NO_ORIGIN),
        }
        std::env::set_var("SITECMD_CONNECT_ORIGIN", "https://env.example");
        let (origin, source) = connect_origin(None).unwrap();
        assert_eq!(origin, "https://env.example");
        assert!(source == OriginSource::Environment);
        let (origin, source) = connect_origin(Some("https://flag.example")).unwrap();
        assert_eq!(origin, "https://flag.example");
        assert!(source == OriginSource::Command);
        return;
    }
    let (origin, source) =
        resolve_origin(None, Some(" \t"), Some("https://build.example"), false).unwrap();
    assert_eq!(origin, "https://build.example");
    assert!(source == OriginSource::Build);
    for value in ["", " \t\n"] {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::login::regression_tests::login_blank_environment_falls_back_and_preserves_source"])
            .env(CHILD, "1").env("SITECMD_CONNECT_ORIGIN", value).output().unwrap();
        assert!(result.status.success(), "blank-origin subprocess failed");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "blank-origin subprocess did not execute its test"
        );
    }
}

#[tokio::test]
async fn login_dotted_origin_is_found_and_revoked_by_undotted_relogin() {
    // Bug: a DNS trailing dot can create a second stored identity and leave a live forgotten token.
    let mut next = fixture("login");
    let mut body: serde_json::Value = serde_json::from_str(&next.0).unwrap();
    body["token"] = "next-bearer".into();
    next.0 = body.to_string();
    let double = ConnectDouble::serve(
        vec![
            fixture("issued"),
            fixture("login"),
            fixture("issued"),
            next,
            (String::new(), "204 No Content"),
        ],
        None,
        &[],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    for (index, host) in ["localhost.", "localhost"].iter().enumerate() {
        let origin = double.origin.replace("127.0.0.1", host);
        let store = Arc::new(CredentialStore::for_test(
            &origin,
            OriginSource::Command,
            None,
            Some(path.clone()),
        ));
        let mut stderr = Vec::new();
        let result = login_with(&origin, &store, &mut stderr, |_| Box::pin(async {})).await;
        assert!(result.is_ok(), "canonical local origin was refused");
        if index == 1 {
            assert!(String::from_utf8(stderr)
                .unwrap()
                .contains("Revoked this computer's earlier SiteCMD token."));
        }
    }
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 5);
    assert!(
        requests[4].contains("Bearer sitecmd_pat_FIXTURE"),
        "dotted login was not retired"
    );
    assert_eq!(double.live.lock().unwrap().len(), 1);
}
