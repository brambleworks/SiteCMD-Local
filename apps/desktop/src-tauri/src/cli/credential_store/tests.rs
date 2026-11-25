use super::*;

fn token() -> StoredToken {
    StoredToken {
        token_id: "id-fixture".into(),
        token: zeroize::Zeroizing::new("private-fixture".into()),
    }
}

#[test]
fn file_round_trip_is_private_and_delete_removes_it() {
    // Bug: a saved CLI token can be readable by other users.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let store = CredentialStore::with_store("https://connect.example", None, Some(path.clone()));
    assert_eq!(
        store.save(&token(), &|_| {}).unwrap(),
        StoreLocation::File(path.clone())
    );
    let saved = store.read_stored().unwrap().unwrap();
    assert_eq!(saved.token_id, "id-fixture");
    assert_eq!(saved.token.as_str(), "private-fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        store.delete().unwrap(),
        Some(StoreLocation::File(path.clone()))
    );
    assert!(!path.exists());
    assert!(store.read_stored().unwrap().is_none());
    assert_eq!(store.delete().unwrap(), None);
}

#[test]
fn keyring_round_trips_through_core_mock_without_plaintext_copy() {
    // Bug: the CLI can bypass its OS credential backend.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let mock = keyring_core::mock::Store::new().unwrap();
    let store = CredentialStore::with_store(
        "https://connect.example",
        Some(mock.clone()),
        Some(path.clone()),
    );
    assert_eq!(
        store.save(&token(), &|_| {}).unwrap(),
        StoreLocation::Keyring
    );
    let reopened =
        CredentialStore::with_store("https://connect.example", Some(mock), Some(path.clone()));
    assert_eq!(
        reopened.read_stored().unwrap().unwrap().token.as_str(),
        "private-fixture"
    );
    assert!(!path.exists());
    assert_eq!(reopened.delete().unwrap(), Some(StoreLocation::Keyring));
    assert!(store.read_stored().unwrap().is_none());
}

#[test]
fn environment_precedes_storage_but_read_stored_ignores_it() {
    // Bug: a CI override can be ignored or mistaken for a persisted token.
    const CHILD: &str = "SITECMD_CREDENTIAL_TEST_CHILD";
    if let Ok(path) = std::env::var(CHILD) {
        let mut store =
            CredentialStore::with_store("https://connect.example", None, Some(path.into()));
        store.origin_source = OriginSource::Command;
        store.save(&token(), &|_| {}).unwrap();
        assert_eq!(
            store.read().unwrap().unwrap().token.as_str(),
            "environment-fixture"
        );
        assert_eq!(
            store.read_stored().unwrap().unwrap().token.as_str(),
            "private-fixture"
        );
        store.delete().unwrap();
        assert_eq!(
            store.read().unwrap().unwrap().token.as_str(),
            "environment-fixture"
        );
        let mut untrusted = store;
        untrusted.origin_source = OriginSource::Repository;
        assert!(untrusted.read().unwrap().is_none());
        untrusted.origin_source = OriginSource::Environment;
        assert_eq!(
            untrusted.read().unwrap().unwrap().token.as_str(),
            "environment-fixture"
        );
        let mut other =
            CredentialStore::with_store("https://other.example", None, untrusted.file_path.clone());
        other.origin_source = OriginSource::Environment;
        assert!(other.read().unwrap().is_none());

        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::credential_store::tests::environment_precedes_storage_but_read_stored_ignores_it",
        ])
        .env(CHILD, dir.path().join("credentials.json"))
        .env("SITECMD_TOKEN", "environment-fixture")
        .env(
            "SITECMD_CONNECT_ORIGIN",
            "HTTPS://CONNECT.EXAMPLE:443/path/",
        )
        .output()
        .unwrap();
    assert!(result.status.success(), "credential subprocess failed");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("1 passed"),
        "credential subprocess did not run its test"
    );
}

#[test]
fn a_token_from_the_environment_wins_over_the_keychain() {
    // Bug: a token saved in the keychain can shadow the SITECMD_TOKEN a CI job sets.
    const CHILD: &str = "SITECMD_KEYCHAIN_PRECEDENCE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let dir = tempfile::tempdir().unwrap();
        let mock = keyring_core::mock::Store::new().unwrap();
        let mut store = CredentialStore::with_store(
            "https://connect.example",
            Some(mock),
            Some(dir.path().join("credentials.json")),
        );
        store.origin_source = OriginSource::Command;
        assert_eq!(
            store.save(&token(), &|_| {}).unwrap(),
            StoreLocation::Keyring
        );
        assert_eq!(
            store.read().unwrap().unwrap().token.as_str(),
            "environment-fixture"
        );
        assert_eq!(
            store.read_stored().unwrap().unwrap().token.as_str(),
            "private-fixture"
        );
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::credential_store::tests::a_token_from_the_environment_wins_over_the_keychain",
        ])
        .env(CHILD, "1")
        .env("SITECMD_TOKEN", "environment-fixture")
        .output()
        .unwrap();
    assert!(result.status.success(), "credential subprocess failed");
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("1 passed"),
        "credential subprocess did not run its test"
    );
}

#[test]
fn file_credentials_are_scoped_to_connect_origin_and_errors_are_redacted() {
    // Bug: a token for one Connect origin can be sent to another origin.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let first = CredentialStore::with_store("https://one.example", None, Some(path.clone()));
    let second = CredentialStore::with_store("https://two.example", None, Some(path.clone()));
    first.save(&token(), &|_| {}).unwrap();
    assert!(second.read_stored().unwrap().is_none());
    second.save(&token(), &|_| {}).unwrap();
    first.delete().unwrap();
    assert!(second.read_stored().unwrap().is_some());
    std::fs::write(path, "private-fixture").unwrap();
    assert!(!second
        .read_stored()
        .unwrap_err()
        .contains("private-fixture"));
    assert!(!format!("{:?}", token()).contains("private-fixture"));
}

fn lock_next_operation(mock: &std::sync::Arc<keyring_core::mock::Store>, origin: &str) {
    use keyring_core::api::CredentialStoreApi;
    let entry = mock.build("sitecmd", origin, None).unwrap();
    entry
        .as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
        .unwrap()
        .set_error(Error::NoStorageAccess(Box::new(std::io::Error::other(
            "locked fixture",
        ))));
}

#[test]
fn logout_removes_file_token_after_the_keychain_unlocks() {
    // Bug: a file token saved while the keychain is locked can outlive logout.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let mock = keyring_core::mock::Store::new().unwrap();
    lock_next_operation(&mock, "https://connect.example");
    let locked = CredentialStore::with_store(
        "https://connect.example",
        Some(mock.clone()),
        Some(path.clone()),
    );
    assert_eq!(
        locked.save(&token(), &|_| {}).unwrap(),
        StoreLocation::File(path.clone())
    );
    let unlocked =
        CredentialStore::with_store("https://connect.example", Some(mock), Some(path.clone()));
    assert!(unlocked.read_stored().unwrap().is_some());
    assert_eq!(
        unlocked.delete().unwrap(),
        Some(StoreLocation::File(path.clone()))
    );
    assert!(!path.exists());
    assert!(locked.read_stored().unwrap().is_none());
}

#[test]
fn keychain_save_removes_the_older_file_copy_and_logout_clears_both() {
    // Bug: switching backends leaves forgotten credentials in the other store.
    use keyring_core::api::CredentialStoreApi;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let file = CredentialStore::with_store("https://connect.example", None, Some(path.clone()));
    file.save(&token(), &|_| {}).unwrap();
    let mock = keyring_core::mock::Store::new().unwrap();
    let keychain = CredentialStore::with_store(
        "https://connect.example",
        Some(mock.clone()),
        Some(path.clone()),
    );
    keychain.save(&token(), &|_| {}).unwrap();
    assert!(!path.exists());
    file.save(&token(), &|_| {}).unwrap();
    keychain.delete().unwrap();
    assert!(!path.exists());
    assert!(matches!(
        mock.build("sitecmd", "https://connect.example", None)
            .unwrap()
            .get_secret(),
        Err(Error::NoEntry)
    ));
}

#[test]
fn keychain_origins_are_normalized_and_distinct_hosts_and_ports_stay_separate() {
    // Bug: origin spelling can strand credentials or merge unrelated keychain entries.
    let mock = keyring_core::mock::Store::new().unwrap();
    let first = CredentialStore::with_store(
        "HTTPS://CONNECT.EXAMPLE:443/path/",
        Some(mock.clone()),
        None,
    );
    first.save(&token(), &|_| {}).unwrap();
    let equivalent =
        CredentialStore::with_store("https://connect.example", Some(mock.clone()), None);
    assert!(equivalent.read_stored().unwrap().is_some());
    for origin in [
        "https://other.example",
        "https://connect.example:444",
        "http://connect.example",
    ] {
        assert!(
            CredentialStore::with_store(origin, Some(mock.clone()), None)
                .read_stored()
                .unwrap()
                .is_none()
        );
    }
    equivalent.delete().unwrap();
    assert!(first.read_stored().unwrap().is_none());
}

#[test]
fn saving_a_file_replaces_the_inode_instead_of_truncating_it() {
    // Bug: an interrupted in-place credential rewrite can destroy the previous sign-in.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let old = dir.path().join("previous-inode.json");
    let store = CredentialStore::with_store("https://connect.example", None, Some(path.clone()));
    store.save(&token(), &|_| {}).unwrap();
    std::fs::hard_link(&path, &old).unwrap();
    let before = std::fs::read(&old).unwrap();
    let replacement = StoredToken {
        token_id: "new-id".into(),
        token: Zeroizing::new("new-fixture".into()),
    };
    store.save(&replacement, &|_| {}).unwrap();
    assert!(
        std::fs::read(&old).unwrap() == before,
        "previous inode was truncated"
    );
    assert_eq!(store.read_stored().unwrap().unwrap().token_id, "new-id");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn unavailable_keyring_falls_back_but_corrupt_keyring_data_is_not_downgraded() {
    // Bug: treating every keyring failure as unavailable can hide corrupt credentials.
    use keyring_core::api::CredentialStoreApi;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let mock = keyring_core::mock::Store::new().unwrap();
    let store = CredentialStore::with_store(
        "https://connect.example",
        Some(mock.clone()),
        Some(path.clone()),
    );
    lock_next_operation(&mock, "https://connect.example");
    assert_eq!(
        store.save(&token(), &|_| {}).unwrap(),
        StoreLocation::File(path.clone())
    );
    assert!(store.read_stored().unwrap().is_some());
    let entry = mock
        .build("sitecmd", "https://connect.example", None)
        .unwrap();
    entry.set_secret(b"not credential JSON").unwrap();
    assert!(store.read_stored().is_err());
}

#[cfg(any(unix, windows))]
#[test]
fn credential_reads_refuse_symlinks() {
    // Bug: a credential read can follow a planted symlink, including on Windows.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.json");
    let link = dir.path().join("credentials.json");
    let target_store =
        CredentialStore::with_store("https://connect.example", None, Some(target.clone()));
    target_store.save(&token(), &|_| {}).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, &link).unwrap();
    let store = CredentialStore::with_store("https://connect.example", None, Some(link));
    assert!(store.read_stored().is_err());
    assert!(store.save(&token(), &|_| {}).is_err());
    assert!(store.delete().is_err());
    assert!(target_store.read_stored().unwrap().is_some());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn native_constructor_inside_tokio_neither_panics_nor_stalls_the_runtime() {
    // Bug: zbus's tokio feature starts a nested runtime and panics during credential-store open.
    const CHILD: &str = "SITECMD_NATIVE_CONSTRUCTOR_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let started = std::time::Instant::now();
        let constructor = tokio::spawn(async { native_store().is_none() });
        let heartbeat = tokio::spawn(async {
            tokio::task::yield_now().await;
            true
        });
        assert!(constructor.await.expect("native constructor panicked"));
        assert!(heartbeat.await.unwrap());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "native constructor stalled the runtime"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "cli::credential_store::tests::native_constructor_inside_tokio_neither_panics_nor_stalls_the_runtime"])
        .env(CHILD, "1")
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", dir.path().join("absent-bus").display()))
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(3), command.output())
        .await
        .expect("native constructor blocked the runtime")
        .unwrap();
    assert!(
        output.status.success(),
        "native constructor subprocess failed"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
fn private_constructor_defaults_to_repository_origin() {
    // Bug: a trusted private-constructor default can silently reopen environment-token access.
    let store = CredentialStore::with_store("https://connect.sitecmd.com", None, None);
    assert!(matches!(store.origin_source, OriginSource::Repository));
    assert!(!store.environment_allowed());
}

#[test]
fn origins_with_userinfo_cannot_read_save_or_delete_credentials() {
    // Bug: accepting userinfo can associate a credential with the wrong authority.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let mock = keyring_core::mock::Store::new().unwrap();
    for origin in [
        "https://user:pass@connect.sitecmd.com",
        "https://user@connect.sitecmd.com",
        "https://:pass@connect.sitecmd.com",
        "https://connect.sitecmd.com@evil.example",
    ] {
        let store = CredentialStore::with_store(origin, Some(mock.clone()), Some(path.clone()));
        assert!(store.read_stored().is_err());
        assert!(store.read_stored_all().is_err());
        assert!(store.save(&token(), &|_| {}).is_err());
        assert!(store.delete().is_err());
        assert!(store.entry.is_none());
        assert!(!path.exists());
    }
}

#[test]
fn login_environment_bearer_applies_to_build_origin() {
    // Bug: the build-selected endpoint can lose its shell token.
    const CHILD: &str = "SITECMD_LOGIN_SOURCE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut store = CredentialStore::with_store("https://build.example", None, None);
        store.origin_source = OriginSource::Build;
        assert_eq!(
            store.read().unwrap().unwrap().token.as_str(),
            "environment-bearer"
        );
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::credential_store::tests::login_environment_bearer_applies_to_build_origin",
        ])
        .env(CHILD, "1")
        .env("SITECMD_TOKEN", "environment-bearer")
        .env_remove("SITECMD_CONNECT_ORIGIN")
        .output()
        .unwrap();
    assert!(result.status.success(), "source subprocess failed");
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
}

#[test]
fn login_future_stamps_are_observed_before_fallback_save() {
    // Bug: after clock rollback, unobserved persisted stamps can let a revoked keychain token shadow N.
    use keyring_core::api::CredentialStoreApi;
    const CHILD: &str = "SITECMD_FUTURE_STAMP_CHILD";
    if let Ok(source) = std::env::var(CHILD) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let mock = keyring_core::mock::Store::new().unwrap();
        let origin = "https://connect.example";
        let future =
            (jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24)).as_microsecond();
        let raw =
            serde_json::json!({ "token_id": "old-id", "token": "old-bearer", "saved_at": future });
        mock.build("sitecmd", origin, None)
            .unwrap()
            .set_secret(&Zeroizing::new(serde_json::to_vec(&raw).unwrap()))
            .unwrap();
        if source == "file" {
            let records = serde_json::json!({ origin: { "token_id": "file-id", "token": "file-bearer", "saved_at": future + 1 } });
            crate::app_identity::write_private_file(
                &path,
                &Zeroizing::new(serde_json::to_vec(&records).unwrap()),
            )
            .unwrap();
        }
        let store =
            CredentialStore::for_test(origin, OriginSource::Command, Some(mock), Some(path));
        if source == "keyring" {
            store.read_stored_all().unwrap();
        }
        store
            .test_faults
            .keyring_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
        store
            .test_faults
            .keyring_delete
            .store(true, std::sync::atomic::Ordering::SeqCst);
        store.save(&token(), &|_| {}).unwrap();
        assert!(
            store
                .read_stored()
                .unwrap()
                .is_some_and(|saved| saved.token.as_str() == "private-fixture"),
            "future-stamped stale record shadowed the newly saved token"
        );
        return;
    }
    for source in ["keyring", "file"] {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::credential_store::tests::login_future_stamps_are_observed_before_fallback_save"])
            .env(CHILD, source).output().unwrap();
        assert!(result.status.success(), "future-stamp subprocess failed");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "future-stamp child did not execute its test"
        );
    }
}
