use super::integrations::{
    hydrate_integration_secrets_with, redact_integration_secrets,
    store_integration_secrets_with_durable_store, strip_tokens_from_extra,
};
use super::migrate_restored_credentials;
use super::migration::{
    has_legacy_key_migration_marker, migrate_credentials_impl,
    should_write_legacy_key_migration_marker, write_legacy_key_migration_marker,
};
use super::names::{
    key_name, legacy_key_name, legacy_token_key_name, token_key_name, KEYRING_PLACEHOLDER,
};
use super::store::{delete_secret, get_secret, set_secret, SECRET_TEST_GUARD};
use crate::integrations::{IntegrationConfig, IntegrationType};
use tauri::test::mock_app;

/// Refusal audit sink that drops entries: these tests assert on the config,
/// and no test may append to the real security log under the app-data
/// directory.
fn discarded_audit(_op: &str, _detail: serde_json::Value, _result: &str) {}

#[cfg(debug_assertions)]
fn clear_debug_secret_store() {
    super::store::DEBUG_SECRET_STORE
        .lock()
        .expect("debug store lock")
        .clear();
}

use crate::db::test_helpers::temp_db;

#[test]
fn strip_tokens_from_extra_preserves_non_secret_fields() {
    let extra = Some(serde_json::json!({
        "tokens": { "access_token": "secret" },
        "instance_url": "https://jira.example.com",
        "email": "ops@example.com"
    }));

    let stripped = strip_tokens_from_extra(extra).expect("extra should remain");

    assert!(stripped.get("tokens").is_none());
    assert_eq!(
        stripped
            .get("instance_url")
            .and_then(|value| value.as_str()),
        Some("https://jira.example.com")
    );
    assert_eq!(
        stripped.get("email").and_then(|value| value.as_str()),
        Some("ops@example.com")
    );
}

#[test]
fn redact_integration_secrets_removes_api_key_and_tokens() {
    let mut config = IntegrationConfig {
        integration_type: IntegrationType::Jira,
        api_key: Some("jira-secret".to_string()),
        site_id: None,
        extra: Some(serde_json::json!({
            "tokens": { "refresh_token": "refresh" },
            "project_key": "OPS"
        })),
        enabled: true,
    };

    redact_integration_secrets(&mut config);

    assert_eq!(config.api_key, None);
    assert_eq!(
        config
            .extra
            .as_ref()
            .and_then(|extra| extra.get("project_key"))
            .and_then(|value| value.as_str()),
        Some("OPS")
    );
    assert!(config
        .extra
        .as_ref()
        .and_then(|extra| extra.get("tokens"))
        .is_none());
}

#[test]
fn ephemeral_debug_secret_store_keeps_credentials_in_db_shape() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let db = temp_db();
    let project_id = db
        .upsert_project("Debug Secrets", "/tmp/debug-secrets", Some("astro"))
        .expect("project");
    let config = IntegrationConfig {
        integration_type: IntegrationType::Plausible,
        api_key: Some("plausible-secret".to_string()),
        site_id: Some("sitecmd.com".to_string()),
        extra: Some(serde_json::json!({
            "tokens": { "access_token": "oauth-secret" },
            "label": "dev"
        })),
        enabled: true,
    };

    let sanitized =
        store_integration_secrets_with_durable_store(app.handle(), &db, project_id, &config, false)
            .expect("debug store should preserve config");

    assert_eq!(sanitized.api_key.as_deref(), Some("plausible-secret"));
    assert_eq!(
        sanitized
            .extra
            .as_ref()
            .and_then(|extra| extra.pointer("/tokens/access_token"))
            .and_then(|value| value.as_str()),
        Some("oauth-secret")
    );
}

#[test]
fn license_key_round_trips_through_the_app_keyring() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let handle = app.handle();

    assert!(
        super::get_license_key(handle).expect("read").is_none(),
        "no license key before store"
    );
    super::store_license_key(handle, "lc-secret-123").expect("store");
    assert_eq!(
        super::get_license_key(handle).expect("read").as_deref(),
        Some("lc-secret-123")
    );
    super::delete_license_key(handle).expect("delete");
    assert!(
        super::get_license_key(handle).expect("read").is_none(),
        "license key cleared after delete"
    );
}

#[test]
fn telemetry_delete_secret_round_trips_through_the_app_keyring() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let handle = app.handle();
    let secret = "delete_0123456789abcdef0123456789abcdef";

    assert!(
        super::get_telemetry_delete_secret(handle)
            .expect("read")
            .is_none(),
        "no deletion secret before store"
    );
    super::store_telemetry_delete_secret(handle, secret).expect("store");
    assert_eq!(
        super::get_telemetry_delete_secret(handle)
            .expect("read")
            .as_deref(),
        Some(secret)
    );
    super::delete_telemetry_delete_secret(handle).expect("delete");
    assert!(
        super::get_telemetry_delete_secret(handle)
            .expect("read")
            .is_none(),
        "deletion secret cleared after delete"
    );
}

#[test]
fn connected_installation_token_is_global_and_fingerprint_keys_are_project_scoped() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let db = temp_db();
    let first = db
        .upsert_project("First", "/tmp/connected-first", None)
        .expect("first project");
    let second = db
        .upsert_project("Second", "/tmp/connected-second", None)
        .expect("second project");
    let site_id = "site_9f2c81d0a4b3";

    super::store_connected_installation_token(app.handle(), "token-first").expect("store token");
    super::store_project_fingerprint_key(app.handle(), &db, first, site_id, [7_u8; 32])
        .expect("store key");

    assert_eq!(
        super::get_connected_installation_token(app.handle())
            .expect("read token")
            .as_deref(),
        Some("token-first")
    );
    let key = super::get_project_fingerprint_key(app.handle(), &db, first, site_id)
        .expect("read key")
        .expect("stored key");
    assert_eq!(
        key.location_hash("rule", "src/main.rs"),
        sitecmd_engine::sync::ProjectFingerprintKey::from_bytes([7_u8; 32])
            .location_hash("rule", "src/main.rs")
    );
    assert_eq!(
        super::get_connected_installation_token(app.handle())
            .expect("read installation token")
            .as_deref(),
        Some("token-first"),
        "one installation token authorizes its assigned sites"
    );
    assert!(
        super::get_project_fingerprint_key(app.handle(), &db, second, site_id)
            .expect("read other project")
            .is_none(),
        "one project's fingerprint key must not be visible to another"
    );
    super::delete_connected_site_secrets(app.handle(), &db, first, site_id)
        .expect("delete site key");
    assert_eq!(
        super::get_connected_installation_token(app.handle())
            .expect("token survives site disconnect")
            .as_deref(),
        Some("token-first")
    );
}

#[test]
fn connected_installation_token_reads_strictly() {
    let source = include_str!("connected.rs");
    assert!(source.contains("get_secret_strict(app, INSTALLATION_TOKEN_USER)"));
}

// These sole handles on server-side slots must not turn keychain read errors
// into absent values. The debug store cannot exercise that failure mode.
#[test]
fn slot_handle_secrets_read_strictly() {
    let source = include_str!("app_secrets.rs");
    for user in [
        "CATALOG_TOKEN_USER",
        "PENDING_ACTIVATION_NONCE_USER",
        "PENDING_RELEASE_USER",
        "LICENSE_KEY_USER",
    ] {
        assert!(
            source.contains(&format!("get_secret_strict(app, {user})")),
            "{user} must be read via get_secret_strict, not the lenient get_secret"
        );
    }
}

fn release(
    key: &str,
    installation: &str,
    catalog: bool,
    lemonsqueezy: bool,
) -> super::PendingRelease {
    super::PendingRelease {
        license_key: key.to_string(),
        installation_id: installation.to_string(),
        catalog,
        lemonsqueezy,
    }
}

#[test]
fn an_unreadable_tombstone_record_errs_instead_of_reading_as_empty() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    clear_debug_secret_store();
    let app = mock_app();
    let handle = app.handle();

    set_secret(handle, "app:catalog_pending_release", "{ not a list").expect("seed garbage");

    let read = super::get_pending_releases(handle).expect_err("garbage must not read as empty");
    assert!(read.to_string().contains("unreadable"), "{read}");
    match &read {
        super::app_secrets::PendingReleaseReadError::Undecodable { raw, .. } => {
            assert_eq!(raw, "{ not a list", "the error carries the bytes it read");
        }
        other => panic!("garbage is Undecodable, not {other:?}"),
    }

    super::store_pending_release(handle, release("key-1", "inst-1", true, false))
        .expect("a new owed release must survive a corrupt blob");
    assert_eq!(
        super::get_pending_releases(handle).expect("fresh list readable"),
        vec![release("key-1", "inst-1", true, false)],
        "the new tombstone starts a fresh list"
    );
    assert_eq!(
        get_secret(handle, "app:catalog_pending_release_quarantine").expect("quarantine readable"),
        Some("{ not a list".to_string()),
        "the unparseable record survives, verbatim, under quarantine"
    );
    delete_secret(handle, "app:catalog_pending_release").expect("cleanup");
    delete_secret(handle, "app:catalog_pending_release_quarantine").expect("cleanup");
}

// Only a successfully read but undecodable record may be quarantined.
#[test]
fn only_a_proven_undecodable_record_may_quarantine() {
    let source = include_str!("app_secrets.rs");
    let store = &source[source
        .find("pub fn store_pending_release")
        .expect("store_pending_release exists")..];
    let storage_arm = store
        .find("PendingReleaseReadError::Storage")
        .expect("the storage-failure arm exists");
    let undecodable_arm = store
        .find("PendingReleaseReadError::Undecodable")
        .expect("the undecodable arm exists");
    let quarantine = store
        .find("quarantine_pending_release_record(")
        .expect("the quarantine call exists");
    assert!(
        storage_arm < undecodable_arm && undecodable_arm < quarantine,
        "the quarantine sits under the Undecodable arm alone"
    );
    let storage_body = &store[storage_arm..undecodable_arm];
    assert!(
        storage_body.contains("return Err"),
        "a storage failure errs without mutation"
    );
    assert!(
        !storage_body.contains("quarantine_pending_release_record("),
        "a storage failure must never quarantine"
    );
    let quarantine_fn = &source[source
        .find("fn quarantine_pending_release_record")
        .expect("quarantine fn exists")..];
    let end = quarantine_fn.find("\n}").expect("fn body ends");
    assert!(
        !quarantine_fn[..end].contains("get_secret_strict"),
        "the quarantine writes the bytes it was handed, never a re-read"
    );
}

// Retry one transient read failure before abandoning the release tombstone.
#[test]
fn a_transient_storage_failure_gets_one_retry_before_the_release_is_lost() {
    let source = include_str!("app_secrets.rs");
    let store = &source[source
        .find("pub fn store_pending_release")
        .expect("store_pending_release exists")..];
    let retry_arm = store
        .find("PendingReleaseReadError::Storage(_)) if !retried")
        .expect("the transient retry arm exists");
    let give_up = store
        .find("nothing was changed and this release was not recorded")
        .expect("the give-up arm names the loss");
    assert!(retry_arm < give_up, "the retry precedes the give-up");
}

#[test]
fn merging_a_repeat_ors_the_owed_sides_instead_of_growing_the_list() {
    let merged = super::app_secrets::merge_pending_release(
        vec![release("key-1", "inst-1", true, false)],
        release("key-1", "inst-1", false, true),
    );
    assert_eq!(merged, vec![release("key-1", "inst-1", true, true)]);

    let appended = super::app_secrets::merge_pending_release(
        vec![release("key-1", "inst-1", true, false)],
        release("key-2", "inst-2", true, false),
    );
    assert_eq!(appended.len(), 2, "a different slot appends");
}

#[test]
fn settling_subtracts_only_what_this_pass_resolved() {
    let current = vec![
        release("key-1", "inst-1", true, true),
        release("key-2", "inst-2", true, false),
    ];
    let after = super::app_secrets::settle_pending_release(
        current,
        &release("key-1", "inst-1", true, true),
        true,
        false,
    );
    assert_eq!(
        after,
        vec![
            release("key-1", "inst-1", false, true),
            release("key-2", "inst-2", true, false),
        ],
        "the unresolved LemonSqueezy side and the untouched entry both survive"
    );

    let emptied = super::app_secrets::settle_pending_release(
        vec![release("key-1", "inst-1", false, true)],
        &release("key-1", "inst-1", false, true),
        false,
        true,
    );
    assert_eq!(emptied, vec![], "a fully settled record is removed");
}

#[test]
fn write_legacy_key_migration_marker_creates_the_marker_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("nested").join("legacy.marker");

    assert!(!has_legacy_key_migration_marker(&marker));
    write_legacy_key_migration_marker(&marker).expect("marker should be written");
    assert!(has_legacy_key_migration_marker(&marker));
}

#[test]
fn legacy_key_migration_marker_waits_for_clean_upgrade_pass() {
    assert!(should_write_legacy_key_migration_marker(true, false, true));
    assert!(!should_write_legacy_key_migration_marker(true, true, true));
    assert!(!should_write_legacy_key_migration_marker(
        true, false, false
    ));
    assert!(!should_write_legacy_key_migration_marker(
        false, false, true
    ));
}

#[test]
fn migrate_credentials_moves_plaintext_sqlite_credentials_into_secure_store() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let db = temp_db();
    let project_id = db
        .upsert_project(
            "Keyring Migration",
            "/tmp/keyring-migration",
            Some("nextjs"),
        )
        .expect("project");

    db.save_integration(
        project_id,
        &IntegrationConfig {
            integration_type: IntegrationType::Jira,
            api_key: Some("jira-secret".to_string()),
            site_id: None,
            extra: Some(serde_json::json!({
                "tokens": { "refresh_token": "refresh-secret" },
                "project_key": "OPS"
            })),
            enabled: true,
        },
    )
    .expect("save plaintext integration");

    let outcome = migrate_credentials_impl(app.handle(), &db, false).expect("migrate credentials");

    assert_eq!(outcome.migrated, 1);
    assert!(!outcome.had_failures);

    let configs = db.get_integrations(project_id).expect("integrations");
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].api_key.as_deref(), Some(KEYRING_PLACEHOLDER));
    assert!(configs[0]
        .extra
        .as_ref()
        .and_then(|extra| extra.get("tokens"))
        .is_none());
    assert_eq!(
        configs[0]
            .extra
            .as_ref()
            .and_then(|extra| extra.get("project_key"))
            .and_then(|value| value.as_str()),
        Some("OPS")
    );

    let namespace = db
        .ensure_project_secret_namespace(project_id)
        .expect("secret namespace");
    assert_eq!(
        get_secret(app.handle(), &key_name(&namespace, "jira")).expect("current api key"),
        Some("jira-secret".to_string())
    );
    assert_eq!(
        get_secret(app.handle(), &token_key_name(&namespace, "jira")).expect("current tokens"),
        Some(r#"{"refresh_token":"refresh-secret"}"#.to_string())
    );
}

#[test]
fn migrate_credentials_copies_legacy_id_keyring_entries_into_namespace_keys() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let db = temp_db();
    let project_id = db
        .upsert_project("Legacy Key Import", "/tmp/legacy-keys", Some("astro"))
        .expect("project");

    db.save_integration(
        project_id,
        &IntegrationConfig {
            integration_type: IntegrationType::GitHub,
            api_key: Some(KEYRING_PLACEHOLDER.to_string()),
            site_id: None,
            extra: None,
            enabled: true,
        },
    )
    .expect("save placeholder integration");

    set_secret(
        app.handle(),
        &legacy_key_name(project_id, "github"),
        "gh-secret",
    )
    .expect("seed legacy api key");
    set_secret(
        app.handle(),
        &legacy_token_key_name(project_id, "github"),
        r#"{"access_token":"legacy-token"}"#,
    )
    .expect("seed legacy token key");

    let outcome =
        migrate_credentials_impl(app.handle(), &db, true).expect("migrate legacy keyring");
    assert_eq!(outcome.migrated, 2);
    assert!(!outcome.had_failures);

    let namespace = db
        .ensure_project_secret_namespace(project_id)
        .expect("secret namespace");
    assert_eq!(
        get_secret(app.handle(), &key_name(&namespace, "github")).expect("current api key"),
        Some("gh-secret".to_string())
    );
    assert_eq!(
        get_secret(app.handle(), &token_key_name(&namespace, "github")).expect("current token key"),
        Some(r#"{"access_token":"legacy-token"}"#.to_string())
    );
    assert_eq!(
        get_secret(app.handle(), &legacy_key_name(project_id, "github"))
            .expect("legacy api key removed"),
        None
    );
    assert_eq!(
        get_secret(app.handle(), &legacy_token_key_name(project_id, "github"))
            .expect("legacy token key removed"),
        None
    );
}

#[test]
fn migrate_restored_credentials_does_not_consult_legacy_id_keyring_entries() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let db = temp_db();
    let project_id = db
        .upsert_project("Restored Project", "/tmp/restored-project", Some("react"))
        .expect("project");

    db.save_integration(
        project_id,
        &IntegrationConfig {
            integration_type: IntegrationType::GitHub,
            api_key: Some(KEYRING_PLACEHOLDER.to_string()),
            site_id: None,
            extra: None,
            enabled: true,
        },
    )
    .expect("save placeholder integration");

    set_secret(
        app.handle(),
        &legacy_key_name(project_id, "github"),
        "gh-secret",
    )
    .expect("seed legacy api key");

    let migrated =
        migrate_restored_credentials(app.handle(), &db).expect("migrate restored credentials");
    assert_eq!(migrated, 0);

    let namespace = db
        .ensure_project_secret_namespace(project_id)
        .expect("secret namespace");
    assert_eq!(
        get_secret(app.handle(), &key_name(&namespace, "github")).expect("current api key"),
        None
    );
    assert_eq!(
        get_secret(app.handle(), &legacy_key_name(project_id, "github"))
            .expect("legacy api key still present"),
        Some("gh-secret".to_string())
    );
    delete_secret(app.handle(), &legacy_key_name(project_id, "github"))
        .expect("cleanup legacy api key");
}

#[test]
fn hydrate_refuses_unmigrated_plaintext_credentials() {
    let _guard = SECRET_TEST_GUARD.lock().expect("secret test guard");
    #[cfg(debug_assertions)]
    clear_debug_secret_store();

    let app = mock_app();
    let db = temp_db();
    let project_id = db
        .upsert_project("Unmigrated", "/tmp/unmigrated", Some("astro"))
        .expect("project");
    let mut config = IntegrationConfig {
        integration_type: IntegrationType::Plausible,
        api_key: Some("still-plaintext".to_string()),
        site_id: Some("sitecmd.com".to_string()),
        extra: Some(serde_json::json!({
            "tokens": { "access_token": "still-plaintext" },
            "label": "dev"
        })),
        enabled: true,
    };

    hydrate_integration_secrets_with(app.handle(), &db, project_id, &mut config, &discarded_audit);

    assert_eq!(
        config.api_key.as_deref(),
        Some(KEYRING_PLACEHOLDER),
        "a plaintext SQLite key must never be used once the durable store is the boundary; the placeholder makes the integration report reconnect"
    );
    assert!(config
        .extra
        .as_ref()
        .and_then(|extra| extra.get("tokens"))
        .is_none());
    assert_eq!(
        config
            .extra
            .as_ref()
            .and_then(|extra| extra.get("label"))
            .and_then(|value| value.as_str()),
        Some("dev")
    );
}

#[test]
fn scheduler_configs_drop_unmigrated_plaintext_before_resolution() {
    let plaintext = IntegrationConfig {
        integration_type: IntegrationType::GitHub,
        api_key: Some("ghp_plaintext".to_string()),
        site_id: Some("owner/repo".to_string()),
        extra: None,
        enabled: true,
    };
    let placeholder = IntegrationConfig {
        integration_type: IntegrationType::GitHub,
        api_key: Some(KEYRING_PLACEHOLDER.to_string()),
        site_id: Some("owner/repo".to_string()),
        extra: None,
        enabled: true,
    };
    let cleaned = super::without_unmigrated_plaintext_secrets_with(
        vec![plaintext, placeholder],
        &discarded_audit,
    );
    assert_eq!(
        cleaned[0].api_key.as_deref(),
        Some(KEYRING_PLACEHOLDER),
        "the plaintext value is replaced by the placeholder, never carried through"
    );
    assert_eq!(cleaned[1].api_key.as_deref(), Some(KEYRING_PLACEHOLDER));
}
