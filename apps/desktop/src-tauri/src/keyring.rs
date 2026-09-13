//! Application secrets stored through the operating-system keychain.

mod app_secrets;
mod connected;
mod integrations;
mod migration;
mod names;
mod namespace;
mod store;

/// Test-only: serializes every test that touches the process-global debug
/// secret store, across modules. See the doc on the static itself.
#[cfg(test)]
pub(crate) use store::SECRET_TEST_GUARD;
mod webhooks;

pub use app_secrets::{
    delete_catalog_token, delete_license_key, delete_pagespeed_api_key, delete_pending_activation,
    delete_pending_connect_activation, delete_telemetry_delete_secret, get_catalog_token,
    get_license_key, get_pagespeed_api_key, get_pending_activation, get_pending_connect_activation,
    get_pending_releases, get_telemetry_delete_secret, replace_pending_releases,
    settle_pending_release, store_catalog_token, store_license_key, store_pagespeed_api_key,
    store_pending_activation, store_pending_connect_activation, store_pending_release,
    store_telemetry_delete_secret, PendingRelease,
};
pub(crate) use connected::get_project_fingerprint_key_bytes;
pub use connected::{
    delete_connected_installation_token, delete_connected_site_secrets,
    delete_pending_fingerprint_key, get_connected_installation_token, get_pending_fingerprint_key,
    get_project_fingerprint_key, promote_pending_fingerprint_key,
    store_connected_installation_token, store_pending_fingerprint_key,
    store_project_fingerprint_key,
};
pub use integrations::{
    audit_to_log, delete_api_key, delete_tokens, get_api_key, get_tokens,
    hydrate_integration_secrets, redact_integration_secrets, store_api_key,
    store_integration_secrets, store_tokens, without_unmigrated_plaintext_secrets,
    without_unmigrated_plaintext_secrets_with, RefusalAudit,
};
pub use migration::{
    mark_legacy_key_migration_complete, migrate_credentials, migrate_restored_credentials,
};
pub use names::KEYRING_PLACEHOLDER;
pub use webhooks::{
    delete_webhook_secret, delete_webhook_secret_for_url, get_webhook_secret,
    migrate_webhook_secrets, store_webhook_secret,
};

#[cfg(test)]
mod tests;
