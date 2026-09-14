//! Google OAuth persistence through the desktop keychain.

pub use sitecmd_runtime::integrations::google_oauth::*;

/// Resolve, refresh, and persist a Google token for desktop callers.
pub(crate) async fn resolve_valid_google_token_for_config(
    app: &tauri::AppHandle,
    db: &crate::db::Database,
    project_id: i64,
    config: &super::IntegrationConfig,
) -> Result<String, String> {
    let extra = config.extra.as_ref().ok_or("No credentials configured")?;
    let client_id = client_id();
    let tokens: GoogleTokens = serde_json::from_value(extra["tokens"].clone())
        .map_err(|e| format!("Invalid stored tokens: {}", e))?;

    let (access_token, refreshed) = get_valid_token(client_id, &tokens).await?;

    if let Some(new_tokens) = refreshed {
        let mut updated_extra = extra.clone();
        updated_extra["tokens"] = serde_json::to_value(&new_tokens).unwrap_or_default();
        let updated_config = super::IntegrationConfig {
            extra: Some(updated_extra),
            ..config.clone()
        };
        let sanitized =
            crate::keyring::store_integration_secrets(app, db, project_id, &updated_config)
                .map_err(|e| e.to_string())?;
        if let Err(e) = db.save_integration(project_id, &sanitized) {
            tracing::error!("Failed to persist refreshed OAuth token: {}", e);
        }
    }

    Ok(access_token)
}

/// Loads an enabled integration and resolves or refreshes its access token for
/// background polling. Missing configuration and dead refresh tokens fail
/// without sending an invalid token.
pub(crate) async fn resolve_valid_google_token(
    app: &tauri::AppHandle,
    db: &crate::db::Database,
    project_id: i64,
    integration_type: &super::IntegrationType,
) -> Result<String, String> {
    let configs = db.get_integrations(project_id).map_err(|e| e.to_string())?;
    let mut config = configs
        .into_iter()
        .find(|config| config.enabled && &config.integration_type == integration_type)
        .ok_or("Integration not configured")?;
    crate::keyring::hydrate_integration_secrets(app, db, project_id, &mut config);
    resolve_valid_google_token_for_config(app, db, project_id, &config).await
}
