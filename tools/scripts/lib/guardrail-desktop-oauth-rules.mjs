export function desktopOAuthSafetyFailures(read) {
  const buildScript = read("apps/desktop/src-tauri/build_config.rs");
  const oauthCommands = read("apps/desktop/src-tauri/src/commands/oauth.rs");
  const googleOAuth = read("apps/desktop/src-tauri/src/integrations/google_oauth.rs");
  const githubOAuth = read("apps/desktop/src-tauri/src/integrations/github_oauth.rs");
  const googleOAuthProduction = googleOAuth.split("#[cfg(test)]")[0];
  const githubOAuthProduction = githubOAuth.split("#[cfg(test)]")[0];
  const tokenForms = [
    googleOAuthProduction
      .split("fn build_token_exchange_form")[1]
      ?.split("fn build_token_refresh_form")[0],
    googleOAuthProduction
      .split("fn build_token_refresh_form")[1]
      ?.split("#[tracing::instrument")[0],
  ];
  const failures = [];

  if (
    !buildScript.includes('"GOOGLE_CLIENT_SECRET"') ||
    !googleOAuthProduction.includes('option_env!("GOOGLE_CLIENT_SECRET")') ||
    tokenForms.some((source) => !source?.includes('form.push(("client_secret", secret));')) ||
    !/build_token_exchange_form\(\s*client_id,\s*client_secret\(\),/.test(googleOAuthProduction) ||
    !/build_token_refresh_form\(\s*client_id,\s*client_secret\(\),/.test(googleOAuthProduction)
  ) {
    failures.push(
      "Desktop Google OAuth must embed the configured GOOGLE_CLIENT_SECRET and include it in both token exchange and refresh requests.",
    );
  }

  if (
    !googleOAuthProduction.includes("generate_pkce_pair") ||
    !googleOAuthProduction.includes('("code_verifier", code_verifier)') ||
    !oauthCommands.includes("&pkce.challenge") ||
    !oauthCommands.includes("&pending.code_verifier")
  ) {
    failures.push(
      "Desktop Google OAuth must retain PKCE generation, authorization challenge, and token-exchange verifier binding.",
    );
  }

  if (
    !githubOAuthProduction.includes('pub const SCOPES: &[&str] = &["repo"];') ||
    githubOAuthProduction.includes('"read:org"')
  ) {
    failures.push(
      "Desktop GitHub classic OAuth must not request unrelated organization scope; keep the current integration limited to repo until it migrates to a fine-grained GitHub App.",
    );
  }

  if (
    [googleOAuthProduction, githubOAuthProduction].some(
      (source) =>
        source.includes("crate::http_client::client()") ||
        source.includes(".json().await") ||
        source.includes(".text().await"),
    ) ||
    !googleOAuthProduction.includes("credentialed_service_client") ||
    !githubOAuthProduction.includes("credentialed_service_client") ||
    !googleOAuthProduction.includes("OAUTH_RESPONSE_MAX_BYTES") ||
    !githubOAuthProduction.includes("OAUTH_RESPONSE_MAX_BYTES") ||
    !googleOAuthProduction.includes("read_json_limited") ||
    !githubOAuthProduction.includes("read_json_limited")
  ) {
    failures.push(
      "Desktop OAuth must use the strict no-redirect credentialed client and bounded response readers.",
    );
  }

  if (
    !googleOAuthProduction.includes("parse_callback_request") ||
    !googleOAuthProduction.includes("OAUTH_CALLBACK_IO_TIMEOUT") ||
    !googleOAuthProduction.includes("let callback_loop = async") ||
    !googleOAuthProduction.includes("400 Bad Request")
  ) {
    failures.push(
      "Google OAuth must keep listening after malformed localhost callbacks and bound each callback connection.",
    );
  }

  if (
    !githubOAuthProduction.includes('verification_uri.path() == "/login/device"') ||
    !githubOAuthProduction.includes('verification_uri.host_str() == Some("github.com")')
  ) {
    failures.push(
      "GitHub OAuth must validate the provider-supplied verification URL before opening it.",
    );
  }

  return failures;
}
