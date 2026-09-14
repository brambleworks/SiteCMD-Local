//! Google OAuth authorization-code flow with a local callback and CSRF validation.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

mod token_error;

use token_error::{token_error_message, TokenOperation};

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Bundled OAuth client identifier - loaded from environment variables at runtime.
#[tracing::instrument]
pub fn client_id() -> &'static str {
    static ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        std::env::var("GOOGLE_CLIENT_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                option_env!("GOOGLE_CLIENT_ID")
                    .unwrap_or_default()
                    .to_string()
            })
    });
    &ID
}

fn client_secret() -> Option<&'static str> {
    static SECRET: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
        std::env::var("GOOGLE_CLIENT_SECRET")
            .ok()
            .or_else(|| option_env!("GOOGLE_CLIENT_SECRET").map(str::to_string))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    SECRET.as_deref()
}

/// Stored in integration_configs.extra as JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64, // unix timestamp
}

/// Scopes we request - read-only for analytics + search console + admin (for listing properties)
pub const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/analytics.readonly",
    "https://www.googleapis.com/auth/webmasters.readonly",
];

/// Generate a cryptographically random state string for CSRF protection.
#[tracing::instrument]
pub fn generate_state() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS RNG unavailable");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Build the authorization URL for the consent screen
#[tracing::instrument(skip(redirect_port, state, code_challenge), fields(client_id = %client_id, has_state = !state.is_empty()))]
pub fn build_auth_url(
    client_id: &str,
    redirect_port: u16,
    state: &str,
    code_challenge: &str,
) -> String {
    let redirect_uri = format!("http://localhost:{}/callback", redirect_port);
    let scope = SCOPES.join(" ");
    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}&code_challenge={}&code_challenge_method=S256",
        AUTH_URL,
        urlencoding::encode(client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
    )
}

/// Start a temporary TCP listener to catch the OAuth callback.
/// Returns (port, oneshot::Receiver<auth_code>).
/// The `expected_state` is verified against the `state` query parameter in the callback.
#[tracing::instrument(skip(expected_state), fields(has_expected_state = !expected_state.is_empty()))]
pub async fn start_callback_server(
    expected_state: String,
) -> Result<(u16, oneshot::Receiver<String>), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback server: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get port: {}", e))?
        .port();

    let (tx, rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        let callback_loop = async {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let n = match tokio::time::timeout(
                    crate::constants::OAUTH_CALLBACK_IO_TIMEOUT,
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) => n,
                    _ => {
                        let _ = stream.shutdown().await;
                        continue;
                    }
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let parsed = parse_callback_request(&request);
                let callback_valid = parsed
                    .as_ref()
                    .map(|(_, returned_state)| returned_state == &expected_state)
                    .unwrap_or(false);

                let (status_line, response_body) = if callback_valid {
                    (
                        "HTTP/1.1 200 OK",
                        r#"<html><head><meta charset="utf-8"></head><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f9fafb">
<div style="text-align:center">
  <h2 style="color:#16a34a">&#10003; Authorization received</h2>
  <p style="color:#6b7280">Returning you to SiteCMD...</p>
  <p style="margin-top:16px"><a href="sitecmd://connected" style="color:#2563eb;text-decoration:none;font-weight:500">Back to SiteCMD</a></p>
</div>
<script>setTimeout(function(){ window.location.href = "sitecmd://connected"; }, 400);</script>
</body></html>"#,
                    )
                } else {
                    (
                        "HTTP/1.1 400 Bad Request",
                        r#"<html><head><meta charset="utf-8"></head><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#fef2f2">
<div style="text-align:center"><h2 style="color:#dc2626">Request ignored</h2><p style="color:#6b7280">Continue authorization in the original browser tab.</p></div>
</body></html>"#,
                    )
                };

                let response = format!(
                    "{status_line}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body,
                );
                let _ = tokio::time::timeout(
                    crate::constants::OAUTH_CALLBACK_IO_TIMEOUT,
                    stream.write_all(response.as_bytes()),
                )
                .await;
                let _ = stream.shutdown().await;

                if let Some((code, _)) = parsed.filter(|_| callback_valid) {
                    let _ = tx.send(code);
                    return;
                }
            }
        };
        let _ = tokio::time::timeout(crate::constants::OAUTH_TIMEOUT, callback_loop).await;
    });

    Ok((port, rx))
}

fn parse_callback_request(request: &str) -> Option<(String, String)> {
    let mut parts = request.lines().next()?.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let request_target = parts.next()?;
    let parsed = url::Url::parse(&format!("http://localhost{request_target}")).ok()?;
    if parsed.path() != "/callback" {
        return None;
    }
    let code = parsed
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())?;
    let state = parsed
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())?;
    (!code.is_empty() && !state.is_empty()).then_some((code, state))
}

/// Exchange authorization code for tokens
#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Generate an OAuth PKCE verifier/challenge pair for public desktop clients.
#[tracing::instrument]
pub fn generate_pkce_pair() -> Result<PkcePair, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("OS RNG unavailable: {}", e))?;
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    Ok(PkcePair {
        verifier,
        challenge,
    })
}

fn build_token_exchange_form<'a>(
    client_id: &'a str,
    client_secret: Option<&'a str>,
    code_verifier: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
) -> Vec<(&'static str, &'a str)> {
    let mut form = vec![
        ("code", code),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];
    if let Some(secret) = client_secret
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
    {
        form.push(("client_secret", secret));
    }
    form
}

fn build_token_refresh_form<'a>(
    client_id: &'a str,
    client_secret: Option<&'a str>,
    refresh_token: &'a str,
) -> Vec<(&'static str, &'a str)> {
    let mut form = vec![
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("grant_type", "refresh_token"),
    ];
    if let Some(secret) = client_secret
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
    {
        form.push(("client_secret", secret));
    }
    form
}

#[tracing::instrument(skip(redirect_port, code, code_verifier), fields(client_id = %client_id))]
pub async fn exchange_code(
    client_id: &str,
    code_verifier: &str,
    code: &str,
    redirect_port: u16,
) -> Result<GoogleTokens, String> {
    let redirect_uri = format!("http://localhost:{}/callback", redirect_port);
    let client = crate::http_client::credentialed_service_client();
    let form = build_token_exchange_form(
        client_id,
        client_secret(),
        code_verifier,
        code,
        redirect_uri.as_str(),
    );

    let resp = client
        .post(TOKEN_URL)
        .form(&form)
        .timeout(crate::constants::API_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = crate::http_client::read_text_limited(
            resp,
            crate::constants::OAUTH_RESPONSE_MAX_BYTES,
            crate::constants::API_TIMEOUT_SHORT,
        )
        .await
        .unwrap_or_default();
        return Err(token_error_message(TokenOperation::Exchange, status, &body));
    }

    let json: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::OAUTH_RESPONSE_MAX_BYTES,
        crate::constants::API_TIMEOUT_SHORT,
    )
    .await
    .map_err(|e| format!("Failed to parse token response: {}", e))?;

    let access_token = json["access_token"]
        .as_str()
        .ok_or("Missing access_token")?
        .to_string();
    let refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());
    let expires_in = json["expires_in"].as_i64().unwrap_or(3600);
    let expires_at = chrono::Utc::now().timestamp() + expires_in;

    Ok(GoogleTokens {
        access_token,
        refresh_token,
        expires_at,
    })
}

/// Refresh an expired access token using the refresh token
#[tracing::instrument(skip(refresh_token), fields(client_id = %client_id))]
pub async fn refresh_access_token(
    client_id: &str,
    refresh_token: &str,
) -> Result<GoogleTokens, String> {
    let client = crate::http_client::credentialed_service_client();
    let form = build_token_refresh_form(client_id, client_secret(), refresh_token);

    let resp = client
        .post(TOKEN_URL)
        .form(&form)
        .timeout(crate::constants::API_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Token refresh failed: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = crate::http_client::read_text_limited(
            resp,
            crate::constants::OAUTH_RESPONSE_MAX_BYTES,
            crate::constants::API_TIMEOUT_SHORT,
        )
        .await
        .unwrap_or_default();
        return Err(token_error_message(TokenOperation::Refresh, status, &body));
    }

    let json: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::OAUTH_RESPONSE_MAX_BYTES,
        crate::constants::API_TIMEOUT_SHORT,
    )
    .await
    .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

    let access_token = json["access_token"]
        .as_str()
        .ok_or("Missing access_token in refresh response")?
        .to_string();
    let expires_in = json["expires_in"].as_i64().unwrap_or(3600);
    let expires_at = chrono::Utc::now().timestamp() + expires_in;

    Ok(GoogleTokens {
        access_token,
        // Refresh token doesn't change on refresh
        refresh_token: Some(refresh_token.to_string()),
        expires_at,
    })
}

/// Get a valid access token - refresh if expired.
/// Returns (access_token, updated_tokens_if_refreshed)
#[tracing::instrument(skip(tokens), fields(client_id = %client_id))]
pub async fn get_valid_token(
    client_id: &str,
    tokens: &GoogleTokens,
) -> Result<(String, Option<GoogleTokens>), String> {
    let now = chrono::Utc::now().timestamp();

    // Refresh if within 60 seconds of expiry
    if now >= tokens.expires_at - 60 {
        let refresh_tok = tokens
            .refresh_token
            .as_deref()
            .ok_or("No refresh token available - please reconnect Google")?;
        let new_tokens = refresh_access_token(client_id, refresh_tok).await?;
        let token = new_tokens.access_token.clone();
        Ok((token, Some(new_tokens)))
    } else {
        Ok((tokens.access_token.clone(), None))
    }
}

#[cfg(test)]
mod tests;
