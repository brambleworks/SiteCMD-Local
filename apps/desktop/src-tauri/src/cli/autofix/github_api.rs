//! The three GitHub REST calls the publish job makes with the per-operation
//! installation token Connect minted for it: open a pull request, open an
//! issue, and hand the token back when the operation is done.

use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// How much of GitHub's own explanation a refusal carries back.
const MAX_REFUSAL_MESSAGE_CHARS: usize = 200;

/// GitHub's own reason for a refusal, bounded, so a maintainer can act on it.
/// Anything else the body carries is dropped, and the summary that quotes this
/// is redacted before it leaves the runner.
fn refusal_message(bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|parsed| {
            parsed["message"]
                .as_str()
                .map(|message| message.chars().take(MAX_REFUSAL_MESSAGE_CHARS).collect())
        })
        .map_or_else(String::new, |message: String| format!(": {message}"))
}

pub struct GitHubApi {
    base: url::Url,
    #[cfg(test)]
    allow_http_loopback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedPullRequest {
    pub number: u64,
    pub head_sha: String,
}

impl GitHubApi {
    pub fn new() -> Self {
        Self {
            base: url::Url::parse("https://api.github.com/").expect("allow-expect: a literal URL"),
            #[cfg(test)]
            allow_http_loopback: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(origin: &str) -> Result<Self, String> {
        Ok(Self {
            allow_http_loopback: true,
            base: url::Url::parse(origin).map_err(|error| error.to_string())?,
        })
    }

    /// One credentialed call. The token is the only credential, it is marked
    /// sensitive so it never reaches a log, and the response is bounded.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<String>,
    ) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
        let url = self
            .base
            .join(path)
            .map_err(|error| format!("GitHub URL: {error}"))?;
        // Only a test points this at a loopback double; the command always
        // holds api.github.com to the external-callback policy.
        #[cfg(test)]
        let policy = if self.allow_http_loopback {
            crate::network_policy::UrlPolicy::Scan
        } else {
            crate::network_policy::UrlPolicy::ExternalCallback
        };
        #[cfg(not(test))]
        let policy = crate::network_policy::UrlPolicy::ExternalCallback;
        crate::network_policy::validate_url(url.as_str(), policy)
            .await
            .map_err(|_| "GitHub endpoint refused by network policy".to_string())?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| "installation token is not a valid header value".to_string())?;
        authorization.set_sensitive(true);
        #[cfg(test)]
        let client = if crate::network_policy::LocalOrigin::classify(&url).is_strict_loopback() {
            crate::http_client::localhost_client()
        } else {
            crate::http_client::credentialed_service_client()
        };
        #[cfg(not(test))]
        let client = crate::http_client::credentialed_service_client();
        let mut request = client
            .request(method, url)
            .header(AUTHORIZATION, authorization)
            .header(ACCEPT, "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .timeout(crate::constants::API_TIMEOUT);
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| crate::http_client::fetch_failure("api.github.com", &error))?;
        let status = response.status();
        let bytes = crate::http_client::read_body_limited(
            response,
            MAX_RESPONSE_BYTES,
            crate::constants::API_TIMEOUT_SHORT,
        )
        .await
        .map_err(|_| "GitHub response could not be read".to_string())?;
        Ok((status, bytes))
    }

    pub async fn create_pull_request(
        &self,
        token: &str,
        repository: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<CreatedPullRequest, String> {
        let payload =
            serde_json::json!({ "base": base, "body": body, "head": head, "title": title })
                .to_string();
        let (status, bytes) = self
            .send(
                reqwest::Method::POST,
                &format!("repos/{repository}/pulls"),
                token,
                Some(payload),
            )
            .await?;
        if status != reqwest::StatusCode::CREATED {
            return Err(format!(
                "GitHub refused the pull request ({status}){}",
                refusal_message(&bytes)
            ));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "GitHub pull request response is not JSON".to_string())?;
        let number = parsed["number"]
            .as_u64()
            .ok_or("GitHub pull request response has no number")?;
        let head_sha = parsed["head"]["sha"]
            .as_str()
            .filter(|sha| sha.len() == 40)
            .ok_or("GitHub pull request response has no head sha")?
            .to_string();
        Ok(CreatedPullRequest { head_sha, number })
    }

    pub async fn create_issue(
        &self,
        token: &str,
        repository: &str,
        title: &str,
        body: &str,
    ) -> Result<u64, String> {
        let payload = serde_json::json!({ "body": body, "title": title }).to_string();
        let (status, bytes) = self
            .send(
                reqwest::Method::POST,
                &format!("repos/{repository}/issues"),
                token,
                Some(payload),
            )
            .await?;
        if status != reqwest::StatusCode::CREATED {
            return Err(format!(
                "GitHub refused the issue ({status}){}",
                refusal_message(&bytes)
            ));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "GitHub issue response is not JSON".to_string())?;
        parsed["number"]
            .as_u64()
            .ok_or_else(|| "GitHub issue response has no number".to_string())
    }

    /// The holder hands the token back the moment it is done with it. GitHub's
    /// endpoint accepts only the token being revoked, so this call carries no
    /// other credential. A false is reported to Connect, never fatal.
    pub async fn revoke_installation_token(&self, token: &str) -> bool {
        matches!(
            self.send(reqwest::Method::DELETE, "installation/token", token, None)
                .await,
            Ok((status, _)) if status == reqwest::StatusCode::NO_CONTENT
        )
    }
}

impl Default for GitHubApi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::GitHubApi;

    #[tokio::test]
    async fn creates_a_pull_request_with_the_token_and_reads_its_number() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0_u8; 64 * 1024];
            let read = stream.read(&mut bytes).await.unwrap();
            let body = r#"{"number":12,"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&bytes[..read]).to_string()
        });

        let api = GitHubApi::for_test(&format!("http://{address}")).unwrap();
        let created = api
            .create_pull_request(
                "ghs_t",
                "example-org/example-site",
                "sitecmd/x-1",
                "main",
                "Add header",
                "body",
            )
            .await
            .unwrap();

        assert_eq!(
            (created.number, created.head_sha.as_str()),
            (12, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        let request = captured.await.unwrap().to_ascii_lowercase();
        assert!(
            request.starts_with("post /repos/example-org/example-site/pulls http/1.1"),
            "{request}"
        );
        assert!(request.contains("authorization: bearer ghs_t"), "{request}");
        assert!(request.contains(r#""head":"sitecmd/x-1""#), "{request}");
    }
}
