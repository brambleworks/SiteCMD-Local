//! Shared pooled HTTP clients, including a narrowly scoped localhost variant.

use reqwest::Client;
use std::fmt;
use std::sync::LazyLock;
use std::time::Duration;

mod loopback_tls;

const REDIRECT_LIMIT: usize = 10;

#[derive(Debug)]
pub enum BodyReadError {
    TooLarge { max_bytes: u64, received_bytes: u64 },
    TimedOut { timeout: Duration },
    Transport(reqwest::Error),
}

impl fmt::Display for BodyReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                max_bytes,
                received_bytes,
            } => write!(
                formatter,
                "response body exceeded the {} byte limit after {} bytes",
                max_bytes, received_bytes
            ),
            Self::TimedOut { timeout } => {
                write!(formatter, "response body timed out after {timeout:?}")
            }
            Self::Transport(_) => write!(formatter, "failed to read response body"),
        }
    }
}

impl std::error::Error for BodyReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::TooLarge { .. } | Self::TimedOut { .. } => None,
        }
    }
}

/// Read an HTTP response body without allowing chunked or dishonest responses
/// to allocate beyond the caller's byte budget.
///
/// `max_bytes` bounds the bytes this function yields, which for a compressed
/// response are the decoded bytes: reqwest strips `Content-Length` when it
/// decodes, so the declared-length shortcut cannot be used to smuggle a small
/// wire body that inflates past the cap, and the chunk loop measures what the
/// decoder produced.
pub async fn read_body_limited(
    mut response: reqwest::Response,
    max_bytes: u64,
    timeout: Duration,
) -> Result<Vec<u8>, BodyReadError> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes {
            return Err(BodyReadError::TooLarge {
                max_bytes,
                received_bytes: content_length,
            });
        }
    }

    let read = async {
        let initial_capacity = response
            .content_length()
            .unwrap_or(0)
            .min(max_bytes)
            .try_into()
            .unwrap_or(0);
        let mut body = Vec::with_capacity(initial_capacity);
        while let Some(chunk) = response.chunk().await.map_err(BodyReadError::Transport)? {
            let received_bytes = body.len() as u64 + chunk.len() as u64;
            if received_bytes > max_bytes {
                return Err(BodyReadError::TooLarge {
                    max_bytes,
                    received_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };

    tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| BodyReadError::TimedOut { timeout })?
}

pub async fn read_text_limited(
    response: reqwest::Response,
    max_bytes: u64,
    timeout: Duration,
) -> Result<String, BodyReadError> {
    let body = read_body_limited(response, max_bytes, timeout).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

pub async fn read_json_limited<T>(
    response: reqwest::Response,
    max_bytes: u64,
    timeout: Duration,
) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let body = read_body_limited(response, max_bytes, timeout)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&body).map_err(|error| format!("invalid JSON response: {error}"))
}

/// The whole reason a request failed, including the causes the top-level
/// message hides.
///
/// reqwest's `Display` renders only its own layer, so an expired certificate,
/// a refused connection, and a name that does not resolve all reach the user
/// as the same sentence: "error sending request for url (...)". Every one of
/// those reasons is already sitting in the error's source chain, which is
/// where the TLS verifier's "certificate is expired" lives. This appends each
/// layer that says something the text so far does not, so the reported reason
/// is the runtime's own words rather than a phrase list this code would have
/// to keep in step with reqwest, hyper, and rustls.
pub fn describe_request_error(error: &(dyn std::error::Error + 'static)) -> String {
    let mut described = error.to_string();
    let mut current = error.source();
    while let Some(layer) = current {
        let text = layer.to_string();
        if !text.is_empty() && !described.contains(&text) {
            described.push_str(": ");
            described.push_str(&text);
        }
        current = layer.source();
    }
    described
}

/// The message for a page fetch that never produced a response, shared by the
/// scan and verification paths so both name the same cause the same way.
pub fn fetch_failure(url: impl fmt::Display, error: &(dyn std::error::Error + 'static)) -> String {
    format!("Failed to fetch {}: {}", url, describe_request_error(error))
}

/// Negotiate response compression for ordinary traffic.
///
/// reqwest decodes gzip and brotli transparently, and the limited body readers
/// above count the decoded chunks, so a caller's byte cap bounds what a
/// compressed response is allowed to expand into rather than only what crossed
/// the wire. deflate stays off because origins implement it inconsistently, and
/// zstd stays off because it would add a C library to the build; both are
/// disabled explicitly so a transitive feature cannot switch them on.
fn negotiate_bounded_compression(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.gzip(true).brotli(true).no_deflate().no_zstd()
}

/// Shared HTTP client for production URLs, and the ordinary-traffic client for
/// registry metadata, integration APIs, and page fetches.
/// Reuses TCP/TLS connections across requests.
pub fn client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        // reqwest builds with rustls-no-provider, so entry points that never
        // call `run()` (the CLI, examples) still need a crypto provider
        // installed before a client with a rustls backend can be built.
        let _ = rustls::crypto::ring::default_provider().install_default();
        negotiate_bounded_compression(Client::builder())
            .timeout(crate::constants::HTTP_CLIENT_TIMEOUT)
            .user_agent(crate::constants::USER_AGENT.as_str())
            .redirect(safe_redirect_policy(
                crate::network_policy::UrlPolicy::Redirect {
                    allow_local_dev: false,
                },
            ))
            .dns_resolver(crate::dns_cache::shared())
            .build()
            .expect("Failed to build HTTP client")
    });
    &CLIENT
}

/// Shared HTTP client for localhost URLs.
/// Permits self-signed certificates only when the TLS destination is loopback.
pub fn localhost_client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        loopback_tls::configure(negotiate_bounded_compression(Client::builder()))
            .timeout(crate::constants::HTTP_CLIENT_TIMEOUT)
            .user_agent(crate::constants::USER_AGENT.as_str())
            .redirect(safe_redirect_policy(
                crate::network_policy::UrlPolicy::Redirect {
                    allow_local_dev: true,
                },
            ))
            .dns_resolver(crate::dns_cache::shared())
            .build()
            .expect("Failed to build localhost HTTP client")
    });
    &CLIENT
}

/// Shared HTTP client for a scan target inside the person's own networks.
/// Certificate verification stays on: a LAN box is another machine, so only
/// loopback earns the self-signed exception.
pub fn private_network_client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        negotiate_bounded_compression(Client::builder())
            .timeout(crate::constants::HTTP_CLIENT_TIMEOUT)
            .user_agent(crate::constants::USER_AGENT.as_str())
            .redirect(safe_redirect_policy(
                crate::network_policy::UrlPolicy::ScanTarget,
            ))
            .dns_resolver(crate::dns_cache::scan_target_resolver())
            .build()
            .expect("Failed to build private network HTTP client")
    });
    &CLIENT
}

/// HTTP client that does NOT follow redirects.
/// Used by redirect chain checks, HTTPS enforcement, and open redirect detection.
/// These read the status line, `location`, and bounded bodies, never a
/// wire-level size or encoding, so they are ordinary traffic.
pub fn no_redirect_client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        negotiate_bounded_compression(Client::builder())
            .timeout(crate::constants::CHECK_PROBE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(crate::constants::USER_AGENT.as_str())
            .dns_resolver(crate::dns_cache::shared())
            .build()
            .expect("Failed to build no-redirect HTTP client")
    });
    &CLIENT
}

/// Non-redirecting client with strict DNS policy for credentialed requests.
pub fn credentialed_service_client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        negotiate_bounded_compression(Client::builder())
            .timeout(crate::constants::API_TIMEOUT_SHORT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(crate::constants::USER_AGENT.as_str())
            .dns_resolver(crate::dns_cache::external_callback_resolver())
            .build()
            .expect("Failed to build credentialed service HTTP client")
    });
    &CLIENT
}

pub fn webhook_client() -> &'static Client {
    credentialed_service_client()
}

/// Policy-guarded client that preserves raw content-encoding responses.
///
/// Measurement probes fetch through this client, never through the shared
/// ordinary-traffic clients above. They report what the server actually sent:
/// `performance.compression` grades the `Content-Encoding` header, which
/// transparent decoding removes, and the asset sampler reports transfer size,
/// which decoding would inflate to the decompressed size. Auto-decompression is
/// therefore turned off for every codec, deflate and zstd included, so enabling
/// their crate features later cannot silently start decoding here.
pub fn no_decompress_client(is_strict_local: bool) -> &'static Client {
    static STRICT: LazyLock<Client> = LazyLock::new(|| build_no_decompress_client(true));
    static PUBLIC: LazyLock<Client> = LazyLock::new(|| build_no_decompress_client(false));
    if is_strict_local {
        &STRICT
    } else {
        &PUBLIC
    }
}

fn build_no_decompress_client(is_strict_local: bool) -> Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = if is_strict_local {
        loopback_tls::configure(Client::builder())
    } else {
        Client::builder()
    };
    builder
        .timeout(crate::constants::API_TIMEOUT_SHORT)
        .user_agent(crate::constants::USER_AGENT.as_str())
        .redirect(safe_redirect_policy(
            crate::network_policy::UrlPolicy::Redirect {
                allow_local_dev: is_strict_local,
            },
        ))
        .dns_resolver(crate::dns_cache::shared())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .expect("Failed to build no-decompress HTTP client")
}

/// Pick the shared client for a scan origin. Loopback keeps the self-signed
/// exception, a private network address gets a client that may reach it, and
/// everything else gets the public client. The client carries its origin's
/// reach into every redirect it follows, so a public page cannot steer the
/// scan into a network the person never named.
pub fn for_scan_origin(origin: crate::network_policy::LocalOrigin) -> &'static Client {
    use crate::network_policy::LocalOrigin;
    match origin {
        LocalOrigin::Loopback => localhost_client(),
        LocalOrigin::PrivateNetwork => private_network_client(),
        LocalOrigin::LocalhostDomain | LocalOrigin::LocalNetworkName | LocalOrigin::Public => {
            client()
        }
    }
}

/// Pick the appropriate shared client based on whether the URL is a strict
/// loopback address (localhost, 127.0.0.1,::1).
pub fn for_url(is_strict_local: bool) -> &'static Client {
    if is_strict_local {
        localhost_client()
    } else {
        client()
    }
}

/// The policy a client applies to every URL a fetched page steers it to. It is
/// the policy of the origin the client was chosen for, so a redirect reaches
/// no further than the target the person named.
fn safe_redirect_policy(policy: crate::network_policy::UrlPolicy) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= REDIRECT_LIMIT {
            return attempt.error(std::io::Error::other("too many redirects"));
        }

        // Validate IP literals here; domain redirects are checked at DNS resolution.
        if let Err(error) =
            crate::network_policy::validate_redirect_target_nonblocking(attempt.url(), policy)
        {
            return attempt.error(std::io::Error::other(error));
        }

        attempt.follow()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn ptr<T>(r: &T) -> *const T {
        r as *const T
    }

    /// gzip a payload the way an origin would, so the tests exercise a real
    /// decoder rather than a hand-written byte fixture.
    fn gzip(payload: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).expect("gzip the test payload");
        encoder.finish().expect("finish the gzip stream")
    }

    /// Read one request head, up to its blank line. A test server answers
    /// only after this, as a real one does: a response that arrives while the
    /// client is still sending its request fails the request in hyper.
    async fn read_request_head(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read request head");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        request
    }

    /// Answer exactly one request with a `Content-Encoding: gzip` body and
    /// hand back the request head the client sent.
    async fn serve_one_gzip_response(listener: TcpListener, body: Vec<u8>) -> String {
        let (mut stream, _) = listener.accept().await.expect("accept gzip request");
        let request = read_request_head(&mut stream).await;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("write response head");
        stream.write_all(&body).await.expect("write gzip body");
        stream.shutdown().await.expect("close gzip response");
        String::from_utf8_lossy(&request).into_owned()
    }

    /// Bind a loopback server serving one gzip response, returning its URL and
    /// the join handle carrying the observed request head.
    async fn gzip_server(body: Vec<u8>) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gzip server");
        let addr = listener.local_addr().expect("gzip server address");
        let served = tokio::spawn(serve_one_gzip_response(listener, body));
        (format!("http://{addr}/payload"), served)
    }

    #[tokio::test]
    async fn ordinary_clients_negotiate_gzip_and_decode_transparently() {
        let payload = "SiteCMD registry metadata compresses well. ".repeat(200);
        for (label, ordinary) in [
            ("production", client()),
            ("localhost", localhost_client()),
            ("no-redirect", no_redirect_client()),
            ("credentialed service", credentialed_service_client()),
        ] {
            let (url, served) = gzip_server(gzip(payload.as_bytes())).await;
            let response = ordinary
                .get(&url)
                .send()
                .await
                .unwrap_or_else(|error| panic!("{label} client request failed: {error}"));

            assert!(
                response.headers().get("content-encoding").is_none(),
                "{label} client must consume Content-Encoding while decoding, not pass it through"
            );

            let body = read_text_limited(response, 1024 * 1024, std::time::Duration::from_secs(5))
                .await
                .unwrap_or_else(|error| panic!("{label} client body read failed: {error}"));
            assert_eq!(
                body, payload,
                "{label} client must hand callers the decoded body"
            );

            let request = served.await.expect("gzip server task").to_ascii_lowercase();
            let accept_encoding = request
                .lines()
                .find(|line| line.starts_with("accept-encoding:"))
                .unwrap_or_else(|| {
                    panic!("{label} client sent no Accept-Encoding header:\n{request}")
                });
            assert!(
                accept_encoding.contains("gzip"),
                "{label} client must offer gzip, got `{accept_encoding}`"
            );
            assert!(
                accept_encoding.contains("br"),
                "{label} client must offer brotli, got `{accept_encoding}`"
            );
        }
    }

    #[tokio::test]
    async fn body_limit_rejects_a_response_that_inflates_past_the_cap() {
        // 256 KiB of one repeated byte: a few hundred bytes on the wire, far
        // past the cap once decoded. Bounding only the wire bytes would accept
        // it, which is the zip-bomb shape this cap exists to refuse.
        let inflated = vec![b'a'; 256 * 1024];
        let compressed = gzip(&inflated);
        let max_bytes = 4096;
        assert!(
            (compressed.len() as u64) < max_bytes,
            "fixture must be under the cap on the wire, got {} bytes",
            compressed.len()
        );

        let (url, served) = gzip_server(compressed).await;
        let response = client().get(&url).send().await.expect("request gzip bomb");
        let result =
            read_body_limited(response, max_bytes, std::time::Duration::from_secs(5)).await;

        assert!(
            matches!(
                result,
                Err(BodyReadError::TooLarge {
                    max_bytes: 4096,
                    ..
                })
            ),
            "the cap must apply to decoded bytes, got {result:?}"
        );
        let _ = served.await;
    }

    #[tokio::test]
    async fn measurement_probe_client_returns_the_raw_encoded_body() {
        let payload = "measurement probes grade the wire response. ".repeat(64);
        let compressed = gzip(payload.as_bytes());
        let (url, served) = gzip_server(compressed.clone()).await;

        let response = no_decompress_client(false)
            .get(&url)
            // The compression check sends this header explicitly; the client
            // must still refuse to decode what comes back.
            .header("Accept-Encoding", "gzip, deflate, br, zstd")
            .send()
            .await
            .expect("probe the gzip response");

        assert_eq!(
            response
                .headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip"),
            "the probe client must preserve Content-Encoding for the compression check to grade"
        );
        let body = read_body_limited(response, 1024 * 1024, std::time::Duration::from_secs(5))
            .await
            .expect("read the raw probe body");
        assert_eq!(
            body, compressed,
            "the probe client must hand back the bytes the server sent, not the decoded payload"
        );
        let _ = served.await;
    }

    #[test]
    fn for_url_routes_strict_local_to_localhost_client() {
        let routed = for_url(true);
        assert_eq!(
            ptr(routed),
            ptr(localhost_client()),
            "is_strict_local=true must return the localhost (cert-skipping) client"
        );
    }

    #[test]
    fn for_url_routes_non_local_to_production_client() {
        let routed = for_url(false);
        assert_eq!(
            ptr(routed),
            ptr(client()),
            "is_strict_local=false must return the TLS-validating production client"
        );
    }

    #[test]
    fn production_and_localhost_clients_are_distinct() {
        assert_ne!(
            ptr(client()),
            ptr(localhost_client()),
            "production and localhost clients must be separate instances - a regression that aliased them would silently accept invalid certs for public URLs"
        );
    }

    #[test]
    fn no_redirect_client_is_distinct_from_others() {
        assert_ne!(ptr(no_redirect_client()), ptr(client()));
        assert_ne!(ptr(no_redirect_client()), ptr(localhost_client()));
    }

    #[test]
    fn webhook_client_is_distinct_from_scan_clients() {
        assert_ne!(ptr(webhook_client()), ptr(client()));
        assert_ne!(ptr(webhook_client()), ptr(no_redirect_client()));
        assert_ne!(ptr(webhook_client()), ptr(localhost_client()));
        assert_eq!(ptr(webhook_client()), ptr(credentialed_service_client()));
    }

    /// One layer of a synthetic error chain shaped like reqwest's.
    #[derive(Debug)]
    struct Layer {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    }

    impl Layer {
        fn leaf(message: &str) -> Self {
            Self {
                message: message.to_string(),
                source: None,
            }
        }

        fn wrapping(message: &str, source: Layer) -> Self {
            Self {
                message: message.to_string(),
                source: Some(Box::new(source)),
            }
        }
    }

    impl fmt::Display for Layer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source.as_deref().map(|source| source as _)
        }
    }

    #[test]
    fn an_expired_certificate_reaches_the_user_as_an_expired_certificate() {
        // The shape the CLI hit on expired.badssl.com: reqwest names only the
        // URL, and the verifier's reason is two layers down.
        let error = Layer::wrapping(
            "error sending request for url (https://expired.badssl.com/)",
            Layer::wrapping(
                "client error (Connect)",
                Layer::leaf(
                    "invalid peer certificate: Other(OtherError(\"\\\"*.badssl.com\\\" certificate is expired: -67818\"))",
                ),
            ),
        );
        assert!(
            !error.to_string().contains("certificate is expired"),
            "negative control: the top-level message alone must not already carry the reason, or this test proves nothing"
        );
        let described = describe_request_error(&error);
        assert!(
            described.contains("certificate is expired"),
            "the verifier's reason must survive the walk, got {described}"
        );
        assert!(
            described.starts_with("error sending request for url"),
            "the top-level message stays first, got {described}"
        );
    }

    #[test]
    fn a_refused_connection_and_a_missing_name_stay_distinguishable() {
        let refused = describe_request_error(&Layer::wrapping(
            "error sending request for url (http://example.com/)",
            Layer::wrapping(
                "tcp connect error",
                Layer::leaf("Connection refused (os error 61)"),
            ),
        ));
        assert!(refused.contains("Connection refused"), "got {refused}");

        let unresolved = describe_request_error(&Layer::wrapping(
            "error sending request for url (http://nope.invalid/)",
            Layer::wrapping(
                "dns error",
                Layer::leaf("failed to lookup address information"),
            ),
        ));
        assert!(
            unresolved.contains("failed to lookup address information"),
            "got {unresolved}"
        );
        assert_ne!(refused, unresolved);
    }

    #[test]
    fn a_cause_already_quoted_by_its_wrapper_is_not_repeated() {
        let described = describe_request_error(&Layer::wrapping(
            "invalid peer certificate: expired",
            Layer::leaf("expired"),
        ));
        assert_eq!(described, "invalid peer certificate: expired");
    }

    #[test]
    fn an_error_without_a_cause_is_reported_unchanged() {
        assert_eq!(
            describe_request_error(&Layer::leaf("too many redirects")),
            "too many redirects"
        );
    }

    #[tokio::test]
    async fn bounded_body_reader_rejects_oversized_chunked_response_before_eof() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind body-limit server");
        let addr = listener.local_addr().expect("body-limit server address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept body-limit request");
            read_request_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .expect("write response head");
            for _ in 0..5 {
                stream
                    .write_all(b"8\r\n12345678\r\n")
                    .await
                    .expect("write response chunk");
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });

        let response = localhost_client()
            .get(format!("http://{addr}/oversized"))
            .send()
            .await
            .expect("request chunked response");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_body_limited(response, 32, std::time::Duration::from_secs(4)),
        )
        .await
        .expect("reader should reject before the server reaches EOF");

        assert!(matches!(
            result,
            Err(BodyReadError::TooLarge { max_bytes: 32, .. })
        ));
        server.abort();
    }
}
