//! TLS certificate expiry probe.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use ts_rs::TS;

use crate::constants::CHECK_LINK_TIMEOUT as PROBE_TIMEOUT;
use crate::network_policy::UrlPolicy;

/// One message for every policy refusal and transport outcome, so a probe
/// aimed at the LAN cannot tell "refused" from "closed" from "no such host".
pub(crate) const PROBE_UNAVAILABLE: &str = "Certificate details are unavailable for this host.";

pub(crate) type ConnectFuture = Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>;

/// Serialized result returned to the frontend.
#[derive(Debug, Serialize, Clone, TS)]
#[ts(export_to = "ipc-bindings.ts")]
pub struct SslProbeResult {
    pub days_remaining: Option<i64>,
    pub auto_renew_hint: bool,
    pub not_after_iso: Option<String>,
    pub error: Option<String>,
}

impl SslProbeResult {
    fn err(msg: impl Into<String>) -> Self {
        Self {
            days_remaining: None,
            auto_renew_hint: false,
            not_after_iso: None,
            error: Some(msg.into()),
        }
    }
}

/// Build a rustls config on the explicit ring provider with the operating
/// system's certificate store, the same verifier reqwest uses, so the
/// dashboard probe and the scan agree on what a trusted chain is.
///
/// Headless entry points do not install a process-default provider.
/// `with_platform_verifier()` eagerly builds the platform verifier and can
/// fail - on non-Apple, non-Windows, non-Android targets it loads native CA
/// certificates and errors if none load - so this returns a `Result` rather
/// than panicking; callers report the error as an unavailable probe instead
/// of crashing.
pub(crate) fn platform_verified_client_config() -> Result<ClientConfig, String> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let builder = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring crypto provider supports the safe default TLS protocol versions");
    let verified = builder
        .with_platform_verifier()
        .map_err(|error| format!("platform certificate verifier unavailable: {error}"))?;
    Ok(verified.with_no_client_auth())
}

pub(crate) fn host_from_url(url: &str) -> Option<String> {
    if url.trim().is_empty() {
        return None;
    }
    if let Ok(u) = url::Url::parse(url) {
        return u.host_str().map(|s| s.to_string());
    }
    let candidate = url.trim().trim_end_matches('/');
    if candidate.contains(' ') || candidate.contains('\n') {
        return None;
    }
    if !candidate.contains('.') {
        return None;
    }
    Some(candidate.to_string())
}

pub(crate) fn days_between(now: DateTime<Utc>, not_after: DateTime<Utc>) -> Option<i64> {
    Some((not_after - now).num_days().max(0))
}

/// Probe certificate expiry, returning failures through `SslProbeResult::error`.
pub async fn check_ssl(url: String) -> Result<SslProbeResult, String> {
    Ok(check_ssl_with(&url, |addr| Box::pin(TcpStream::connect(addr))).await)
}

/// The probe with its socket behind a seam, so tests can prove that policy
/// refusals happen before any connection attempt.
pub(crate) async fn check_ssl_with(
    url: &str,
    connect: impl Fn(SocketAddr) -> ConnectFuture + Send + Sync,
) -> SslProbeResult {
    check_ssl_with_config(url, connect, platform_verified_client_config).await
}

/// `check_ssl_with` with the TLS config build behind a seam too, so a test
/// can prove a `platform_verified_client_config` failure (e.g. no native CA
/// certificates load) reports `PROBE_UNAVAILABLE` instead of panicking.
async fn check_ssl_with_config(
    url: &str,
    connect: impl Fn(SocketAddr) -> ConnectFuture + Send + Sync,
    build_config: impl Fn() -> Result<ClientConfig, String>,
) -> SslProbeResult {
    let Some(host) = host_from_url(url) else {
        return SslProbeResult::err("Invalid URL");
    };
    let host = host.trim_matches(|c| c == '[' || c == ']').to_string();

    // Same policy as a scan target: loopback dev servers stay allowed, every
    // other private or internal address is refused before DNS or a socket.
    let policy_url = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("https://[{host}]/"),
        _ => format!("https://{host}/"),
    };
    if crate::network_policy::validate_url(&policy_url, UrlPolicy::Scan)
        .await
        .is_err()
    {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    }

    let Some(addr) = resolve_probe_addr(&host).await else {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    };

    let Ok(server_name) = ServerName::try_from(host.clone()) else {
        return SslProbeResult::err("Invalid URL");
    };
    let Ok(config) = build_config() else {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    };
    let connector = TlsConnector::from(Arc::new(config));

    let Ok(Ok(tcp)) = tokio::time::timeout(PROBE_TIMEOUT, connect(addr)).await else {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    };
    let Ok(Ok(tls_stream)) =
        tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp)).await
    else {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    };

    let (_io, session) = tls_stream.into_inner();
    let leaf = match session.peer_certificates() {
        Some(certs) if !certs.is_empty() => certs[0].clone(),
        _ => return SslProbeResult::err(PROBE_UNAVAILABLE),
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    };
    let not_after_ts = parsed.validity().not_after.timestamp();
    let Some(not_after) = DateTime::<Utc>::from_timestamp(not_after_ts, 0) else {
        return SslProbeResult::err(PROBE_UNAVAILABLE);
    };
    SslProbeResult {
        days_remaining: days_between(Utc::now(), not_after),
        auto_renew_hint: is_likely_auto_renew(&host, &parsed),
        not_after_iso: Some(not_after.to_rfc3339()),
        error: None,
    }
}

/// Resolve the validated host once and connect to that exact address, so a
/// second lookup cannot rebind the name to an internal address between the
/// policy check and the socket.
async fn resolve_probe_addr(host: &str) -> Option<SocketAddr> {
    let literal = host.parse::<IpAddr>().ok();
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 443u16))
        .await
        .ok()?
        .collect();
    for addr in &addrs {
        if literal.is_none()
            && crate::network_policy::validate_resolved_domain_ip_target(
                host,
                addr.ip(),
                UrlPolicy::Scan,
            )
            .is_err()
        {
            return None;
        }
    }
    addrs.into_iter().next()
}

fn is_likely_auto_renew(host: &str, cert: &x509_parser::certificate::X509Certificate<'_>) -> bool {
    let issuer = cert.issuer().to_string().to_lowercase();
    let host_lc = host.to_lowercase();
    issuer.contains("let's encrypt")
        || issuer.contains("google trust services")
        || issuer.contains("cloudflare")
        || host_lc.ends_with(".vercel.app")
        || host_lc.ends_with(".netlify.app")
        || host_lc.ends_with(".fly.dev")
        || host_lc.ends_with(".pages.dev")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_url_extracts_hostname() {
        assert_eq!(
            host_from_url("https://example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host_from_url("https://example.com:443/path").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_from_url("example.com").as_deref(), Some("example.com"));
        assert_eq!(host_from_url("").as_deref(), None);
        assert_eq!(host_from_url("not a url").as_deref(), None);
    }

    #[test]
    fn days_between_counts_days_remaining() {
        let now = Utc::now();
        assert_eq!(
            days_between(now, now + chrono::Duration::days(30)).unwrap(),
            30
        );
    }

    #[test]
    fn client_config_binds_provider_without_process_default() {
        // Headless entry points may not install a process-default CryptoProvider.
        let config = platform_verified_client_config()
            .expect("this machine's native certificate store loads");
        assert!(
            !config.crypto_provider().cipher_suites.is_empty(),
            "ring provider must expose cipher suites",
        );
    }

    #[tokio::test]
    async fn a_platform_verifier_build_failure_reports_unavailable_not_a_panic() {
        // with_platform_verifier() eagerly builds the verifier and can fail
        // (e.g. no native CA certificates load on some Linux configurations);
        // this proves that failure reports PROBE_UNAVAILABLE through the
        // build_config seam instead of unwinding.
        let opened = Arc::new(AtomicBool::new(false));
        let result = check_ssl_with_config(
            "https://example.com",
            refusing_connector(opened.clone()),
            || Err("no native CA certificates loaded".to_string()),
        )
        .await;
        assert_eq!(result.error.as_deref(), Some(PROBE_UNAVAILABLE));
        assert_eq!(result.days_remaining, None);
        assert!(
            !opened.load(Ordering::SeqCst),
            "a config-build failure must be reported before any connect attempt"
        );
    }

    #[test]
    fn days_between_clamps_past_to_zero() {
        let now = Utc::now();
        assert_eq!(
            days_between(now, now - chrono::Duration::days(5)).unwrap(),
            0
        );
    }

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn refusing_connector(opened: Arc<AtomicBool>) -> impl Fn(SocketAddr) -> ConnectFuture {
        move |_addr| {
            opened.store(true, Ordering::SeqCst);
            Box::pin(async { Err(std::io::Error::other("socket must not open")) })
        }
    }

    #[tokio::test]
    async fn private_range_hosts_are_refused_before_a_socket_opens() {
        let opened = Arc::new(AtomicBool::new(false));
        for url in [
            "https://10.0.0.5",
            "http://192.168.1.10",
            "https://169.254.169.254",
            "https://[fc00::1]",
            "https://[::ffff:10.0.0.1]",
            "http://metadata.google.internal",
            "100.64.0.1",
        ] {
            let result = check_ssl_with(url, refusing_connector(opened.clone())).await;
            assert_eq!(result.error.as_deref(), Some(PROBE_UNAVAILABLE), "{url}");
            assert_eq!(result.days_remaining, None, "{url}");
        }
        assert!(
            !opened.load(Ordering::SeqCst),
            "policy refusal must happen before any connect attempt"
        );
    }

    #[tokio::test]
    async fn every_transport_failure_reports_the_same_message() {
        // Connect refused by the seam.
        let opened = Arc::new(AtomicBool::new(false));
        let refused =
            check_ssl_with("https://example.com", refusing_connector(opened.clone())).await;
        assert_eq!(refused.error.as_deref(), Some(PROBE_UNAVAILABLE));
        assert!(
            opened.load(Ordering::SeqCst),
            "a public host reaches the connector"
        );

        // Handshake failure: a loopback listener that accepts and closes.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind handshake stub");
        let stub_addr = listener.local_addr().expect("stub address");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let closed = check_ssl_with("https://example.com", move |_addr| {
            Box::pin(tokio::net::TcpStream::connect(stub_addr))
        })
        .await;
        assert_eq!(closed.error.as_deref(), Some(PROBE_UNAVAILABLE));
    }

    #[tokio::test]
    async fn unparseable_input_is_the_only_distinct_error() {
        let opened = Arc::new(AtomicBool::new(false));
        for url in ["", "not a url", "nodots"] {
            let result = check_ssl_with(url, refusing_connector(opened.clone())).await;
            assert_eq!(result.error.as_deref(), Some("Invalid URL"), "{url:?}");
        }
        assert!(!opened.load(Ordering::SeqCst));
    }
}
