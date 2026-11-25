//! Shared SSRF validation for scans, sitemaps, webhooks, and redirects.

use sitecmd_protocol::network_class::{is_private_network_ip, is_private_or_internal_ip};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub enum UrlPolicy {
    /// The scan target a person named, and the fetches subordinate to it.
    ///
    /// SiteCMD runs as that person, on their machine, with their network, so
    /// naming an address they can already reach grants no access they did not
    /// have: this policy reaches loopback and the private networks the machine
    /// is attached to. Link-local stays refused because cloud metadata lives
    /// at `169.254.169.254` and no site anyone means to scan does, and a scan
    /// body is persisted, exported, and can be sent to an AI provider.
    ScanTarget,
    /// User-initiated scans may target explicit loopback dev servers.
    Scan,
    /// External callbacks/webhooks must never target local or private networks.
    ExternalCallback,
    /// Redirects inherit the local-dev allowance of the originating client.
    Redirect { allow_local_dev: bool },
}

impl UrlPolicy {
    fn allow_local_dev(self) -> bool {
        match self {
            Self::ScanTarget | Self::Scan => true,
            Self::ExternalCallback => false,
            Self::Redirect { allow_local_dev } => allow_local_dev,
        }
    }

    /// Whether this policy may reach the private networks this machine is
    /// attached to, rather than only the machine itself. Only a target the
    /// person named, and the fetches that target leads to, may.
    fn allows_private_network(self) -> bool {
        matches!(self, Self::ScanTarget)
    }

    fn label(self) -> &'static str {
        match self {
            Self::ScanTarget | Self::Scan => "URL",
            Self::ExternalCallback => "External callback URL",
            Self::Redirect { .. } => "Redirect target",
        }
    }
}

/// How local a scan target is, computed once per scan and threaded through
/// the pipeline instead of re-derived from the URL at every consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalOrigin {
    /// `localhost`, `127.0.0.0/8`, `[::1]`: certificate checks are skipped
    /// and the loopback redirect exception applies.
    Loopback,
    /// A `.localhost` subdomain: loopback by RFC 6761 but resolved by the OS,
    /// so the redirect exception applies while certificate checks stay on.
    LocalhostDomain,
    /// `*.local` or `0.0.0.0`: a local environment label, no policy exception.
    LocalNetworkName,
    /// A literal address on a private network this machine is attached to.
    /// A scan may reach it because the person named it, but it is another
    /// machine, so certificate verification stays on.
    PrivateNetwork,
    Public,
}

impl LocalOrigin {
    /// Two deliberate widenings relative to the predicates this replaces:
    /// every `127.0.0.0/8` literal classifies as `Loopback` (the old
    /// `is_strict_localhost` accepted only `127.0.0.1`), and a trailing-dot
    /// FQDN form (`localhost.`) normalizes the same way
    /// `is_local_dev_domain` already normalizes it elsewhere in this file,
    /// so it also classifies as `Loopback` even though the protocol's
    /// predicates compare `host_str()` without trimming the trailing dot.
    pub fn classify(url: &url::Url) -> Self {
        match url.host() {
            Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Self::Loopback,
            Some(url::Host::Ipv6(ip)) if IpAddr::V6(ip).to_canonical().is_loopback() => {
                Self::Loopback
            }
            Some(url::Host::Ipv4(ip)) if ip.is_unspecified() => Self::LocalNetworkName,
            Some(url::Host::Ipv4(ip)) if is_private_network_ip(IpAddr::V4(ip)) => {
                Self::PrivateNetwork
            }
            Some(url::Host::Ipv6(ip)) if is_private_network_ip(IpAddr::V6(ip)) => {
                Self::PrivateNetwork
            }
            Some(url::Host::Domain(domain)) => {
                let domain = domain.trim_end_matches('.').to_ascii_lowercase();
                if domain == "localhost" {
                    Self::Loopback
                } else if domain.ends_with(".localhost") {
                    Self::LocalhostDomain
                } else if domain.ends_with(".local") {
                    Self::LocalNetworkName
                } else {
                    Self::Public
                }
            }
            _ => Self::Public,
        }
    }

    pub fn allows_local_dev(self) -> bool {
        matches!(self, Self::Loopback | Self::LocalhostDomain)
    }

    /// Classify using addresses the caller already resolved.
    pub(crate) fn classify_resolved_addresses(
        url: &url::Url,
        addrs: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        let origin = Self::classify(url);
        if origin == Self::Public {
            Self::from_resolved_addresses(origin, addrs)
        } else {
            origin
        }
    }

    /// Private reach is earned only when every address a name answers with
    /// is private. A name that also answers publicly is a public site, and
    /// promoting it would hand that site's pages the LAN and loopback reach
    /// `ScanTarget` grants. Loopback behind a public name is DNS rebinding,
    /// refused elsewhere in this file; it must not be promoted to a reach.
    fn from_resolved_addresses(sync: Self, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut private_only = false;
        for ip in addrs {
            let ip = ip.to_canonical();
            if ip.is_loopback() || !is_private_network_ip(ip) {
                return sync;
            }
            private_only = true;
        }
        if private_only {
            Self::PrivateNetwork
        } else {
            sync
        }
    }
}

pub async fn validate_url(url: &str, policy: UrlPolicy) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL '{}': {}", url, e))?;
    validate_url_target(&parsed, policy).await
}

pub(crate) async fn validate_url_target(url: &url::Url, policy: UrlPolicy) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "Unsupported URL scheme '{}'. Only http:// and https:// URLs are allowed.",
                scheme
            ))
        }
    }

    let host = url
        .host()
        .ok_or_else(|| format!("{} must include a host.", policy.label()))?;

    match host {
        url::Host::Ipv4(ip) => validate_ip_target(IpAddr::V4(ip), policy),
        url::Host::Ipv6(ip) => validate_ip_target(IpAddr::V6(ip), policy),
        url::Host::Domain(domain) => validate_domain_target_async(domain, url, policy).await,
    }
}

/// Validate redirect targets without blocking DNS on the async runtime.
/// IP literals are checked here; domain addresses are checked by
/// `CachedDnsResolver` at connection time to prevent DNS rebinding.
pub fn validate_redirect_target_nonblocking(
    url: &url::Url,
    policy: UrlPolicy,
) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "Unsupported URL scheme '{}'. Only http:// and https:// URLs are allowed.",
                scheme
            ))
        }
    }

    let host = url
        .host()
        .ok_or_else(|| format!("{} must include a host.", policy.label()))?;

    match host {
        url::Host::Ipv4(ip) => validate_ip_target(IpAddr::V4(ip), policy),
        url::Host::Ipv6(ip) => validate_ip_target(IpAddr::V6(ip), policy),
        url::Host::Domain(domain) => {
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if normalized == "metadata.google.internal" {
                return Err("Cannot access cloud metadata endpoints.".to_string());
            }
            if is_local_dev_domain(&normalized) && !policy.allow_local_dev() {
                return Err("External callback URLs cannot target localhost.".to_string());
            }
            Ok(())
        }
    }
}

async fn validate_domain_target_async(
    domain: &str,
    url: &url::Url,
    policy: UrlPolicy,
) -> Result<(), String> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    if normalized == "metadata.google.internal" {
        return Err("Cannot access cloud metadata endpoints.".to_string());
    }
    if is_local_dev_domain(&normalized) {
        if policy.allow_local_dev() {
            return Ok(());
        }
        return Err("External callback URLs cannot target localhost.".to_string());
    }

    let port = url.port_or_known_default().unwrap_or(80);
    let resolved = crate::dns_cache::lookup_host(&normalized, port)
        .await
        .map_err(|e| format!("Could not resolve URL host '{}': {}", domain, e))?;

    let mut saw_addr = false;
    for addr in resolved {
        saw_addr = true;
        validate_resolved_domain_ip_target(domain, addr.ip(), policy)?;
    }
    if !saw_addr {
        return Err(format!("Could not resolve URL host '{}'.", domain));
    }
    Ok(())
}

fn is_local_dev_domain(domain: &str) -> bool {
    domain == "localhost" || domain.ends_with(".localhost")
}

fn validate_ip_target(ip: IpAddr, policy: UrlPolicy) -> Result<(), String> {
    if policy.allow_local_dev() && ip.to_canonical().is_loopback() {
        return Ok(());
    }
    if policy.allows_private_network() && is_private_network_ip(ip) {
        return Ok(());
    }
    if is_private_or_internal_ip(ip) {
        return Err(format!(
            "Cannot access private/internal IP address '{}'.",
            ip
        ));
    }
    Ok(())
}

pub(crate) fn validate_resolved_domain_ip_target(
    domain: &str,
    ip: IpAddr,
    policy: UrlPolicy,
) -> Result<(), String> {
    let is_loopback = ip.to_canonical().is_loopback();
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    if is_local_dev_domain(&normalized) {
        if !policy.allow_local_dev() {
            return Err("External callback URLs cannot target localhost.".to_string());
        }
        if is_loopback {
            return Ok(());
        }
        return Err(format!(
            "Cannot access non-loopback IP address '{}' through a localhost hostname.",
            ip
        ));
    }

    if is_loopback {
        return Err(format!(
            "Cannot access loopback IP address '{}' through a non-localhost hostname.",
            ip
        ));
    }
    validate_ip_target(ip, policy)
}

#[cfg(test)]
#[path = "network_policy_tests.rs"]
mod tests;
