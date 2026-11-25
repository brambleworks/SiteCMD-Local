//! Address classification, project environment labels, and URL identity.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Address space a person's own machine and networks occupy: loopback, the
/// RFC 1918 private ranges, the RFC 6598 shared range that carrier-grade NAT
/// and tailnets use, and IPv6 unique-local, plus the IPv4-mapped spellings of
/// those. A named scan target may reach these.
///
/// Narrower than the native network deny list: link-local
/// (`169.254.0.0/16`, `fe80::/10`) is excluded because cloud metadata answers
/// there, and multicast, broadcast, and the reserved blocks are excluded
/// because they are not hosts.
pub fn is_private_network_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_private() || ip.is_loopback() || (a == 100 && (64..=127).contains(&b))
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| is_private_network_ip(IpAddr::V4(mapped)))
        }
    }
}

/// Ranges that only exist inside a private, reserved, or internal network.
/// Nothing here is ever a public site, so it is the deny list every policy is
/// measured against.
pub fn is_private_or_internal_ip(ip: IpAddr) -> bool {
    if is_private_network_ip(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                // 0.0.0.0/8 "this network": only 0.0.0.0 is `is_unspecified`,
                // but some stacks route the rest of the block to loopback.
                || a == 0
                // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved: never a host.
                || ip.is_multicast()
                || (a & 0xf0) == 240
                // 198.18.0.0/15 benchmarking (RFC 2544) and 192.0.0.0/24 IETF
                // protocol assignments (RFC 6890).
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0)
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_multicast()
                || is_unicast_link_local_ipv6(ip)
                || is_site_local_ipv6(ip)
                || is_local_use_nat64(ip)
                || embedded_ipv4_addresses(ip)
                    .into_iter()
                    .flatten()
                    .any(|embedded| is_private_or_internal_ip(IpAddr::V4(embedded)))
        }
    }
}

/// IPv4 addresses carried inside transition-mechanism IPv6 prefixes. Each is
/// checked against the IPv4 policy so an IPv6 literal cannot smuggle a
/// private IPv4 target past the v4 range checks: RFC 4291 mapped and
/// compatible forms, RFC 6052 NAT64, RFC 3056 6to4, and RFC 4380 Teredo
/// (server address, plus the client address stored inverted).
fn embedded_ipv4_addresses(ip: Ipv6Addr) -> [Option<Ipv4Addr>; 5] {
    let s = ip.segments();
    let pair = |high: u16, low: u16| Ipv4Addr::from(((high as u32) << 16) | low as u32);
    let nat64 =
        (s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0]).then(|| pair(s[6], s[7]));
    let six_to_four = (s[0] == 0x2002).then(|| pair(s[1], s[2]));
    let teredo = s[0] == 0x2001 && s[1] == 0;
    let teredo_server = teredo.then(|| pair(s[2], s[3]));
    let teredo_client = teredo.then(|| Ipv4Addr::from(!(((s[6] as u32) << 16) | s[7] as u32)));
    [
        ip.to_ipv4(),
        nat64,
        six_to_four,
        teredo_server,
        teredo_client,
    ]
}

/// 64:ff9b:1::/48 is the local-use NAT64 prefix (RFC 8215): the embedded
/// address is site-specific, so the whole block is internal.
fn is_local_use_nat64(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001
}

fn is_unicast_link_local_ipv6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// fec0::/10 site-local unicast (RFC 3879 deprecated it, stacks still route
/// it). It sits just outside the fe80::/10 link-local mask, so it needs its
/// own check rather than a wider mask that would also swallow fe00::/9.
fn is_site_local_ipv6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfec0
}

fn has_host_token(host: &str, token: &str) -> bool {
    host.split('.')
        .flat_map(|label| label.split('-'))
        .any(|part| part == token)
}

/// Hostnames local dev environments publish for a site served from this
/// machine. They resolve to loopback but do not read as local, so inference
/// has to know them by name: DDEV, Lando, Docksal, and the RFC 6761 `.test`
/// TLD used by Valet/Herd and hand-rolled Docker setups.
/// Mirrored by LOCAL_DEV_HOST_SUFFIXES in src/lib/project-environments.ts.
const LOCAL_DEV_HOST_SUFFIXES: &[&str] = &[".ddev.site", ".lndo.site", ".docksal.site", ".test"];

/// Whether a host is an IP literal on a network this machine is attached to.
/// A name-matching rule cannot see these: a dev server on the LAN is reached
/// as `http://192.168.1.40:8080/`, with no hostname to recognize.
///
/// The native network policy uses the same ranges a named scan
/// target may reach, so every address a scan can fetch that is not public is
/// graded as a local environment.
fn is_private_ip_literal(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().is_ok_and(is_private_network_ip)
}

fn environment_from_host(host: &str) -> &'static str {
    let lower = host.to_lowercase();

    if is_project_loopback_host(&lower)
        || lower.ends_with(".local")
        || lower.ends_with(".localhost")
        || LOCAL_DEV_HOST_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        || is_private_ip_literal(&lower)
    {
        return "local";
    }

    if has_host_token(&lower, "dev") || has_host_token(&lower, "development") {
        return "development";
    }

    if has_host_token(&lower, "staging")
        || has_host_token(&lower, "stage")
        || has_host_token(&lower, "preview")
        || has_host_token(&lower, "qa")
        || lower.ends_with(".vercel.app")
        || lower.ends_with(".netlify.app")
        || lower.ends_with(".onrender.com")
    {
        return "staging";
    }

    "production"
}

/// Detect if a URL is a localhost/pre-deploy URL (broad - includes *.local, *.localhost)
pub fn is_localhost(url: &url::Url) -> bool {
    match url.host_str() {
        Some(host) => environment_from_host(host) == "local",
        None => false,
    }
}

/// Infer the best default environment label for a URL from its hostname.
pub fn infer_environment_name(url: &str) -> &'static str {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(environment_from_host))
        .unwrap_or("production")
}

/// Normalize a user-provided environment label into the canonical set used by SiteCMD.
pub fn normalize_environment_name(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => None,
        "local" | "localhost" | "loopback" => Some("local"),
        "development" | "dev" => Some("development"),
        "staging" | "stage" | "preview" | "qa" | "test" | "testing" => Some("staging"),
        "production" | "prod" | "live" => Some("production"),
        _ => None,
    }
}

/// Resolve a canonical environment, giving localhost URLs precedence over labels.
pub fn resolve_environment_name(url: &str, provided: Option<&str>) -> &'static str {
    let inferred = infer_environment_name(url);
    match provided.and_then(normalize_environment_name) {
        Some(_) if inferred == "local" => "local",
        Some("local") if inferred != "local" => inferred,
        Some("production") if inferred != "production" => inferred,
        Some(normalized) => normalized,
        None => inferred,
    }
}

fn is_strict_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || matches!(host, "127.0.0.1" | "::1" | "[::1]")
}

fn is_project_loopback_host(host: &str) -> bool {
    host == "0.0.0.0" || is_strict_loopback_host(host)
}

/// True only for exact loopback hosts. Local names and subdomains may resolve remotely.
pub fn is_strict_localhost(url: &url::Url) -> bool {
    url.host_str().is_some_and(is_strict_loopback_host)
}

/// Canonical URL identity shared by project detection and environment deduplication.
pub fn url_identity_key(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(parsed) => {
            let host = parsed
                .host_str()
                .map(|host| {
                    if is_project_loopback_host(host) {
                        "localhost".to_string()
                    } else {
                        host.to_ascii_lowercase()
                    }
                })
                .unwrap_or_default();
            let port = parsed
                .port()
                .map(|port| format!(":{}", port))
                .unwrap_or_default();
            let path = {
                let trimmed = parsed.path().trim_end_matches('/');
                if trimmed.is_empty() {
                    "/"
                } else {
                    trimmed
                }
            };
            let query = parsed
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();
            format!(
                "{}://{}{}{}{}",
                parsed.scheme().to_ascii_lowercase(),
                host,
                port,
                path,
                query
            )
        }
        Err(_) => raw.trim().trim_end_matches('/').to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localhost_detection() {
        let cases = vec![
            ("http://localhost:3000", true),
            ("http://127.0.0.1:8080", true),
            ("http://0.0.0.0:5173", true),
            ("http://myapp.local", true),
            ("http://myapp.localhost:3000", true),
            ("http://[::1]:5173", true),
            ("https://myapp.ddev.site", true),
            ("https://myapp.lndo.site", true),
            ("https://myapp.docksal.site", true),
            ("https://myapp.test", true),
            // A dev server reached by LAN address has no hostname to match.
            ("http://192.168.1.40:8080", true),
            ("http://10.0.0.5:3000", true),
            ("http://172.16.4.2", true),
            ("http://[fd00::1]:8080", true),
            ("http://100.100.4.7", true),
            // Link-local is refused at the scan boundary rather than graded,
            // because cloud metadata answers there.
            ("http://169.254.169.254", false),
            // A public literal stays public; the ranges are the whole test.
            ("http://93.184.216.34", false),
            ("http://[2606:2800:220:1::248]", false),
            ("https://ddev.site.example.com", false),
            ("https://localhost.example.com", false),
            ("https://example.com", false),
            ("https://www.google.com", false),
        ];

        for (url_str, expected) in cases {
            let url = url::Url::parse(url_str).unwrap();
            assert_eq!(is_localhost(&url), expected, "Failed for {}", url_str);
        }
    }

    #[test]
    fn test_strict_localhost_detection() {
        let cases = vec![
            ("http://localhost:3000", true),
            ("http://127.0.0.1:8080", true),
            ("http://[::1]:5173", true),
            // These are localhost but NOT strict-localhost (mDNS/DNS resolved)
            ("http://0.0.0.0:5173", false),
            ("http://myapp.local", false),
            ("http://myapp.localhost:3000", false),
            // A dev-environment hostname is a local environment, but it is
            // resolved through DNS, so it never earns the loopback exception.
            ("https://myapp.ddev.site", false),
            // A LAN address is a local environment, but it is another machine
            // on the network, so it never earns the loopback exception.
            ("http://192.168.1.40:8080", false),
            ("http://[fd00::1]:8080", false),
            // Obviously not localhost
            ("https://example.com", false),
            ("https://www.google.com", false),
        ];

        for (url_str, expected) in cases {
            let url = url::Url::parse(url_str).unwrap();
            assert_eq!(
                is_strict_localhost(&url),
                expected,
                "strict failed for {}",
                url_str
            );
        }
    }

    #[test]
    fn test_infer_environment_name() {
        let cases = vec![
            ("http://localhost:3000", "local"),
            ("http://127.0.0.1:8080", "local"),
            ("http://myapp.localhost:3000", "local"),
            ("https://dev.example.com", "development"),
            ("https://marketing-stage.example.com", "staging"),
            ("https://preview-my-app.vercel.app", "staging"),
            ("https://qa.example.com", "staging"),
            ("https://smarthomeu.ddev.site", "local"),
            ("https://myapp.lndo.site", "local"),
            ("http://myapp.docksal.site", "local"),
            ("http://myapp.test", "local"),
            ("http://192.168.1.40:8080", "local"),
            ("http://10.0.0.5:3000", "local"),
            ("http://93.184.216.34", "production"),
            ("https://localhost.example.com", "production"),
            ("https://ddev.site.example.com", "production"),
            ("https://upstage.example.com", "production"),
            ("https://example.com", "production"),
            ("not-a-url", "production"),
        ];

        for (url, expected) in cases {
            assert_eq!(
                infer_environment_name(url),
                expected,
                "infer failed for {}",
                url
            );
        }
    }

    #[test]
    fn test_normalize_environment_name() {
        let cases = vec![
            ("localhost", Some("local")),
            ("dev", Some("development")),
            ("preview", Some("staging")),
            ("qa", Some("staging")),
            ("prod", Some("production")),
            ("live", Some("production")),
            ("", None),
            ("custom", None),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                normalize_environment_name(raw),
                expected,
                "normalize failed for {}",
                raw
            );
        }
    }

    #[test]
    fn test_resolve_environment_name() {
        let cases = vec![
            ("http://127.0.0.1:4321", Some("production"), "local"),
            ("https://dev.example.com", Some("production"), "development"),
            (
                "https://preview-my-app.vercel.app",
                Some("preview"),
                "staging",
            ),
            ("https://localhost.example.com", Some("local"), "production"),
            ("https://upstage.example.com", Some("staging"), "staging"),
            ("https://example.com", Some("prod"), "production"),
            ("https://example.com", Some("staging"), "staging"),
            ("https://example.com", Some("custom"), "production"),
            ("https://qa.example.com", None, "staging"),
            // A dev-environment hostname keeps the label its config file
            // declared instead of being downgraded to production.
            ("https://smarthomeu.ddev.site", Some("local"), "local"),
            ("https://myapp.lndo.site", Some("local"), "local"),
            ("http://myapp.docksal.site", Some("local"), "local"),
            ("http://myapp.test", Some("local"), "local"),
        ];

        for (url, provided, expected) in cases {
            assert_eq!(
                resolve_environment_name(url, provided),
                expected,
                "resolve failed for {} with {:?}",
                url,
                provided
            );
        }
    }

    #[test]
    fn url_identity_key_folds_loopback_and_normalizes() {
        // All loopback aliases collapse to one key so project detection and
        // environment dedupe agree on identity.
        let k = url_identity_key("http://127.0.0.1:4321/");
        assert_eq!(k, "http://localhost:4321/");
        assert_eq!(url_identity_key("http://localhost:4321"), k);
        assert_eq!(url_identity_key("http://0.0.0.0:4321/"), k);
        assert_eq!(url_identity_key("http://[::1]:4321"), k);

        // Scheme + host lowercased; path case preserved; trailing slash trimmed.
        assert_eq!(
            url_identity_key("HTTPS://Example.COM/Path/"),
            "https://example.com/Path"
        );
        // Empty path normalizes to "/"; query is kept verbatim.
        assert_eq!(
            url_identity_key("https://example.com"),
            "https://example.com/"
        );
        assert_eq!(
            url_identity_key("https://example.com/?a=1"),
            "https://example.com/?a=1"
        );

        // Unparseable input falls back to a trimmed, lowercased raw string.
        assert_eq!(url_identity_key("  NOT A URL/  "), "not a url");
    }
}
