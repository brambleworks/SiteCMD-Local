//! Broad local-environment inference and strict loopback checks for security decisions.

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
/// `network_policy` owns the ranges, and it is the same set a named scan
/// target may reach, so every address a scan can fetch that is not public is
/// graded as a local environment.
fn is_private_ip_literal(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>()
        .is_ok_and(crate::network_policy::is_private_network_ip)
}

fn environment_from_host(host: &str) -> &'static str {
    let lower = host.to_lowercase();

    if lower == "localhost"
        || lower == "127.0.0.1"
        || lower == "0.0.0.0"
        || lower == "::1"
        || lower == "[::1]"
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

/// True only for exact loopback hosts; `.local` and subdomains may resolve remotely.
pub fn is_strict_localhost(url: &url::Url) -> bool {
    match url.host_str() {
        Some(host) => {
            let h = host.to_lowercase();
            h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
        }
        None => false,
    }
}

/// Whether an `http://` loopback endpoint may stand in for an HTTPS origin,
/// which is what lets a wire test point a service client at a local double.
/// Only a test build has an arm that can answer true, so a release binary
/// cannot honor the flag whatever a caller passes it.
#[cfg(test)]
pub fn loopback_endpoint_allowed(allowed_by_caller: bool, url: &url::Url) -> bool {
    allowed_by_caller && url.scheme() == "http" && is_strict_localhost(url)
}

#[cfg(not(test))]
pub fn loopback_endpoint_allowed(_allowed_by_caller: bool, _url: &url::Url) -> bool {
    false
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
}
