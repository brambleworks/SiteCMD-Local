//! Detects version-bearing server headers.

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct ServerInfoCheck;

impl Check for ServerInfoCheck {
    fn id(&self) -> &str {
        "security.server_info"
    }

    /// Never emits its own id; each header gets its own sub-check verdict.
    fn emitted_ids(&self) -> Vec<String> {
        ["server_header", "x_powered_by"]
            .iter()
            .map(|suffix| format!("security.server_info.{suffix}"))
            .collect()
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if ctx.is_localhost {
            let preview_note = "Skipped on localhost preview. Server identification headers often reflect the local preview server rather than your deployed production stack.".to_string();
            return vec![
                CheckResult {
                    check_id: "security.server_info.server_header".into(),
                    category: ScanCategory::Security,
                    title: "Server header information".into(),
                    description: preview_note.clone(),
                    status: CheckStatus::Skipped,
                    severity: Severity::Low,
                    fix_prompt: None,
                    manual_fix: None,
                    raw_data: Some(serde_json::json!({ "reason": "localhost_preview_server" })),
                    confidence: crate::checks::IssueConfidence::High,
                    confidence_reason: None,
                    why_it_matters: None,
                },
                CheckResult {
                    check_id: "security.server_info.x_powered_by".into(),
                    category: ScanCategory::Security,
                    title: "X-Powered-By header".into(),
                    description: preview_note,
                    status: CheckStatus::Skipped,
                    severity: Severity::Low,
                    fix_prompt: None,
                    manual_fix: None,
                    raw_data: Some(serde_json::json!({ "reason": "localhost_preview_server" })),
                    confidence: crate::checks::IssueConfidence::High,
                    confidence_reason: None,
                    why_it_matters: None,
                },
            ];
        }

        let headers = &ctx.response_headers;
        let mut results = Vec::new();

        // Server header
        let server_header = headers.get("server").and_then(|v| v.to_str().ok());
        if let Some(server) = server_header {
            // Slashes or digits may expose a version, deploy hash, or build id,
            // so copy names the broader "version or build information".
            let reveals_version =
                server.contains('/') || server.chars().any(|c| c.is_ascii_digit());
            results.push(CheckResult {
                check_id: "security.server_info.server_header".into(),
                category: ScanCategory::Security,
                title: if reveals_version {
                    "Server header reveals version or build information".into()
                } else {
                    "Server header information".into()
                },
                description: if reveals_version {
                    format!(
                        "The Server response header contains product plus version- or build-like information: '{}'. This can make passive fingerprinting easier, but it does not establish that the software is vulnerable, and removing the header is not a substitute for patching. Proxies and CDNs may also supply or rewrite the value.",
                        server
                    )
                } else {
                    format!("Server header is set to '{}' without version details.", server)
                },
                status: if reveals_version { CheckStatus::Warn } else { CheckStatus::Pass },
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: if reveals_version {
                    Some("Confirm which layer emits the header. If the detail is unnecessary, use that server, proxy, or platform's supported setting to suppress version/build data; verify the production response after every proxy/CDN hop. Prioritize inventory and timely patching because the stack can often be inferred through other behavior.".into())
                } else { None },
                raw_data: Some(serde_json::json!({ "server": server })),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: if reveals_version {
                    Some("Detailed product metadata can reduce reconnaissance effort, although patch status and reachable behavior determine actual risk.".into())
                } else { None },
            });
        } else {
            results.push(CheckResult {
                check_id: "security.server_info.server_header".into(),
                category: ScanCategory::Security,
                title: "Server header information".into(),
                description: "No Server response header was present. This confirms only that this header does not disclose server metadata; the technology stack may still be observable through other headers, assets, or behavior.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            });
        }

        // X-Powered-By header
        let powered_by = crate::header_lines::field_value(headers, "x-powered-by");
        if let Some(value) = powered_by.as_deref() {
            results.push(CheckResult {
                check_id: "security.server_info.x_powered_by".into(),
                category: ScanCategory::Security,
                title: "X-Powered-By header reveals technology stack".into(),
                description: format!(
                    "The X-Powered-By response header identifies application technology: '{}'. This can make passive fingerprinting easier, but it does not establish a vulnerability and removing it is not a substitute for patching. A proxy or framework may add the header outside application code.",
                    value
                ),
                status: CheckStatus::Warn,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: Some("Confirm which application, proxy, or platform layer emits X-Powered-By, then use that component's supported configuration to remove it if the metadata has no operational value. Verify the production response after all hops and keep the underlying runtime inventoried and patched.".into()),
                raw_data: Some(serde_json::json!({ "x_powered_by": value })),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: Some("Technology metadata can reduce reconnaissance effort, although patch status, configuration, and reachable behavior determine actual risk.".into()),
            });
        } else {
            results.push(CheckResult {
                check_id: "security.server_info.x_powered_by".into(),
                category: ScanCategory::Security,
                title: "X-Powered-By header".into(),
                description: "No X-Powered-By response header was present. This confirms only that this header does not identify the application framework; other responses and assets may still reveal the stack.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            });
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Check, CheckStatus, PageContext};
    use http::header::{HeaderMap, HeaderValue};

    fn ctx_with_headers(headers: HeaderMap) -> PageContext {
        PageContext {
            evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: headers,
            status_code: 200,
            body: String::new(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: Some("HTTP/2.0".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        }
    }

    fn localhost_ctx_with_headers(headers: HeaderMap) -> PageContext {
        PageContext {
            evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            url: url::Url::parse("http://127.0.0.1:4324").unwrap(),
            response_headers: headers,
            status_code: 200,
            body: String::new(),
            is_localhost: true,
            is_strict_localhost: false,
            http_version: Some("HTTP/1.1".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn test_server_info_version_exposed_warn() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx/1.21.0"));
        let check = ServerInfoCheck;
        let results = check.run(&ctx_with_headers(h));
        let server = results
            .iter()
            .find(|r| r.check_id == "security.server_info.server_header")
            .unwrap();
        assert_eq!(server.status, CheckStatus::Warn);
    }

    #[test]
    fn deploy_hash_server_header_is_described_as_version_or_build() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("Fly/0d4d5b8a"));
        let check = ServerInfoCheck;
        let results = check.run(&ctx_with_headers(h));
        let server = results
            .iter()
            .find(|r| r.check_id == "security.server_info.server_header")
            .unwrap();
        assert_eq!(server.status, CheckStatus::Warn);
        assert!(
            server
                .description
                .contains("version- or build-like information"),
            "{}",
            server.description
        );
        assert!(!server.description.contains("detailed version information"));
    }

    #[test]
    fn test_server_info_no_version_pass() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx"));
        let check = ServerInfoCheck;
        let results = check.run(&ctx_with_headers(h));
        let server = results
            .iter()
            .find(|r| r.check_id == "security.server_info.server_header")
            .unwrap();
        assert_eq!(server.status, CheckStatus::Pass);
    }

    #[test]
    fn test_server_info_no_header_pass() {
        let check = ServerInfoCheck;
        let results = check.run(&ctx_with_headers(HeaderMap::new()));
        let server = results
            .iter()
            .find(|r| r.check_id == "security.server_info.server_header")
            .unwrap();
        assert_eq!(server.status, CheckStatus::Pass);
        let powered = results
            .iter()
            .find(|r| r.check_id == "security.server_info.x_powered_by")
            .unwrap();
        assert_eq!(powered.status, CheckStatus::Pass);
    }

    #[test]
    fn test_server_info_x_powered_by_warn() {
        let mut h = HeaderMap::new();
        h.insert("x-powered-by", HeaderValue::from_static("Express"));
        let check = ServerInfoCheck;
        let results = check.run(&ctx_with_headers(h));
        let powered = results
            .iter()
            .find(|r| r.check_id == "security.server_info.x_powered_by")
            .unwrap();
        assert_eq!(powered.status, CheckStatus::Warn);
    }

    #[test]
    fn test_server_info_localhost_preview_is_skipped() {
        let mut h = HeaderMap::new();
        h.insert(
            "server",
            HeaderValue::from_static("SimpleHTTP/0.6 Python/3.14.3"),
        );
        h.insert("x-powered-by", HeaderValue::from_static("PreviewServer"));
        let check = ServerInfoCheck;
        let results = check.run(&localhost_ctx_with_headers(h));
        let server = results
            .iter()
            .find(|r| r.check_id == "security.server_info.server_header")
            .unwrap();
        assert_eq!(server.status, CheckStatus::Skipped);
        let powered = results
            .iter()
            .find(|r| r.check_id == "security.server_info.x_powered_by")
            .unwrap();
        assert_eq!(powered.status, CheckStatus::Skipped);
    }
}
