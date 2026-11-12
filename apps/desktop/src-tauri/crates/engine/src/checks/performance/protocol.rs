//! Check HTTP protocol support and total inline CSS size.
//! Thresholds align with page-weight severity tiers.

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use std::sync::LazyLock;

static STYLE_BLOCK_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<style[^>]*>(.*?)</style>").unwrap());

/// The protocol observed by the runtime's connection to the entry page.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NegotiatedProtocol {
    pub protocol: String,
    pub observed_at: String,
}

impl NegotiatedProtocol {
    fn http_version(&self) -> Option<&'static str> {
        match self.protocol.as_str() {
            "h2" => Some("HTTP/2"),
            "h3" => Some("HTTP/3"),
            "http/1.1" => Some("HTTP/1.1"),
            "http/1.0" => Some("HTTP/1.0"),
            _ => None,
        }
    }
}

/// Check if the server supports HTTP/2
pub struct Http2Check;

impl Check for Http2Check {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "performance.http2"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Performance
    }
    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        self.run_with_protocol(ctx, None)
    }
}

impl Http2Check {
    /// Grade the page's own observation first, falling back to the runtime fact.
    pub fn run_with_protocol(
        &self,
        ctx: &PageContext,
        negotiated_protocol: Option<&NegotiatedProtocol>,
    ) -> Vec<CheckResult> {
        let version = ctx
            .http_version
            .as_deref()
            .or_else(|| negotiated_protocol.and_then(NegotiatedProtocol::http_version));
        let Some(version) = version else {
            return vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "HTTP/2 Support".into(),
                description:
                    "The negotiated HTTP protocol was not observed, so this check did not grade it."
                        .into(),
                status: CheckStatus::Skipped,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: Some(serde_json::json!({"reason": "protocol_not_observed"})),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }];
        };

        // Local dev servers speak HTTP/1.1; HTTP/2 comes from the
        // production server or CDN, so grading a preview scan produced
        // production advice for every local run.
        // compression.rs has the same skip.
        if ctx.is_localhost {
            return vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "HTTP/2 Support".into(),
                description: "Skipped on localhost preview. Local dev servers speak HTTP/1.1; HTTP/2 and HTTP/3 are provided by the deployed server or CDN.".into(),
                status: CheckStatus::Skipped,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: Some(serde_json::json!({"reason": "localhost_preview_server"})),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }];
        }

        let is_h2_plus = version.contains("HTTP/2") || version.contains("HTTP/3");
        // Browsers negotiate h2 and h3 through ALPN during the TLS handshake,
        // so a page served over plain HTTP cannot reach either one whatever
        // the server supports. HTTPS is the prerequisite, not a protocol
        // setting (neverssl.com received h2/h3 advice it could not act on).
        let plaintext_scheme = ctx.url.scheme() == "http";
        // Only the response header establishes an HTTP/3 advertisement.
        let advertises_h3 = crate::header_lines::field_value(&ctx.response_headers, "alt-svc")
            .is_some_and(|value| value.contains("h3"));

        vec![CheckResult {
            check_id: self.id().into(),
            category: self.category(),
            title: if is_h2_plus {
                "Modern HTTP protocol detected".into()
            } else if plaintext_scheme {
                "HTTP/1.x over plain HTTP".into()
            } else {
                "Response used HTTP/1.x".into()
            },
            description: if is_h2_plus {
                if advertises_h3 {
                    format!(
                        "This request used {}, and the response advertises HTTP/3 via Alt-Svc. Actual visitor negotiation still depends on browser, network, and the public proxy/CDN path.",
                        version
                    )
                } else if version.contains("HTTP/3") {
                    format!(
                        "This request used {}, which loads pages faster over one connection. What each visitor gets still depends on their browser, their network and your CDN.",
                        version
                    )
                } else {
                    format!(
                        "This request used {}, which provides multiplexing and header compression. HTTP/3 was not advertised in this response; that is optional and not a defect by itself.",
                        version
                    )
                }
            } else if plaintext_scheme {
                format!("This request used {} over plain HTTP. Browsers negotiate HTTP/2 and HTTP/3 through ALPN during the TLS handshake, so this page cannot reach either protocol until it is served over HTTPS.", version)
            } else {
                format!("This request used {}. HTTP/2 or HTTP/3 can reduce connection and request-serialization overhead for some pages, but the benefit depends on the resource graph, network, and proxy/CDN path.", version)
            },
            status: if is_h2_plus {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Medium,
            fix_prompt: None,
            manual_fix: if is_h2_plus {
                None
            } else if plaintext_scheme {
                Some("Serve this hostname over HTTPS first: obtain a certificate, redirect HTTP to HTTPS, and confirm the redirect target answers. HTTP/2 and HTTP/3 follow from the TLS handshake once that is in place, so re-test the protocol only after the site is reachable over HTTPS.".into())
            } else {
                Some("Identify the browser-facing server, CDN, or proxy that negotiated this response and enable HTTP/2 or HTTP/3 there using its current documentation. Public browser deployments normally negotiate modern protocols over TLS with ALPN. Re-test the public hostname and representative assets; do not change an origin hidden behind an HTTP/1.1-only upstream hop unless that is the visitor-facing bottleneck.".into())
            },
            raw_data: Some(serde_json::json!({
                "http_version": version,
                "alt_svc_h3": advertises_h3,
                "scheme": ctx.url.scheme(),
            })),
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: if is_h2_plus {
                None
            } else if plaintext_scheme {
                Some("Without TLS the page also has no transport confidentiality or integrity, and the protocol upgrade is unavailable to every visitor. HTTP/1.x can additionally require more connections and serialize requests per connection.".into())
            } else {
                Some("HTTP/1.x can require more connections and serialize requests per connection. On a resource-heavy or high-latency page that may add delay, while a small page or an internal upstream hop may see little user impact.".into())
            },
        }]
    }
}

/// Check for excessively large inline CSS
pub struct InlineCssSizeCheck;

impl Check for InlineCssSizeCheck {
    fn id(&self) -> &str {
        "performance.inline_css"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Performance
    }
    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let mut total_bytes: usize = 0;
        let mut block_count = 0u32;
        let mut large_blocks: Vec<String> = Vec::new();

        for cap in STYLE_BLOCK_RE.captures_iter(&ctx.body) {
            let content = &cap[1];
            let size = content.len();
            total_bytes += size;
            block_count += 1;

            // Use decimal KB so displayed sizes match byte thresholds.
            if size > 50_000 {
                large_blocks.push(format!("{}KB", size / 1000));
            }
        }

        let total_kb = total_bytes / 1000;
        // Inline CSS tiers: 50-100 KB warns, 100-200 KB is Medium, and only
        // values above 200 KB are High.
        let (status, severity) = if total_kb > 200 {
            (CheckStatus::Fail, Severity::High)
        } else if total_kb > 100 {
            (CheckStatus::Fail, Severity::Medium)
        } else if total_kb > 50 {
            (CheckStatus::Warn, Severity::Medium)
        } else {
            (CheckStatus::Pass, Severity::Low)
        };

        vec![CheckResult {
            check_id: self.id().into(),
            category: self.category(),
            title: if total_kb > 200 {
                "Inline CSS over 200KB".into()
            } else if total_kb > 100 {
                "Inline CSS over 100KB".into()
            } else if total_kb > 50 {
                "Inline CSS over 50KB".into()
            } else {
                "Inline CSS Size".into()
            },
            description: if status == CheckStatus::Pass {
                if block_count == 0 {
                    "No inline <style> blocks found.".into()
                } else {
                    format!(
                        "{}KB of inline CSS across {} block{} - below this check's 50KB review threshold.",
                        total_kb,
                        block_count,
                        if block_count == 1 { "" } else { "s" }
                    )
                }
            } else {
                format!("{}KB of inline CSS across {} block{}. This increases HTML and CSS parse work and cannot be cached independently from the document; actual paint impact depends on placement, reuse, compression, and the alternative request path.{}",
                    total_kb,
                    block_count,
                    if block_count == 1 { "" } else { "s" },
                    if !large_blocks.is_empty() { format!(" Large blocks: {}", large_blocks.join(", ")) } else { String::new() })
            },
            status,
            severity,
            fix_prompt: None,
            manual_fix: if status != CheckStatus::Pass {
                Some("Use a production browser trace and CSS coverage to separate critical, route-specific, and shared rules. Keep a measured amount of genuinely critical CSS inline when it helps; move reusable or non-critical rules to cacheable stylesheets only when the added request and loading order improve the supported pages. Re-test paint timing and unstyled-content behavior.".into())
            } else {
                None
            },
            raw_data: Some(serde_json::json!({
                "total_bytes": total_bytes,
                "block_count": block_count,
            })),
            confidence: if status == CheckStatus::Pass { crate::checks::IssueConfidence::High } else { crate::checks::IssueConfidence::NeedsReview },
            confidence_reason: (status != CheckStatus::Pass).then(|| "The inline byte count is direct, but source size alone does not determine paint delay; placement, compression, selector use, document caching, and the cost of an external request were not measured.".into()),
            why_it_matters: if status != CheckStatus::Pass {
                Some("Large inline CSS increases the document's transfer and parse work and cannot be cached independently. It can delay rendering when encountered before relevant content, but this source check does not measure that impact.".into())
            } else {
                None
            },
        }]
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
