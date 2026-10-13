//! seo.og_image_relative: Open Graph URL values must be absolute.

use super::extract_meta;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct OgImageAbsoluteCheck;

impl Check for OgImageAbsoluteCheck {
    fn id(&self) -> &str {
        "seo.og_image_relative"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        // The Open Graph protocol defines these values as full URLs. Platform
        // fallback behavior is not uniform, so report non-absolute syntax
        // without claiming every preview necessarily fails.
        let mut relative: Vec<(&str, String)> = Vec::new();
        for tag in ["og:image", "og:url"] {
            if let Some(value) = extract_meta(&ctx.body, tag) {
                let trimmed = value.trim().to_string();
                let lower = trimmed.to_ascii_lowercase();
                if !trimmed.is_empty()
                    && !lower.starts_with("http://")
                    && !lower.starts_with("https://")
                {
                    let safe_value = crate::log_sanitizer::evidence_safe_url_reference(&trimmed);
                    relative.push((tag, safe_value));
                }
            }
        }

        let listed = relative
            .iter()
            .map(|(tag, value)| format!("{}=\"{}\"", tag, value))
            .collect::<Vec<_>>()
            .join(", ");
        vec![CheckResult {
            check_id: "seo.og_image_relative".into(),
            category: ScanCategory::Seo,
            title: if relative.is_empty() {
                "Open Graph URLs are absolute".into()
            } else {
                "Open Graph URL values are not absolute".into()
            },
            description: if relative.is_empty() {
                "The inspected og:image and og:url values, when present and non-empty, use absolute HTTP(S) URLs. This syntax check does not verify that the targets load or that a platform will render a preview.".into()
            } else {
                format!(
                    "These Open Graph tags carry relative, protocol-relative, or non-HTTP(S) URL values: {}. They do not meet the protocol's full-URL shape; platform resolution and fallback behavior varies, so preview failure is not asserted from syntax alone.",
                    listed
                )
            },
            status: if relative.is_empty() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Medium,
            fix_prompt: None,
            manual_fix: if relative.is_empty() {
                None
            } else {
                Some("Emit a canonical absolute HTTPS URL, including the intended host and path, for og:image and og:url. Configure the framework's current canonical-site/metadata base when available, then inspect the deployed HTML, fetch the image logged out, and test supported platforms with their preview tools.".into())
            },
            raw_data: if relative.is_empty() {
                None
            } else {
                Some(serde_json::json!({
                    "relative_values": relative
                        .iter()
                        .map(|(tag, value)| serde_json::json!({"tag": tag, "value": value}))
                        .collect::<Vec<_>>(),
                }))
            },
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: if relative.is_empty() {
                None
            } else {
                Some("Non-absolute Open Graph URLs are less portable because consumers are not required to infer the page origin. Some platforms may recover, but supported previews should be verified rather than assumed.".into())
            },
        }]
    }
}
