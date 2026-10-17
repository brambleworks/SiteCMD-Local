//! seo.charset: the character-encoding declaration HTML5 requires within
//! the first 1024 bytes (or on the Content-Type header).

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use regex::Regex;
use std::sync::LazyLock;

/// HTML5 requires the character-encoding declaration, when it lives in the
/// document, to appear within the first 1024 bytes. A `charset=` parameter on
/// the Content-Type response header satisfies the requirement on its own.
static META_CHARSET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<meta\s[^>]*?(?:charset\s*=|http-equiv\s*=\s*["']?content-type["']?[^>]*charset\s*=)"#)
        .expect("valid meta charset regex")
});

const CHARSET_BYTE_BUDGET: usize = 1024;

pub struct MetaCharsetCheck;

impl Check for MetaCharsetCheck {
    fn id(&self) -> &str {
        "seo.charset"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let header_declares_charset = ctx
            .response_headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_ascii_lowercase().contains("charset="))
            .unwrap_or(false);
        let meta_offset = META_CHARSET_RE.find(&ctx.body).map(|m| m.start());

        let (status, title, description) = match (header_declares_charset, meta_offset) {
            (true, _) => (
                CheckStatus::Pass,
                "Character encoding declared",
                "The character encoding is declared in the Content-Type header or an early <meta charset> within the first 1024 bytes, giving the HTML parser an explicit encoding before substantial document content.".to_string(),
            ),
            (false, Some(offset)) if offset < CHARSET_BYTE_BUDGET => (
                CheckStatus::Pass,
                "Character encoding declared",
                "The character encoding is declared in the Content-Type header or an early <meta charset> within the first 1024 bytes, giving the HTML parser an explicit encoding before substantial document content.".to_string(),
            ),
            (false, Some(offset)) => (
                CheckStatus::Warn,
                "Charset declared too late",
                format!(
                    "The <meta charset> declaration starts around byte {} - past the 1024-byte window HTML5 gives browsers for it. Until the declaration is seen, the browser guesses the encoding, which can garble non-ASCII text and trigger a re-parse.",
                    offset
                ),
            ),
            (false, None) => (
                CheckStatus::Fail,
                "No character encoding declared",
                "Neither the Content-Type header nor a <meta charset> tag declares the page encoding. Browsers fall back to guessing, which garbles accented characters, quotes, and non-Latin text unpredictably.".to_string(),
            ),
        };

        let passing = status == CheckStatus::Pass;
        vec![CheckResult {
            check_id: "seo.charset".into(),
            category: ScanCategory::Seo,
            title: title.into(),
            description,
            status,
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if passing {
                None
            } else {
                Some("Put <meta charset=\"utf-8\"> as the first element inside <head>, before <title> and any other tags, or add `; charset=utf-8` to the Content-Type response header.".into())
            },
            raw_data: Some(serde_json::json!({
                "header_declares_charset": header_declares_charset,
                "meta_charset_byte_offset": meta_offset,
            })),
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: if passing {
                None
            } else {
                Some("An undeclared or late encoding shows up as mojibake - garbled quotes and accents - on real pages.".into())
            },
        }]
    }
}
