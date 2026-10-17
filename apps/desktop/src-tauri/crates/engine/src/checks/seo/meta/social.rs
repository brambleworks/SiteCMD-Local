//! Open Graph and Twitter card metadata.

use super::extract_meta;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct OpenGraphCheck;

impl Check for OpenGraphCheck {
    fn id(&self) -> &str {
        "seo.open_graph"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let og_title = extract_meta(&ctx.body, "og:title").filter(|value| !value.trim().is_empty());
        let og_desc =
            extract_meta(&ctx.body, "og:description").filter(|value| !value.trim().is_empty());
        let og_image = extract_meta(&ctx.body, "og:image").filter(|value| !value.trim().is_empty());

        let mut missing = Vec::new();
        if og_title.is_none() {
            missing.push("og:title");
        }
        if og_desc.is_none() {
            missing.push("og:description");
        }
        if og_image.is_none() {
            missing.push("og:image");
        }

        vec![CheckResult {
            check_id: "seo.open_graph".into(),
            category: ScanCategory::Seo,
            title: if missing.is_empty() {
                "Open Graph tags".into()
            } else if missing.len() == 1 {
                "Missing Open Graph tag".into()
            } else {
                "Missing Open Graph tags".into()
            },
            description: if missing.is_empty() {
                "og:title, og:description, and og:image are present. These fields give compatible link-preview clients the basic metadata they need, but preview rendering still depends on image fetchability, platform rules, and cache state.".into()
            } else {
                format!(
                    "Missing Open Graph tag{}: {}. Compatible link-preview clients may fall back to the document title, description, another image, or a reduced preview when these fields are absent.",
                    if missing.len() == 1 { "" } else { "s" },
                    missing.join(", "),
                )
            },
            status: if missing.is_empty() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if missing.is_empty() {
                None
            } else {
                Some("Add OG tags in <head>: <meta property=\"og:title\" content=\"...\"> <meta property=\"og:description\" content=\"...\"> <meta property=\"og:image\" content=\"...\">".into())
            },
            raw_data: Some(
                serde_json::json!({"og_title": og_title, "og_description": og_desc, "og_image": og_image}),
            ),
            confidence: if missing.is_empty() {
                crate::checks::IssueConfidence::High
            } else {
                crate::checks::IssueConfidence::NeedsReview
            },
            confidence_reason: if missing.is_empty() {
                None
            } else {
                Some("The fields are directly absent or empty in the fetched HTML, but whether Open Graph metadata is required depends on the site's sharing channels and each client's fallback behavior.".into())
            },
            why_it_matters: if missing.is_empty() {
                None
            } else {
                Some("Open Graph fields let compatible clients choose an intentional title, summary, and image; exact rendering and caching remain platform-specific.".into())
            },
        }]
    }
}

pub struct TwitterCardCheck;

impl Check for TwitterCardCheck {
    fn id(&self) -> &str {
        "seo.twitter_cards"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let card = extract_meta(&ctx.body, "twitter:card").filter(|value| !value.trim().is_empty());
        let has_complete_og_fallback = extract_meta(&ctx.body, "og:title").is_some()
            && extract_meta(&ctx.body, "og:description").is_some()
            && extract_meta(&ctx.body, "og:image").is_some();

        vec![CheckResult {
            check_id: "seo.twitter_cards".into(),
            category: ScanCategory::Seo,
            title: if card.is_some() {
                "Twitter Card type".into()
            } else {
                "Missing Twitter Card type".into()
            },
            description: if card.is_some() {
                "A non-empty twitter:card value is present. This confirms an explicit card-type request only; it does not verify that the value is currently supported, that title/image fields are complete, or that X/Twitter will render a preview.".into()
            } else if has_complete_og_fallback {
                "No twitter:card type was found. Complete Open Graph fields are present and can supply fallback values, but an explicit card type is needed to request a particular X/Twitter card format; final rendering remains platform-controlled.".into()
            } else {
                "No twitter:card type was found, and the basic Open Graph fallback set is incomplete. X/Twitter may render a reduced link treatment or derive values from other page metadata.".into()
            },
            status: if card.is_some() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if card.is_some() {
                None
            } else {
                Some("Add an explicit <meta name=\"twitter:card\" content=\"summary\"> or content=\"summary_large_image\"> based on the image treatment you intend, and provide valid title, description, and image values through twitter:* tags or their supported Open Graph fallbacks. Verify the production URL after the platform recrawls it.".into())
            },
            raw_data: Some(serde_json::json!({
                "twitter_card": card.as_deref(),
                "has_complete_open_graph_fallback": has_complete_og_fallback,
            })),
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: if card.is_some() {
                None
            } else {
                Some("An explicit card type documents the intended X/Twitter presentation. Open Graph can provide field-level fallbacks, but it does not guarantee a particular card layout or that a preview will render.".into())
            },
        }]
    }
}
