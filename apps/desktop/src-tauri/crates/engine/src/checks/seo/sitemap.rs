//! Portable sitemap probe vocabulary and grading. Missing and inconclusive
//! outcomes remain distinct.

#[path = "sitemap_set.rs"]
mod set;
#[path = "sitemap_stack.rs"]
mod stack;

pub use set::{
    partial_reason, sitemap_bound_description, sitemap_identity, unread_sitemaps_count,
    unread_sitemaps_description, unread_sitemaps_reason, SitemapBound,
};
pub use stack::detect_stack_hint;
use stack::framework_specific_sitemap_fix;

use crate::checks::seo::robots::RobotsTxtFetch;
use crate::checks::{
    origin_with_port, CheckResult, CheckStatus, IssueConfidence, PageContext, ScanCategory,
    Severity,
};

/// Maximum same-origin `Sitemap:` declarations from robots.txt that one scan
/// will request. Conventional paths are still checked after this bounded set.
pub const SITEMAP_DECLARATION_PROBE_LIMIT: usize = 20;

/// First sitemap candidate that returned a well-formed `<urlset>` or
/// `<sitemapindex>` document with the required `<loc>` value on every entry.
/// This is deliberately a structural check rather than full XSD validation.
#[derive(Debug)]
pub struct SitemapFetch {
    pub url: String,
    /// Original sitemap document. Consumers that inspect element values must
    /// preserve their case; XML element-name comparisons are handled by the
    /// parser rather than by lowercasing the entire document.
    pub body: String,
    pub entry_count: usize,
    pub kind: SitemapKind,
}

impl SitemapFetch {
    /// Record a candidate that returned a valid sitemap. Every runtime builds
    /// this from a [`SitemapDocument`], so the entry count and the format
    /// label can never be derived two different ways.
    pub fn new(
        url: impl Into<String>,
        body: impl Into<String>,
        document: &SitemapDocument,
    ) -> Self {
        Self {
            url: url.into(),
            body: body.into(),
            entry_count: document.locs.len(),
            kind: document.kind,
        }
    }
}

/// One sanitized-for-presentation outcome from a sitemap candidate probe.
#[derive(Debug)]
pub struct SitemapProbeObservation {
    pub url: String,
    pub outcome: String,
}

/// Shared sitemap probe result. Missing and inconclusive are kept separate so
/// authentication, rate limiting, server errors, and transport failures never
/// become the false finding "no sitemap exists."
#[derive(Debug)]
pub enum SitemapProbe {
    Found(SitemapFetch),
    Missing {
        observations: Vec<SitemapProbeObservation>,
    },
    Inconclusive {
        observations: Vec<SitemapProbeObservation>,
    },
}

pub use super::sitemap_document::{
    parse_sitemap_document, sitemap_candidate_urls, sitemap_document_summary,
    sitemap_urls_from_robots, SitemapDocument, SitemapKind, SitemapParse, SITEMAP_CANDIDATE_PATHS,
};

/// Whether a declared candidate URL parses onto exactly the probed origin.
pub fn url_is_same_origin(candidate: &str, origin: &str) -> bool {
    url::Url::parse(candidate)
        .map(|u| origin_with_port(&u) == origin)
        .unwrap_or(false)
}

fn safe_sitemap_declaration(base: &str, raw: &str) -> String {
    if let Ok(parsed) = url::Url::parse(raw) {
        let safe = crate::log_sanitizer::evidence_safe_page_url(parsed.as_str());
        return if matches!(parsed.scheme(), "http" | "https") {
            safe
        } else {
            format!("{safe} (non-HTTP(S) as declared)")
        };
    }
    if let Ok(base_url) = url::Url::parse(base) {
        if let Ok(resolved) = base_url.join(raw.trim()) {
            return format!(
                "{} (relative as declared)",
                crate::log_sanitizer::evidence_safe_page_url(resolved.as_str())
            );
        }
    }
    "[unparseable-sitemap-declaration]".into()
}

fn evidence_preview(values: &[String], total_count: usize) -> String {
    if total_count <= values.len() {
        return values.join(", ");
    }
    format!(
        "{}, and {} more",
        values.join(", "),
        total_count - values.len()
    )
}

/// Grade the `seo.sitemap` outcome from the shared per-scan probe, the
/// robots.txt fetch (for declaration accounting), and the scanned page (for
/// the stack hint that makes the fix copy concrete).
pub fn evaluate_sitemap(
    page: &PageContext,
    robots: &RobotsTxtFetch,
    probe: &SitemapProbe,
) -> Vec<CheckResult> {
    let base = origin_with_port(&page.url);
    let conventional_urls = sitemap_candidate_urls(&base);
    let declared_all = robots
        .body()
        .map(sitemap_urls_from_robots)
        .unwrap_or_default();
    let mut same_origin_declared = Vec::new();
    let mut cross_origin_declared = Vec::new();
    let mut invalid_declaration_count = 0usize;
    for declared in &declared_all {
        match url::Url::parse(declared) {
            Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => {
                if origin_with_port(&parsed) == base {
                    same_origin_declared.push(declared.clone());
                } else {
                    cross_origin_declared.push(declared.clone());
                }
            }
            _ => invalid_declaration_count += 1,
        }
    }
    let same_origin_probe_truncated = same_origin_declared.len() > SITEMAP_DECLARATION_PROBE_LIMIT;
    let mut tested_urls: Vec<String> = same_origin_declared
        .iter()
        .take(SITEMAP_DECLARATION_PROBE_LIMIT)
        .cloned()
        .collect();
    for url in conventional_urls {
        if !tested_urls.contains(&url) {
            tested_urls.push(url);
        }
    }
    let safe_tested_urls: Vec<String> = tested_urls
        .iter()
        .map(|url| crate::log_sanitizer::evidence_safe_page_url(url))
        .collect();
    let safe_declared: Vec<String> = declared_all
        .iter()
        .take(SITEMAP_DECLARATION_PROBE_LIMIT)
        .map(|url| safe_sitemap_declaration(&base, url))
        .collect();
    let declared_evidence_truncated = declared_all.len() > safe_declared.len();
    let safe_cross_origin: Vec<String> = cross_origin_declared
        .iter()
        .take(SITEMAP_DECLARATION_PROBE_LIMIT)
        .map(|url| crate::log_sanitizer::evidence_safe_page_url(url))
        .collect();
    let cross_origin_evidence_truncated = cross_origin_declared.len() > safe_cross_origin.len();
    let has_cross_origin = !cross_origin_declared.is_empty();

    if let SitemapProbe::Found(found) = probe {
        let safe_url = crate::log_sanitizer::evidence_safe_page_url(&found.url);
        let entry_label = found.kind.entry_label();
        // A plain-text sitemap has no root element to name, so the copy
        // describes the format instead of pretending there is a <text> tag.
        let document_label = match found.kind {
            SitemapKind::Text => "A plain-text sitemap".to_string(),
            kind => format!("A well-formed <{}> document", kind.label()),
        };
        let empty = found.entry_count == 0;
        return vec![CheckResult {
            check_id: "seo.sitemap".into(),
            category: ScanCategory::Seo,
            title: if empty {
                "Sitemap document has no entries".into()
            } else if found.kind == SitemapKind::Text {
                "Plain-text sitemap response".into()
            } else {
                "XML sitemap response".into()
            },
            description: if empty {
                format!(
                    "{document_label} was returned at {safe_url}, but it contains no direct {entry_label} entries. This check does not establish whether another sitemap is submitted privately or exists at an undisclosed path."
                )
            } else {
                match found.kind {
                    SitemapKind::Text => format!(
                        "{document_label} was returned at {safe_url} listing {} absolute {entry_label}s. This structural probe does not validate every target URL, search-console submission, or crawling/indexing.",
                        found.entry_count
                    ),
                    _ => format!(
                        "{document_label} was returned at {safe_url} with {} direct {entry_label} entries and a non-empty <loc> in each entry. This structural probe does not validate every target URL, XML Schema conformance, search-console submission, or crawling/indexing.",
                        found.entry_count
                    ),
                }
            },
            status: if empty {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if empty {
                Some("Confirm which sitemap URL is authoritative, then configure its generator to include the public canonical URLs that should be discoverable. Keep private, redirected, error, duplicate, and noindex URLs out; fetch the deployed XML again and validate representative entries before submitting it where useful.".into())
            } else {
                None
            },
            raw_data: Some(serde_json::json!({
                "url": safe_url,
                "root_element": found.kind.label(),
                "entries": found.entry_count,
                "structural_checks": match found.kind {
                    SitemapKind::Text => ["plain_text_format", "absolute_urls_only", "at_least_one_url"],
                    _ => ["well_formed_xml", "recognized_root", "direct_entries_have_nonempty_loc"],
                },
                "xsd_validated": false,
                "entry_urls_fetched": false,
                "search_console_submission_verified": false,
                "robots_declaration_count": declared_all.len(),
                "robots_declarations_evidence": safe_declared,
                "robots_declarations_evidence_truncated": declared_evidence_truncated,
            })),
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: if empty {
                Some("An empty sitemap supplies no URL-discovery information. Whether that matters depends on the site's size, internal linking, update pattern, and other discovery channels.".into())
            } else {
                None
            },
        }];
    }

    // Use the detected stack to make the fix instructions concrete.
    let stack_hint = detect_stack_hint(page);
    let framework_fix = framework_specific_sitemap_fix(stack_hint);

    let (probe_kind, observations) = match probe {
        SitemapProbe::Missing { observations } => ("missing", observations),
        SitemapProbe::Inconclusive { observations } => ("inconclusive", observations),
        SitemapProbe::Found(_) => unreachable!("found sitemap returned above"),
    };
    let inconclusive = probe_kind == "inconclusive";
    let has_unverified_declaration =
        has_cross_origin || invalid_declaration_count > 0 || same_origin_probe_truncated;
    let cross_origin_preview = evidence_preview(&safe_cross_origin, cross_origin_declared.len());

    let title = if inconclusive {
        "Sitemap probe did not complete"
    } else if has_cross_origin {
        "Cross-origin sitemap declaration not verified"
    } else if same_origin_probe_truncated {
        "Sitemap declaration sample incomplete"
    } else if invalid_declaration_count > 0 {
        "Sitemap declaration needs review"
    } else {
        "No usable sitemap found at tested locations"
    };
    let description = if inconclusive {
        format!(
            "The scanner could not reach a conclusive sitemap result because at least one candidate returned an access-limited, rate-limited, server-error, unreadable, or network-failure outcome. Tested {}.{}{}{} This does not prove that a sitemap is missing or broken.",
            safe_tested_urls.join(", "),
            if has_cross_origin { format!(" robots.txt also declares {} cross-origin sitemap candidate{} that SiteCMD did not request: {}.", cross_origin_declared.len(), if cross_origin_declared.len() == 1 { "" } else { "s" }, cross_origin_preview) } else { String::new() },
            if invalid_declaration_count > 0 { format!(" {} robots.txt Sitemap declaration{} not an absolute HTTP(S) URL and {} not requested.", invalid_declaration_count, if invalid_declaration_count == 1 { " is" } else { "s are" }, if invalid_declaration_count == 1 { "was" } else { "were" }) } else { String::new() },
            if same_origin_probe_truncated { format!(" Only the first {} same-origin robots.txt declarations were probed.", SITEMAP_DECLARATION_PROBE_LIMIT) } else { String::new() },
        )
    } else if has_cross_origin {
        format!(
            "robots.txt declares {} sitemap candidate{} on another origin: {}. SiteCMD deliberately did not request {}. The tested conventional and same-origin declared candidates did not yield a usable sitemap, but that is not evidence that {} absent or invalid.{}{}",
            cross_origin_declared.len(),
            if cross_origin_declared.len() == 1 { "" } else { "s" },
            cross_origin_preview,
            if cross_origin_declared.len() == 1 { "that host" } else { "those hosts" },
            if cross_origin_declared.len() == 1 { "the cross-origin sitemap is" } else { "the cross-origin sitemaps are" },
            if invalid_declaration_count > 0 { format!(" {} additional robots.txt declaration{} not an absolute HTTP(S) URL.", invalid_declaration_count, if invalid_declaration_count == 1 { " is" } else { "s are" }) } else { String::new() },
            if same_origin_probe_truncated { format!(" Only the first {} same-origin declarations were probed.", SITEMAP_DECLARATION_PROBE_LIMIT) } else { String::new() },
        )
    } else if same_origin_probe_truncated {
        format!(
            "robots.txt declares {} same-origin sitemap candidates. SiteCMD probed the first {} plus the conventional paths and found no usable sitemap; the remaining declared candidates were not requested, so this does not establish that every declaration is missing or invalid.{}",
            same_origin_declared.len(),
            SITEMAP_DECLARATION_PROBE_LIMIT,
            if invalid_declaration_count > 0 { format!(" {} additional declaration{} not an absolute HTTP(S) URL.", invalid_declaration_count, if invalid_declaration_count == 1 { " is" } else { "s are" }) } else { String::new() },
        )
    } else if invalid_declaration_count > 0 {
        format!(
            "robots.txt contains {} Sitemap declaration{} that {} not an absolute HTTP(S) URL, so {} not requested. No usable sitemap was found at the tested conventional or valid same-origin declared locations: {}. This does not rule out an undisclosed or privately submitted sitemap.",
            invalid_declaration_count,
            if invalid_declaration_count == 1 { "" } else { "s" },
            if invalid_declaration_count == 1 { "is" } else { "are" },
            if invalid_declaration_count == 1 { "it was" } else { "they were" },
            safe_tested_urls.join(", "),
        )
    } else {
        format!(
            "No well-formed <urlset> or <sitemapindex> with loc-bearing entries was found at the tested conventional paths or same-origin robots.txt declarations: {}. A sitemap may still exist at an undisclosed path, and not every small, well-linked site needs one.",
            safe_tested_urls.join(", ")
        )
    };
    let manual_fix = if inconclusive {
        "Repeat the listed requests as a logged-out public client and inspect the exact status, redirect, response body, CDN/WAF policy, and timeout. If an authoritative sitemap is already usable to supported crawlers, no generator change is needed; otherwise correct only the observed access or document problem and verify again."
            .to_string()
    } else if has_cross_origin {
        "Fetch each declared cross-origin URL from a public logged-out client, validate the returned sitemap/index and representative child entries, and check the search consoles the site uses. If it is valid and authoritative, no duplicate sitemap is needed. If the declaration is stale or the document is invalid, correct the robots.txt URL or its generator and re-verify."
            .to_string()
    } else if same_origin_probe_truncated {
        "Review why robots.txt contains more sitemap declarations than the bounded probe can request. Identify the authoritative sitemap or index, verify every untested declaration deliberately, and remove stale duplicates. Prefer one sitemap index when many child sitemaps are needed; re-fetch the final robots.txt and authoritative XML after deployment."
            .to_string()
    } else if invalid_declaration_count > 0 {
        "Inspect every Sitemap line in robots.txt and replace relative, malformed, or non-HTTP(S) values with the absolute public URL of an authoritative sitemap or sitemap index. Remove stale declarations, fetch the deployed URL logged out, validate representative entries, and avoid creating a sitemap solely to clear this advisory when the site does not need one."
            .to_string()
    } else {
        framework_fix
    };

    vec![CheckResult {
        check_id: "seo.sitemap".into(), category: ScanCategory::Seo,
        title: title.into(),
        description,
        // An inconclusive probe establishes nothing about the sitemap, so it
        // reports as skipped rather than as a warning the operator must clear.
        status: if inconclusive {
            CheckStatus::Skipped
        } else {
            CheckStatus::Warn
        },
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: Some(manual_fix),
        raw_data: Some(serde_json::json!({
            "tested_candidate_urls": safe_tested_urls,
            "robots_declared": safe_declared,
            "cross_origin_declared": safe_cross_origin,
            "robots_declaration_count": declared_all.len(),
            "invalid_declaration_count": invalid_declaration_count,
            "same_origin_declaration_count": same_origin_declared.len(),
            "same_origin_probe_limit": SITEMAP_DECLARATION_PROBE_LIMIT,
            "same_origin_probe_truncated": same_origin_probe_truncated,
            "declaration_evidence_truncated": declared_evidence_truncated,
            "cross_origin_evidence_truncated": cross_origin_evidence_truncated,
            "stack_hint": stack_hint,
            "probe_outcome": probe_kind,
            "observations": observations.iter().map(|observation| serde_json::json!({
                "url": crate::log_sanitizer::evidence_safe_page_url(&observation.url),
                "outcome": observation.outcome,
            })).collect::<Vec<_>>(),
        })),
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: Some(if inconclusive {
            "At least one candidate could not be classified as present or absent from this probe context; transient and crawler-specific responses remain possible."
        } else if has_cross_origin {
            "The declared cross-origin sitemap was intentionally not fetched, so its existence and validity are unknown."
        } else if same_origin_probe_truncated {
            "The bounded probe did not request every same-origin robots.txt declaration, so the untested candidates remain unknown."
        } else if invalid_declaration_count > 0 {
            "The invalid declaration syntax is directly observed, but an undisclosed or privately submitted sitemap and the site's need for one remain unknown."
        } else {
            "The tested locations had no usable sitemap, but an undisclosed path or private search-console submission is not observable and sitemap value depends on site structure."
        }.into()),
        why_it_matters: Some(if inconclusive || has_unverified_declaration {
            "Sitemap discovery cannot be assessed reliably until the declared or inconclusive response is verified in the site's real crawler context."
        } else {
            "A sitemap can improve discovery for large, new, frequently changing, or weakly linked sites. Its absence alone does not prove that any page is unindexed."
        }.into()),
    }]
}

#[cfg(test)]
#[path = "sitemap_tests.rs"]
mod tests;
