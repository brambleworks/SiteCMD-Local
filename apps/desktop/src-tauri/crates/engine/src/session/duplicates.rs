//! Pages that share a title, meta description, or H1 with another page.
//!
//! Split from `mod.rs` to keep both files inside the Rust
//! maintainability line budget; the grouping rules and the copy that explains
//! them are one subject and stay together here.

use super::compared::ComparedPages;
use super::{base_result, safe_page_url, truncate, SessionPage};
use crate::checks::{CheckResult, IssueConfidence, Severity};
use std::collections::{HashMap, HashSet};

/// Group pages by a normalized text field and report groups sharing a value.
///
/// An unknown page joins its value's group but is never kept. Two established
/// kept pages make a duplicate whatever unknown members say. Otherwise a
/// group with an unknown member declines when no other group is a duplicate.
/// This can decline a group that no unknown page could complete, or a group
/// that is duplicated in every reading because a known page canonicalizes
/// to an unknown member and different pages compete in its two readings.
///
/// A repeated value is only a defect between pages that both ask to be indexed
/// in their own right. A `noindex` page is not competing for the value, and a
/// page whose canonical points at another member of its own group has already
/// declared that member the representative, which is the intended pattern
/// rather than a duplicate.
pub(super) fn duplicate_field<'a>(
    pages: &[&'a SessionPage],
    compared: &ComparedPages<'_>,
    check_id: &str,
    label: &str,
    field: impl Fn(&'a SessionPage) -> Option<&'a str>,
) -> Vec<(CheckResult, Vec<String>)> {
    let mut groups: HashMap<String, Vec<&SessionPage>> = HashMap::new();
    let mut noindex_excluded = 0usize;
    for page in pages {
        if let Some(value) = field(page) {
            let key = value.trim().to_ascii_lowercase();
            // A replacement character means the decode dropped bytes, so two
            // values that read alike may not be alike; neither is compared.
            if key.is_empty() || key.contains('\u{FFFD}') {
                continue;
            }
            if page.noindex == Some(true) {
                noindex_excluded += 1;
                continue;
            }
            groups.entry(key).or_default().push(page);
        }
    }

    let mut canonicalized_excluded = 0usize;
    let mut undecided = false;
    let grouped: HashMap<String, Vec<&str>> = groups
        .into_iter()
        .map(|(key, members)| {
            let member_urls: HashSet<&str> = members.iter().map(|page| page.url.as_str()).collect();
            let kept: Vec<&str> = members
                .iter()
                .filter(|page| {
                    let canonicalized_to_a_sibling = page
                        .canonical
                        .as_deref()
                        .is_some_and(|target| target != page.url && member_urls.contains(target));
                    if canonicalized_to_a_sibling {
                        canonicalized_excluded += 1;
                    }
                    page.noindex.is_some() && !canonicalized_to_a_sibling
                })
                .map(|page| page.url.as_str())
                .collect();
            undecided |= kept.len() < 2
                && members.len() >= 2
                && members.iter().any(|page| page.noindex.is_none());
            (key, kept)
        })
        .collect();

    let mut duplicated: Vec<(&String, &Vec<&str>)> =
        grouped.iter().filter(|(_, urls)| urls.len() >= 2).collect();
    if duplicated.is_empty() {
        return if undecided {
            vec![(
                super::not_checked(
                    check_id,
                    format!("A page sharing its {label} with another compared page reached SiteCMD with its X-Robots-Tag lines combined, so whether it competes for that {label} could not be told."),
                ),
                Vec::new(),
            )]
        } else {
            Vec::new()
        };
    }
    duplicated.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));

    let total_pages: usize = duplicated.iter().map(|(_, urls)| urls.len()).sum();
    let preview = duplicated
        .iter()
        .take(3)
        .map(|(value, urls)| {
            format!(
                "\"{}\" ({} pages)",
                crate::log_sanitizer::redact_secrets(&truncate(value, 70)),
                urls.len()
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    let evidence_scope = if label == "H1 heading" {
        "first non-empty H1 text extracted from each initial HTML response"
    } else if label == "title" {
        "document-title text extracted from each initial HTML response"
    } else {
        "meta-description content extracted from each initial HTML response"
    };

    let mut result = base_result(
        check_id,
        format!("{} pages share the same {}", total_pages, label),
        format!(
            "{} of the {} compared pages share the same normalized {} with at least one other page: {}{}. The comparison uses the {}. Pages that declare noindex, and pages whose canonical points at another page in the same group, are left out of these groups.{} It does not establish that the pages have the same purpose, that the value is inappropriate, or that a search engine will select a particular snippet or page.",
            total_pages,
            compared.pages.len(),
            label,
            preview,
            if duplicated.len() > 3 {
                format!(" and {} more group(s)", duplicated.len() - 3)
            } else {
                String::new()
            },
            evidence_scope,
            compared.exclusion_note(),
        ),
    );
    result.severity = if check_id == "seo.duplicate_h1" {
        Severity::Low
    } else {
        Severity::Medium
    };
    result.confidence = IssueConfidence::NeedsReview;
    result.confidence_reason = Some(
        "The repeated text is directly observed within this scanned set, and pages that declare noindex or canonicalize to another page in their group were removed from it, but page intent, localization, pagination, rendered metadata, and search-engine selection were not evaluated."
            .into(),
    );
    result.manual_fix = Some(match label {
        "H1 heading" => "Review whether the surfaced pages have distinct primary topics. If they do, give each page a visible page-level heading that describes its own content; preserve a shared heading when the pages intentionally present the same topic or state. Check the rendered heading structure rather than changing text solely to make it unique.".into(),
        "title" => "First distinguish duplicate <title> elements on one page from one effective title repeated across scanned pages. Consolidate same-page declarations to one authoritative metadata source. For genuinely distinct indexable pages, give each an accurate page-specific title; preserve intentional repetition for equivalent, paginated, localized, or application states when that matches the content and canonical strategy.".into(),
        _ => "First distinguish duplicate meta-description elements on one page from one effective description repeated across scanned pages. Consolidate conflicting same-page declarations. For distinct indexable pages where a description is useful, write an accurate page-specific summary; search engines may still generate a different snippet from page content.".into(),
    });
    result.why_it_matters = Some(match label {
        "H1 heading" => "If pages have different primary topics, repeating the same visible page heading can make those pages harder for visitors and assistive-technology users to distinguish. Repetition is not automatically a defect.".into(),
        "title" => "If distinct pages use the same document title, browser tabs, bookmarks, assistive technology, and search-result candidates can be harder to distinguish; search engines may rewrite title links.".into(),
        _ => "If distinct pages use the same intended summary, their search-result candidates may be less differentiated; search engines can ignore or rewrite meta descriptions.".into(),
    });
    result.raw_data = Some(serde_json::json!({
        "groups": duplicated
            .iter()
            .take(10)
            .map(|(value, urls)| serde_json::json!({
                "value": crate::log_sanitizer::redact_secrets(&truncate(value, 200)),
                "pages": urls.iter().map(|url| safe_page_url(url)).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "group_count": duplicated.len(),
        "comparison_scope": evidence_scope,
        "rendered_dom_inspected": false,
        "canonical_relationships_considered": true,
        "noindex_pages_excluded": noindex_excluded,
        "pages_canonicalized_to_a_group_member_excluded": canonicalized_excluded,
        "pages_compared": compared.pages.len(),
        "selected_urls": compared.selected,
        "selected_urls_without_a_successful_response": compared.without_successful_response,
        "selected_urls_resolving_to_an_already_compared_page": compared.repeated_pages,
    }));
    let named = duplicated
        .iter()
        .flat_map(|(_, urls)| urls.iter().map(|url| url.to_string()))
        .collect();
    vec![(result, named)]
}
