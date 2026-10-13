use super::compared::ComparedPages;
use super::{base_result, safe_page_url, SessionPage};
use crate::checks::{CheckResult, IssueConfidence, Severity};
use std::collections::HashMap;

/// hreflang declarations between scanned pages that are not reciprocated.
pub(super) fn hreflang_reciprocity(
    pages: &[&SessionPage],
    compared: &ComparedPages<'_>,
) -> Vec<(CheckResult, Vec<String>)> {
    if compared.hreflang_truncated {
        return Vec::new();
    }
    let by_url: HashMap<&str, &SessionPage> = pages.iter().map(|p| (p.url.as_str(), *p)).collect();

    let mut missing: Vec<String> = Vec::new();
    let mut named = Vec::new();
    for page in pages {
        for target_url in &page.hreflang {
            if target_url == &page.url {
                continue;
            }
            // Only pairs where the target was scanned are verifiable.
            let Some(target) = by_url.get(target_url.as_str()) else {
                continue;
            };
            let reciprocated = target.hreflang.iter().any(|href| href == &page.url);
            if !reciprocated {
                named.extend([page.url.clone(), target_url.clone()]);
                missing.push(format!(
                    "{} -> {}",
                    safe_page_url(&page.url),
                    safe_page_url(target_url)
                ));
            }
        }
    }

    if missing.is_empty() {
        return Vec::new();
    }

    let mut result = base_result(
        "seo.hreflang_reciprocity",
        format!(
            "{} hreflang link{} not reciprocated",
            missing.len(),
            if missing.len() == 1 { " is" } else { "s are" }
        ),
        format!(
            "These scanned pages contain an initial-HTML hreflang alternate whose scanned target has no parsed initial-HTML annotation back to the source URL: {}{}. Google Search documents return links for hreflang pairs and may ignore a non-returning annotation. Other consumers and annotations delivered through HTTP headers or sitemaps were not evaluated; only pairs whose targets were also scanned were checked.{}",
            missing.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
            if missing.len() > 5 {
                format!(" and {} more", missing.len() - 5)
            } else {
                String::new()
            },
            compared.exclusion_note(),
        ),
    );
    result.severity = Severity::Low;
    result.confidence = IssueConfidence::NeedsReview;
    result.confidence_reason = Some(
        "The missing return link is direct evidence in the parsed initial HTML of two scanned pages, but HTTP-header/sitemap annotations, target equivalence, language-code meaning, canonicals, and consumer processing were not evaluated."
            .into(),
    );
    result.manual_fix = Some(
        "Confirm that the source and target are localized equivalents. For each intended pair, emit a return annotation and a language-specific self-reference through one consistently managed channel (HTML, HTTP headers, or sitemap), using supported language/region values and fully qualified canonical final URLs. Generate the mapping from one locale source of truth, then verify both deployed responses and the target consumer's current requirements.".into(),
    );
    result.why_it_matters = Some(
        "A consumer that requires reciprocal alternate relationships may ignore a one-directional annotation, reducing the usefulness of the intended language/region mapping. This scan does not establish which version users are shown.".into(),
    );
    result.raw_data = Some(serde_json::json!({
        "missing_return_links": missing,
        "annotation_source": "initial_html_link",
        "only_scanned_targets_checked": true,
        "http_header_annotations_inspected": false,
        "sitemap_annotations_inspected": false,
        "target_equivalence_verified": false,
    }));
    vec![(result, named)]
}
