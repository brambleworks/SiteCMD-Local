use std::collections::{BTreeSet, HashMap};

use crate::cli::export::labels::category_display_name;
use crate::core::scan_types::{actionable, Category, ScanResult};

pub(super) fn build_rules_md(result: &ScanResult) -> String {
    render_rules_md(
        &result.url,
        actionable(&result.issues).filter_map(|issue| {
            Some((
                issue.category?,
                issue.check_id.as_str(),
                issue.title.as_str(),
            ))
        }),
    )
}

pub(in crate::cli) fn render_rules_md<'a>(
    url: &str,
    findings: impl Iterator<Item = (Category, &'a str, &'a str)>,
) -> String {
    let all_categories = Category::ALL;

    let mut out = String::with_capacity(1024);

    out.push_str(&format!(
        "# SiteCMD Rules - {url}\n# Reference from CLAUDE.md: See .sitecmd/rules.md for Web Scan coding rules\n",
    ));

    let mut by_category = HashMap::<Category, BTreeSet<String>>::new();
    for (category, check_id, title) in findings {
        by_category
            .entry(category)
            .or_default()
            .insert(derive_rule(check_id, title));
    }
    for cat in &all_categories {
        let Some(rules) = by_category.get(cat) else {
            continue;
        };

        let cat_label = category_display_name(cat);
        out.push_str(&format!("\n## {}\n", cat_label));
        for rule in rules {
            out.push_str(&format!("- {}\n", rule));
        }
    }

    if out.lines().count() <= 2 {
        out.push_str("\n_No active rules - all checks passed._\n");
    }

    out
}

/// Map a check ID and title to an imperative coding rule.
fn derive_rule(check_id: &str, title: &str) -> String {
    // Well-known check ID -> rule mappings
    match check_id {
        "security.headers.csp" | "security_headers.csp" => {
            return "Create and tailor Content-Security-Policy to the resources and framing the product needs; test a report-only policy across real user flows before enforcing it".to_string();
        }
        "security.headers.hsts" | "security_headers.hsts" => {
            return "Use a staged HSTS rollout after HTTPS is reliable; increase max-age deliberately and add includeSubDomains only after every subdomain is audited".to_string();
        }
        "security.headers.x_frame_options" | "security_headers.x_frame_options" => {
            return "Define a CSP frame-ancestors policy that matches the product's embedding requirements; use X-Frame-Options as a legacy fallback when appropriate".to_string();
        }
        "security.headers.x_content_type_options" | "security_headers.x_content_type_options" => {
            return "Send X-Content-Type-Options: nosniff on browser-served responses and keep declared content types accurate".to_string();
        }
        "security.headers.referrer_policy" | "security_headers.referrer_policy" => {
            return "Set an explicit Referrer-Policy that matches the site's privacy and integration requirements".to_string();
        }
        "security.headers.permissions_policy" | "security_headers.permissions_policy" => {
            return "Use Permissions-Policy to disable browser capabilities the product does not need and allow required capabilities only to intended origins".to_string();
        }
        "seo.title" => {
            return "Give each indexable page a descriptive title; review rendered width and search intent instead of enforcing a fixed character count".to_string();
        }
        "seo.meta_description" => {
            return "Give important indexable pages a useful meta description, while allowing for query-dependent search snippets and search-engine rewrite behavior".to_string();
        }
        _ => {}
    }

    if check_id.contains("alt_text")
        || check_id.contains("image_alt")
        || check_id.contains("alt-text")
    {
        return "Give informative images an equivalent text alternative and decorative images an empty alt attribute".to_string();
    }
    if check_id.contains("label") && (check_id.contains("form") || check_id.contains("input")) {
        return "Give each applicable form control an accessible name, preferably through a visible associated label".to_string();
    }
    if check_id.contains("https") && !check_id.contains("hsts") {
        return "Serve public content over HTTPS and redirect HTTP to a configured canonical HTTPS destination".to_string();
    }
    if check_id.contains("canonical") {
        return "Use a consistent absolute canonical URL when duplicate or alternate URL variants need consolidation".to_string();
    }
    if check_id.contains("robots") {
        return "Review robots directives for accidental crawl blocks; remember that robots.txt controls crawling, not guaranteed deindexing".to_string();
    }
    if check_id.contains("sitemap") {
        return "For sites that benefit from discovery support, publish an accurate XML sitemap containing canonical indexable URLs".to_string();
    }
    if check_id.contains("viewport") {
        return "Configure the viewport for the intended responsive layout without disabling user zoom".to_string();
    }
    if check_id.contains("charset") || check_id.contains("encoding") {
        return "Declare UTF-8 early in the HTML head and serve a matching Content-Type charset"
            .to_string();
    }

    derive_rule_from_title(title)
}

/// Derive a generic rule from a check title when there's no specific mapping.
fn derive_rule_from_title(title: &str) -> String {
    // A title alone does not carry enough applicability context to safely turn
    // "Missing X" or "No X" into a universal coding standard. Preserve the
    // finding as a review instruction instead of inventing an absolute rule.
    format!("Review finding: {}", title)
}

#[cfg(test)]
mod tests {
    #[test]
    fn unknown_seo_ids_use_the_generic_rule() {
        // Fake SEO ids select specialized guidance despite having no registered check.
        for id in ["seo.meta.title", "seo.meta.description", "seo.description"] {
            assert_eq!(
                super::derive_rule(id, "Unknown check"),
                "Review finding: Unknown check"
            );
        }
        assert!(super::derive_rule("seo.title", "Title").starts_with("Give each indexable page"));
        assert!(super::derive_rule("seo.meta_description", "Description")
            .starts_with("Give important indexable pages"));
    }
}
