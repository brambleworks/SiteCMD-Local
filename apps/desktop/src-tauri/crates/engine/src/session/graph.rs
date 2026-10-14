use super::compared::ComparedPages;
use super::signals::{normalize_page_url, MAX_INTERNAL_LINKS_PER_PAGE};
use super::{base_result, safe_page_url, SessionPage, SessionSitemap, ORPHAN_MIN_PAGES};
use crate::checks::{CheckResult, IssueConfidence, Severity};
use std::collections::HashSet;

/// Pages in the scan set that no other scanned page links to.
pub(super) fn orphan_pages(
    pages: &[&SessionPage],
    compared: &ComparedPages<'_>,
) -> Vec<(CheckResult, Vec<String>)> {
    if pages.len() < ORPHAN_MIN_PAGES {
        return Vec::new();
    }
    // Without the entry page's own links the graph is missing the page most
    // others hang off, so an orphan list built from what is left would be
    // guesswork. `unreported_outcomes` reports that as Skipped with a reason.
    let Some(entry_page) = compared.entry_page else {
        return Vec::new();
    };

    // A page answers to every URL that reached it, not only the one it landed
    // on: a link written to a pre-redirect URL, or to the URL a second
    // selection used, is a real inbound link. The same aliases exclude a
    // page's link to itself.
    let mut linked: HashSet<&str> = HashSet::new();
    for page in pages {
        let own: HashSet<&str> = compared.aliases_of(page).collect();
        for link in &page.internal_links {
            if !own.contains(link.as_str()) {
                linked.insert(link.as_str());
            }
        }
    }

    // Nothing needs to link to the page the scan started from (usually the
    // homepage) for it to be reachable.
    let orphans: Vec<&str> = pages
        .iter()
        .filter(|p| p.url != entry_page)
        .filter(|p| !compared.aliases_of(p).any(|alias| linked.contains(alias)))
        .map(|p| p.url.as_str())
        .collect();

    if orphans.is_empty() {
        return Vec::new();
    }
    let safe_orphans: Vec<String> = orphans.iter().map(|url| safe_page_url(url)).collect();
    let links_truncated = pages.iter().any(|page| page.internal_links_truncated);

    let mut result = base_result(
        "seo.orphan_pages",
        format!(
            "{} page{} not linked from any other scanned page",
            orphans.len(),
            if orphans.len() == 1 { " is" } else { "s are" }
        ),
        format!(
            "In the bounded graph of {} compared pages, {} page{} received no link from an initial-HTML <a href> on another scanned page, at any of the URLs that reached it: {}{}. The scan entry page is excluded. This does not establish that a URL is unreachable: links may exist on unscanned pages, in a rendered or conditional state, through external sources, or beyond the per-page collection cap{}.{}",
            pages.len(),
            orphans.len(),
            if orphans.len() == 1 { "" } else { "s" },
            safe_orphans.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
            if orphans.len() > 5 {
                format!(" and {} more", orphans.len() - 5)
            } else {
                String::new()
            },
            if links_truncated { " on at least one page" } else { "" },
            compared.exclusion_note(),
        ),
    );
    result.severity = Severity::Low;
    result.confidence = IssueConfidence::NeedsReview;
    result.confidence_reason = Some(
        "Only initial-HTML anchor links between scanned pages were evaluated; rendered navigation, unscanned pages, external links, direct visits, authentication states, and any links beyond the collection cap remain outside this evidence.".into(),
    );
    result.manual_fix = Some(
        "Review each surfaced URL in the full production crawl and rendered navigation before changing it. If people and crawlers should discover the page through the site, add a useful crawlable link from a relevant page or shared navigation. If it is deliberately unlisted, confirm that its sitemap, canonical, noindex, access-control, campaign, and post-action behavior match that intent; sitemap inclusion and indexability are separate decisions.".into(),
    );
    result.why_it_matters = Some(
        "If a useful page truly has no crawlable path from the site's navigation graph, visitors and link-following crawlers may be less likely to discover it. This bounded scan does not prove that condition.".into(),
    );
    result.raw_data = Some(serde_json::json!({
        "pages_without_observed_inbound_link": safe_orphans,
        "scanned_pages": pages.len(),
        "scan_entry_excluded": true,
        "initial_html_anchor_links_only": true,
        "every_url_that_reached_a_page_counts_as_inbound": true,
        "same_site_scheme_and_www_twins_count_as_inbound": true,
        "rendered_dom_inspected": false,
        "unscanned_pages_inspected": false,
        "per_page_link_cap": MAX_INTERNAL_LINKS_PER_PAGE,
        "link_collection_truncated": links_truncated,
        "pages_compared": compared.pages.len(),
        "selected_urls": compared.selected,
        "selected_urls_without_a_successful_response": compared.without_successful_response,
        "selected_urls_resolving_to_an_already_compared_page": compared.repeated_pages,
    }));
    let named = orphans.iter().map(|url| url.to_string()).collect();
    vec![(result, named)]
}

/// Pages that are noindex AND listed in the sitemap: the sitemap invites
/// crawlers to a page that then tells them to go away.
pub(super) fn noindex_in_sitemap(
    pages: &[&SessionPage],
    compared: &ComparedPages<'_>,
    sitemap: SessionSitemap<'_>,
) -> Vec<(CheckResult, Vec<String>)> {
    let sitemap_set: HashSet<String> = sitemap.urls.iter().map(|u| normalize_page_url(u)).collect();

    let contradictions: Vec<&str> = pages
        .iter()
        .filter(|p| p.noindex == Some(true) && sitemap_set.contains(&p.url))
        .map(|p| p.url.as_str())
        .collect();

    if contradictions.is_empty() {
        // A listed page whose noindex is unknown may be the contradiction.
        let undecided = pages
            .iter()
            .any(|p| p.noindex.is_none() && sitemap_set.contains(&p.url));
        return if undecided {
            vec![(
                super::not_checked(
                    "seo.noindex_in_sitemap",
                    "A page listed in the sitemap reached SiteCMD with its X-Robots-Tag lines combined, so whether it is noindex could not be told.".into(),
                ),
                Vec::new(),
            )]
        } else {
            Vec::new()
        };
    }
    let safe_contradictions: Vec<String> = contradictions
        .iter()
        .map(|url| safe_page_url(url))
        .collect();
    let mut result = base_result(
        "seo.noindex_in_sitemap",
        format!(
            "{} noindex page{} listed in the sitemap",
            contradictions.len(),
            if contradictions.len() == 1 { " is" } else { "s are" }
        ),
        format!(
            "These scanned pages had a noindex directive in the initial HTML or final X-Robots-Tag response and also appeared in the supplied sitemap URL set: {}{}. That is a discovery/indexing contradiction whose intent needs review; it can reflect an accidental noindex, a stale sitemap, or a deliberate URL that remains discoverable for another reason.{}{}",
            safe_contradictions.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
            if contradictions.len() > 5 {
                format!(" and {} more", contradictions.len() - 5)
            } else {
                String::new()
            },
            match sitemap.partial_because {
                Some(reason) => format!(" SiteCMD read only part of this site's sitemap ({reason}), so there may be more."),
                None => String::new(),
            },
            compared.exclusion_note(),
        ),
    );
    result.confidence = IssueConfidence::NeedsReview;
    result.confidence_reason = Some(
        "The noindex and sitemap membership are directly observed for this scan, but URL intent, other sitemap sources, canonical selection, later response changes, and target-crawler processing were not evaluated."
            .into(),
    );
    result.manual_fix = Some(
        "Decide the intended state for each URL. If it should be eligible for indexing, remove every unintended noindex source and verify status, canonical, robots access, internal links, and rendered content. If exclusion is intentional, remove it from index-oriented sitemap output unless a documented consumer or workflow requires it there. Regenerate and fetch the deployed sitemap, then verify the final HTML and X-Robots-Tag response.".into(),
    );
    result.why_it_matters = Some(
        "A noindex URL in a sitemap sends inconsistent maintenance signals and may reveal either accidental exclusion or stale discovery data. It does not by itself prove crawl waste or a particular indexing outcome.".into(),
    );
    result.raw_data = Some(serde_json::json!({
        "pages": safe_contradictions,
        "noindex_sources_checked": ["initial_html_meta", "final_x_robots_tag"],
        "sitemap_url_set_supplied": true,
        "sitemap_url_set_complete": sitemap.partial_because.is_none(),
        "indexing_state_verified": false,
        "pages_compared": compared.pages.len(),
        "selected_urls": compared.selected,
        "selected_urls_without_a_successful_response": compared.without_successful_response,
        "selected_urls_resolving_to_an_already_compared_page": compared.repeated_pages,
    }));
    let named = contradictions.iter().map(|url| url.to_string()).collect();
    vec![(result, named)]
}
