use super::compared::ComparedPages;
use super::{base_result, safe_page_url, SessionPage};
use crate::checks::{CheckResult, CheckStatus, IssueConfidence};
use std::collections::{HashMap, HashSet};

/// Canonical relationships that loop or chain between scanned pages.
pub(super) fn canonical_loops(
    pages: &[&SessionPage],
    compared: &ComparedPages<'_>,
) -> Vec<(CheckResult, Vec<String>)> {
    let canon: HashMap<&str, &str> = pages
        .iter()
        .filter_map(|p| {
            p.canonical
                .as_deref()
                .filter(|c| *c != p.url)
                .map(|c| (p.url.as_str(), c))
        })
        .collect();

    if canon.is_empty() {
        return Vec::new();
    }

    // Find cycles of any length. Canonicalize each cycle by rotating it to
    // its lexicographically smallest URL so walking from every member still
    // emits one piece of evidence.
    let mut loop_keys = std::collections::BTreeSet::new();
    for start in canon.keys().copied() {
        let mut positions: HashMap<&str, usize> = HashMap::new();
        let mut path: Vec<&str> = Vec::new();
        let mut current = start;
        loop {
            if let Some(position) = positions.get(current).copied() {
                let cycle = &path[position..];
                if !cycle.is_empty() {
                    let minimum = cycle
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, url)| *url)
                        .map(|(index, _)| index)
                        .unwrap_or(0);
                    let rotated = cycle[minimum..]
                        .iter()
                        .chain(cycle[..minimum].iter())
                        .copied()
                        .collect::<Vec<_>>();
                    loop_keys.insert(rotated.join("\u{0}"));
                }
                break;
            }
            positions.insert(current, path.len());
            path.push(current);
            let Some(next) = canon.get(current).copied() else {
                break;
            };
            current = next;
        }
    }
    let mut named: Vec<String> = loop_keys
        .iter()
        .flat_map(|key| key.split('\0').map(str::to_string))
        .collect();
    let loops: Vec<String> = loop_keys
        .iter()
        .map(|key| {
            let nodes = key.split('\0').collect::<Vec<_>>();
            nodes
                .iter()
                .chain(nodes.first())
                .map(|url| safe_page_url(url))
                .collect::<Vec<_>>()
                .join(" -> ")
        })
        .collect();

    // Report maximal indirect chains from graph roots. A direct A -> B
    // canonical is not a chain; A -> B -> C is.
    let incoming: HashSet<&str> = canon.values().copied().collect();
    let mut chains = Vec::new();
    for start in canon
        .keys()
        .copied()
        .filter(|candidate| !incoming.contains(candidate))
    {
        let mut seen = HashSet::new();
        let mut path = vec![start];
        let mut current = start;
        seen.insert(start);
        while let Some(next) = canon.get(current).copied() {
            path.push(next);
            if !seen.insert(next) {
                break;
            }
            current = next;
        }
        if path.len() >= 3 {
            named.extend(path.iter().map(|url| url.to_string()));
            chains.push(
                path.iter()
                    .map(|url| safe_page_url(url))
                    .collect::<Vec<_>>()
                    .join(" -> "),
            );
        }
    }
    chains.sort();

    if loops.is_empty() && chains.is_empty() {
        return Vec::new();
    }

    let has_loop = !loops.is_empty();
    let mut findings = Vec::new();
    if !loops.is_empty() {
        findings.push(format!("canonical loops: {}", loops.join("; ")));
    }
    if !chains.is_empty() {
        findings.push(format!(
            "canonical chains: {}",
            chains
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }

    let mut result = base_result(
        "seo.canonical_loop",
        if has_loop {
            "Initial-HTML canonical cycle observed".into()
        } else {
            "Indirect initial-HTML canonical chain observed".into()
        },
        format!(
            "The first parsed initial-HTML canonical on the scanned pages forms {}. A cycle has no terminal target within the observed set; an indirect chain can still settle on a final target but asks a consumer to follow more than one canonical relationship. This analysis did not inspect HTTP Link headers, duplicate canonical declarations, target status/indexability, content equivalence, or canonical selection by a search engine.{}",
            findings.join(". "),
            compared.exclusion_note(),
        ),
    );
    result.status = if has_loop {
        CheckStatus::Fail
    } else {
        CheckStatus::Warn
    };
    result.confidence = IssueConfidence::NeedsReview;
    result.confidence_reason = Some(
        "The initial-HTML relationships are directly observed, but alternate canonical sources, target responses, page equivalence, and search-engine canonical selection were not evaluated."
            .into(),
    );
    result.manual_fix = Some(
        "First confirm that the URLs are duplicate or near-duplicate representations and choose the representative that should carry their signals. Point each duplicate directly to that crawlable final representative, align redirects/internal links/sitemaps/hreflang, and give a standalone representative a coherent self-canonical where appropriate. Inspect both rendered HTML and HTTP Link headers, then verify final statuses, indexability, content equivalence, and the deployed relationship graph.".into(),
    );
    result.why_it_matters = Some(if has_loop {
        "A canonical cycle gives no consistent terminal representative in the observed HTML relationship graph. Consumers treat canonical annotations as hints and may choose a different representative.".into()
    } else {
        "An indirect canonical chain can weaken the clarity of the intended representative and is easier for templates, redirects, and sitemap signals to contradict. It does not prove an indexing failure.".into()
    });
    result.raw_data = Some(serde_json::json!({
        "loops": loops,
        "chains": chains,
        "canonical_source": "first_initial_html_link",
        "http_link_headers_inspected": false,
        "duplicate_canonical_declarations_inspected": false,
        "target_responses_inspected": false,
        "content_equivalence_verified": false,
    }));
    vec![(result, named)]
}
