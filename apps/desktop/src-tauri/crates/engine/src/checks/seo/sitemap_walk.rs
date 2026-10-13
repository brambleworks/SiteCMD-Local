//! The bounded sitemap candidate walk every runtime drives: same-origin
//! `Sitemap:` declarations from robots.txt, at most
//! `SITEMAP_DECLARATION_PROBE_LIMIT`, then the conventional paths, once each;
//! the first well-formed document in that order wins. A runtime asks for the
//! request the walk names, hands back its answer, and walks again.

use crate::checks::seo::robots::RobotsTxtFetch;
use crate::checks::seo::sitemap::{
    parse_sitemap_document, sitemap_candidate_urls, sitemap_urls_from_robots, url_is_same_origin,
    SitemapFetch, SitemapParse, SitemapProbe, SitemapProbeObservation,
    SITEMAP_DECLARATION_PROBE_LIMIT,
};
use crate::probe::{BodyLimit, ProbeFailureClass, ProbeOutcome, ProbeRequest};

/// The most page URLs one sitemap read keeps for discovery and the cross-page comparison,
/// on every lane. A set cut here is partial, and says so.
pub const SITEMAP_URL_LIMIT: usize = 5000;

/// One candidate's request: a plain GET read under the sitemap cap.
///
/// Deliberately NOT the browser `Accept` the 404 probe sends: no evidence says
/// origins content-negotiate a sitemap, and asking for text/html first would
/// make an HTML shell the preferred representation of a document the parser
/// rejects, turning a found sitemap into a missing one.
pub fn sitemap_request(url: &str) -> ProbeRequest {
    ProbeRequest::get(url).limit(BodyLimit::Sitemap)
}

/// The candidates in walk order: the declarations robots.txt makes on this
/// origin, then the conventional paths, with no URL twice.
pub fn sitemap_candidates(origin: &str, robots: &RobotsTxtFetch) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let RobotsTxtFetch::Found { body } = robots {
        for url in sitemap_urls_from_robots(body)
            .into_iter()
            .filter(|url| url_is_same_origin(url, origin))
            .take(SITEMAP_DECLARATION_PROBE_LIMIT)
        {
            if !candidates.contains(&url) {
                candidates.push(url);
            }
        }
    }
    for url in sitemap_candidate_urls(origin) {
        if !candidates.contains(&url) {
            candidates.push(url);
        }
    }
    candidates
}

/// Walk the candidates over the answers in hand. `Err` is the request for the
/// first candidate with no answer yet; `Ok` is the walk's answer, which keeps
/// "nothing found" apart from "nothing answered", as the desktop's always did.
pub fn walk_sitemap_candidates<'a>(
    candidates: &[String],
    outcome_of: impl Fn(&ProbeRequest) -> Option<&'a ProbeOutcome>,
) -> Result<SitemapProbe, ProbeRequest> {
    let mut observations = Vec::with_capacity(candidates.len());
    let mut inconclusive = false;
    for url in candidates {
        let request = sitemap_request(url);
        let Some(outcome) = outcome_of(&request) else {
            return Err(request);
        };
        let safe_url = crate::log_sanitizer::evidence_safe_page_url(url);
        match classify(url, outcome) {
            Candidate::Found(fetch) => return Ok(SitemapProbe::Found(fetch)),
            Candidate::Missing(outcome) => observations.push(SitemapProbeObservation {
                url: safe_url,
                outcome,
            }),
            Candidate::Inconclusive(outcome) => {
                inconclusive = true;
                observations.push(SitemapProbeObservation {
                    url: safe_url,
                    outcome,
                });
            }
        }
    }
    Ok(if inconclusive {
        SitemapProbe::Inconclusive { observations }
    } else {
        SitemapProbe::Missing { observations }
    })
}

/// One candidate's answer, as the walk reads it.
enum Candidate {
    Found(SitemapFetch),
    /// Read in full and not a usable sitemap: a 404 or 410, or a body the
    /// grammar refuses. Says nothing about a sitemap elsewhere.
    Missing(String),
    /// No conclusive answer: the request failed, its body could not be read,
    /// or its status was neither a success nor a not-found.
    Inconclusive(String),
}

fn classify(url: &str, outcome: &ProbeOutcome) -> Candidate {
    let unread = || "response body could not be read within probe limits".to_string();
    let response = match outcome {
        ProbeOutcome::Failure(failure) if failure.class == ProbeFailureClass::BodyCapExceeded => {
            return Candidate::Inconclusive(unread())
        }
        ProbeOutcome::Failure(_) => return Candidate::Inconclusive("request failed".into()),
        ProbeOutcome::Response(response) => response,
    };
    if matches!(response.status, 404 | 410) {
        return Candidate::Missing(format!("HTTP {}", response.status));
    }
    if !(200..300).contains(&response.status) {
        return Candidate::Inconclusive(format!("HTTP {}", response.status));
    }
    let Some(body) = &response.body else {
        return Candidate::Inconclusive(unread());
    };
    match parse_sitemap_document(&body.text) {
        SitemapParse::WellFormed(document) => {
            Candidate::Found(SitemapFetch::new(url, body.text.clone(), &document))
        }
        // A document the grammar rejects is not a valid sitemap here even
        // when page discovery can still read locations out of it.
        SitemapParse::Salvaged { reason, .. } | SitemapParse::Unusable { reason } => {
            Candidate::Missing(format!("HTTP {} but {}", response.status, reason))
        }
    }
}

#[cfg(test)]
#[path = "sitemap_walk_tests.rs"]
mod tests;
