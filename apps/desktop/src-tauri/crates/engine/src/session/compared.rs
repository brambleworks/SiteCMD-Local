use super::SessionPage;
use std::collections::{HashMap, HashSet};

/// The pages a cross-page comparison may actually use, and what was left out.
///
/// Two selected URLs can land on one page (a trailing-slash twin, or a stale
/// sitemap entry that now redirects), and a dead URL still returns a body. A
/// comparison that counted either would report a page as its own duplicate or
/// grade a site's error template instead of its pages.
pub(super) struct ComparedPages<'a> {
    pub(super) pages: Vec<&'a SessionPage>,
    pub(super) positions: Vec<usize>,
    pub(super) hreflang_truncated: bool,
    /// Every URL the scan asked for that landed on a given compared page,
    /// keyed by that page's effective URL and always including it. Dropping a
    /// repeated selection must not drop the URL it was reached through, or a
    /// page linked only through that URL becomes a false orphan.
    pub(super) aliases: HashMap<&'a str, HashSet<&'a str>>,
    /// The compared page the scan started from, when it was comparable. Orphan
    /// analysis exempts it, and cannot run honestly without it.
    pub(super) entry_page: Option<&'a str>,
    pub(super) selected: usize,
    pub(super) without_successful_response: usize,
    pub(super) repeated_pages: usize,
}

impl<'a> ComparedPages<'a> {
    pub(super) fn from_pages(pages: &'a [SessionPage]) -> Self {
        let mut compared: Vec<&SessionPage> = Vec::new();
        let mut aliases: HashMap<&str, HashSet<&str>> = HashMap::new();
        let mut entry_page = None;
        let mut positions = Vec::new();
        let mut without_successful_response = 0;
        let mut repeated_pages = 0;
        for (position, page) in pages.iter().enumerate() {
            // A page that never answered at all contributes no signals to this
            // analysis, so only a response that is not a page reaches here: an
            // error body, or a redirect that never resolved to a document.
            if !(200..300).contains(&page.status_code) {
                without_successful_response += 1;
                continue;
            }
            // `SessionPage.url` is normalized once, at extraction, so it is
            // already the cross-page identity.
            let known = aliases.entry(page.url.as_str()).or_default();
            let first_selection = known.is_empty();
            known.insert(page.url.as_str());
            known.insert(page.requested_url.as_str());
            if !first_selection {
                repeated_pages += 1;
                continue;
            }
            if position == 0 {
                entry_page = Some(page.url.as_str());
            }
            compared.push(page);
            positions.push(position);
        }
        Self {
            hreflang_truncated: compared.iter().any(|page| page.hreflang_truncated),
            pages: compared,
            positions,
            aliases,
            entry_page,
            selected: pages.len(),
            without_successful_response,
            repeated_pages,
        }
    }

    /// The input positions of the compared pages among `urls`, ascending and
    /// once each. An address no compared page has, such as a canonical
    /// target outside the scan, names no page.
    pub(super) fn positions_of(&self, urls: &[String]) -> Vec<usize> {
        let mut named: Vec<usize> = self
            .pages
            .iter()
            .zip(&self.positions)
            .filter(|(page, _)| urls.contains(&page.url))
            .map(|(_, position)| *position)
            .collect();
        named.sort_unstable();
        named
    }

    /// Every URL a compared page answers to: the one it landed on plus every
    /// selected URL that reached it.
    pub(super) fn aliases_of(&self, page: &SessionPage) -> impl Iterator<Item = &str> {
        self.aliases
            .get(page.url.as_str())
            .into_iter()
            .flat_map(|urls| urls.iter().copied())
    }

    /// How the outcome copy names what was actually compared.
    pub(super) fn compared_phrase(&self) -> String {
        if self.excluded() == 0 {
            format!("all {} scanned pages", self.pages.len())
        } else {
            format!(
                "{} of the {} selected URLs",
                self.pages.len(),
                self.selected
            )
        }
    }

    pub(super) fn excluded(&self) -> usize {
        self.without_successful_response + self.repeated_pages
    }

    /// The sentence appended to every session outcome when the compared set is
    /// smaller than the selected set. Empty when nothing was left out.
    pub(super) fn exclusion_note(&self) -> String {
        let mut reasons = Vec::new();
        if self.without_successful_response > 0 {
            reasons.push(format!(
                "{} with no successful page response",
                self.without_successful_response
            ));
        }
        if self.repeated_pages > 0 {
            reasons.push(format!(
                "{} that resolved to a page already compared",
                self.repeated_pages
            ));
        }
        if reasons.is_empty() {
            return String::new();
        }
        format!(" Not compared: {}.", reasons.join(" and "))
    }
}
