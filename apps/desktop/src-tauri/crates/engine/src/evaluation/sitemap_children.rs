//! An index sitemap's children, for a route session whose runtime names a
//! limit: the children on the page's own origin, in the index's order, at most
//! that limit, each read under the sitemap cap. A child's answer is read as it
//! is recorded and handed back without its body, so a route keeps the index
//! and the page addresses its children list within the evidence bound, never
//! a child's document. A session that names no limit, as the desktop's and
//! every corpus case that names none do, reads no children.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::probes::{probe_key, ExecutedProbe};
use crate::checks::seo::sitemap::{parse_sitemap_document, url_is_same_origin, SitemapFetch};
use crate::checks::seo::sitemap_walk::{sitemap_child_request, SITEMAP_URL_LIMIT};
use crate::log_sanitizer::ISSUE_EVIDENCE_URL_MAX_CHARS;
use crate::probe::{ProbeOutcome, ProbeRequest};

/// The index's children as the walk found it.
struct Children {
    /// How many children the index lists, on any origin.
    listed: usize,
    /// The children asked for: the first `limit` distinct addresses on the
    /// page's origin, in index order, each with its address and answer key.
    asked: Vec<(String, String)>,
    /// Asked slots before the first unasked child, with repeats using their first slot.
    prefix_slots: Vec<usize>,
}

/// The children one route reads, and their page addresses within the evidence bound.
#[derive(Default)]
pub struct ChildSitemaps {
    limit: usize,
    children: OnceLock<Children>,
    /// Each asked child's answer by its slot in `asked`: read (`true`), or
    /// answered with nothing conclusive (`false`).
    answers: HashMap<usize, bool>,
    pages: Vec<String>,
    /// A child's pages within the evidence bound were cut at the walk's URL limit.
    cut: bool,
}

/// What an index's children gave a route.
pub(crate) struct ChildPages<'a> {
    /// How many children the index lists.
    pub(crate) listed: usize,
    /// How many were read, counted in the index's order up to the first that
    /// was not, so "SiteCMD read the first N" stays true.
    pub(crate) read: usize,
    /// Their page addresses within `ISSUE_EVIDENCE_URL_MAX_CHARS`, in read order.
    pub(crate) pages: &'a [String],
    /// The pages reached the walk's URL limit: a child's were cut there, or
    /// an asked child was left unread when it was reached.
    pub(crate) url_limited: bool,
    /// Every asked child answered conclusively, except those the URL limit left
    /// unread, so the pages miss nothing but what the URL limit cut.
    pub(crate) complete: bool,
}

impl ChildSitemaps {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Whether its runtime named a nonzero child limit.
    pub(crate) fn names_limit(&self) -> bool {
        self.limit != 0
    }

    /// The index's children, read from the index the first time it is seen.
    fn children(&self, index: &SitemapFetch, origin: &str) -> &Children {
        self.children.get_or_init(|| {
            let parsed = parse_sitemap_document(&index.body);
            let mut asked: Vec<(String, String)> = Vec::new();
            for url in parsed.locs() {
                if asked.len() == self.limit {
                    break;
                }
                if url_is_same_origin(url, origin) && asked.iter().all(|(seen, _)| seen != url) {
                    asked.push((url.clone(), probe_key(&sitemap_child_request(url))));
                }
            }
            let prefix_slots = {
                let slots_by_url: HashMap<_, _> = asked
                    .iter()
                    .enumerate()
                    .map(|(slot, (url, _))| (url.as_str(), slot))
                    .collect();
                parsed
                    .locs()
                    .iter()
                    .map_while(|url| slots_by_url.get(url.as_str()).copied())
                    .collect()
            };
            Children {
                listed: parsed.locs().len(),
                asked,
                prefix_slots,
            }
        })
    }

    /// Whether the route has seen its index yet.
    pub(crate) fn knows_index(&self) -> bool {
        self.children.get().is_some()
    }

    /// Note the index the walk found, so the answers recorded after it can be
    /// matched to the children it lists.
    pub(crate) fn learn_index(&self, index: &SitemapFetch, origin: &str) {
        self.children(index, origin);
    }

    /// The children to request: none for a limit of zero, none once their
    /// pages reach the walk's URL limit.
    pub(crate) fn wanted(&self, index: &SitemapFetch, origin: &str) -> Vec<ProbeRequest> {
        if self.pages.len() >= SITEMAP_URL_LIMIT {
            return Vec::new();
        }
        self.children(index, origin)
            .asked
            .iter()
            .map(|(url, _)| sitemap_child_request(url))
            .collect()
    }

    /// Read one child's answer, when it is one this route asked for, and hand
    /// it back without its body: the route keeps page addresses within the evidence
    /// bound, never its document. The first answer for a child is the one read.
    pub(crate) fn absorb(&mut self, mut child: ExecutedProbe) -> ExecutedProbe {
        let slot = self
            .children
            .get()
            .and_then(|children| children.asked.iter().position(|(_, key)| *key == child.key));
        if let Some(slot) = slot {
            if !self.answers.contains_key(&slot) {
                let read = self.read(&child.outcome);
                self.answers.insert(slot, read);
            }
        }
        if let ProbeOutcome::Response(response) = &mut child.outcome {
            response.body = None;
        }
        child
    }

    /// One child's answer, read as the walk reads a candidate's: a 404 or 410
    /// is read and lists no pages, any other answer but a success is not
    /// read, and a success keeps its bounded locations unless it is an index,
    /// whose children are not read. A document the strict grammar refuses
    /// still gives the locations it holds, as the desktop's reading of an
    /// index's children does. Invalid UTF-8 leaves the child unread.
    fn read(&mut self, outcome: &ProbeOutcome) -> bool {
        let ProbeOutcome::Response(response) = outcome else {
            return false;
        };
        if matches!(response.status, 404 | 410) {
            return true;
        }
        let Some(body) = response
            .body
            .as_ref()
            .filter(|_| (200..300).contains(&response.status))
        else {
            return false;
        };
        if !body.utf8_valid {
            return false;
        }
        let parsed = parse_sitemap_document(&body.text);
        if !parsed.lists_child_sitemaps() {
            let room = SITEMAP_URL_LIMIT.saturating_sub(self.pages.len());
            let mut kept = parsed.locs().iter().filter(|loc| {
                loc.chars().take(ISSUE_EVIDENCE_URL_MAX_CHARS + 1).count()
                    <= ISSUE_EVIDENCE_URL_MAX_CHARS
            });
            self.pages.extend(kept.by_ref().take(room).cloned());
            self.cut |= kept.next().is_some();
        }
        true
    }

    /// What the index's children gave.
    pub(crate) fn pages(&self, index: &SitemapFetch, origin: &str) -> ChildPages<'_> {
        let children = self.children(index, origin);
        let read = children
            .prefix_slots
            .iter()
            .take_while(|slot| self.answers.get(slot) == Some(&true))
            .count();
        let full = self.pages.len() >= SITEMAP_URL_LIMIT;
        let unanswered = (0..children.asked.len()).any(|slot| !self.answers.contains_key(&slot));
        ChildPages {
            listed: children.listed,
            read,
            pages: &self.pages,
            url_limited: self.cut || (full && unanswered),
            complete: !self.answers.values().any(|read| !read) && (full || !unanswered),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChildSitemaps;
    use crate::checks::seo::sitemap::{parse_sitemap_document, SitemapFetch, SitemapParse};
    use crate::checks::seo::sitemap_walk::sitemap_child_request;
    use crate::evaluation::{probe_key, ExecutedProbe};
    use crate::probe::{decode_probe_body, ProbeOutcome, ProbeResponse};

    #[test]
    fn a_childs_answer_is_kept_as_its_pages_and_never_its_body() {
        let body = "<?xml version='1.0'?><sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'><sitemap><loc>https://example.com/posts.xml</loc></sitemap></sitemapindex>";
        let SitemapParse::WellFormed(document) = parse_sitemap_document(body) else {
            panic!("the index parses");
        };
        let index = SitemapFetch::new("https://example.com/sitemap.xml", body, &document);
        let mut children = ChildSitemaps::new(50);
        children.learn_index(&index, "https://example.com");
        let child = "<?xml version='1.0'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'><url><loc>https://example.com/listed</loc></url></urlset>";
        let kept = children.absorb(ExecutedProbe::new(
            probe_key(&sitemap_child_request("https://example.com/posts.xml")),
            ProbeOutcome::Response(ProbeResponse {
                status: 200,
                final_url: "https://example.com/posts.xml".into(),
                content_type: Some("application/xml".into()),
                content_length: None,
                headers: Vec::new(),
                body: Some(decode_probe_body(child.as_bytes().to_vec())),
            }),
        ));
        let ProbeOutcome::Response(response) = kept.outcome else {
            panic!("a response");
        };
        assert!(response.body.is_none());
        let read = children.pages(&index, "https://example.com");
        assert_eq!(read.pages, ["https://example.com/listed"]);
        assert!(read.complete);
    }

    #[test]
    fn a_childs_first_failed_answer_is_not_replaced_by_a_success() {
        // Reading a later success must not replace the child's first failure.
        let body = "<?xml version='1.0'?><sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'><sitemap><loc>https://example.com/posts.xml</loc></sitemap></sitemapindex>";
        let SitemapParse::WellFormed(document) = parse_sitemap_document(body) else {
            panic!("the index parses");
        };
        let index = SitemapFetch::new("https://example.com/sitemap.xml", body, &document);
        let mut children = ChildSitemaps::new(50);
        children.learn_index(&index, "https://example.com");
        let child = "<urlset><url><loc>https://example.com/listed</loc></url></urlset>";
        for (status, body) in [(503, None), (200, Some(child))] {
            children.absorb(ExecutedProbe::new(
                probe_key(&sitemap_child_request("https://example.com/posts.xml")),
                ProbeOutcome::Response(ProbeResponse {
                    status,
                    final_url: "https://example.com/posts.xml".into(),
                    content_type: Some("application/xml".into()),
                    content_length: None,
                    headers: Vec::new(),
                    body: body.map(|text| decode_probe_body(text.as_bytes().to_vec())),
                }),
            ));
        }
        let read = children.pages(&index, "https://example.com");
        assert!(read.pages.is_empty());
        assert_eq!(read.read, 0);
    }
}
