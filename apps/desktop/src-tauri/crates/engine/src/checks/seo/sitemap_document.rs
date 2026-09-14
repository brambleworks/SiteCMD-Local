//! Shared sitemap candidates, robots.txt declarations, and document parsing.
//!
//! Discovery may use URLs from [`SitemapParse::Salvaged`], while the validity
//! check still reports that document as malformed.

/// Conventional sitemap paths in preferred probe order.
pub const SITEMAP_CANDIDATE_PATHS: [&str; 6] = [
    "/sitemap.xml",
    "/sitemap-index.xml",
    "/sitemap_index.xml",
    // WordPress 5.5+ serves its built-in sitemap here, not at /sitemap.xml.
    "/wp-sitemap.xml",
    // Older CMS plugins generate through a script path.
    "/sitemap.php",
    // The sitemaps.org plain-text format: one URL per line.
    "/sitemap.txt",
];

/// The conventional sitemap candidate URLs for an origin, in probe order.
pub fn sitemap_candidate_urls(base: &str) -> Vec<String> {
    let base = base.trim_end_matches('/');
    SITEMAP_CANDIDATE_PATHS
        .iter()
        .map(|path| format!("{base}{path}"))
        .collect()
}

/// Parse `Sitemap:` directives; callers enforce origin and network policy.
pub fn sitemap_urls_from_robots(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            if line
                .get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sitemap:"))
            {
                let url = line[8..].trim();
                if !url.is_empty() {
                    return Some(url.to_string());
                }
            }
            None
        })
        .collect()
}

/// Which sitemap format a document turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitemapKind {
    /// `<urlset>`: the entries are page URLs.
    UrlSet,
    /// `<sitemapindex>`: the entries are child sitemaps to fetch.
    SitemapIndex,
    /// The sitemaps.org plain-text format: the lines are page URLs.
    Text,
}

impl SitemapKind {
    /// How the format is named in evidence and copy.
    pub fn label(self) -> &'static str {
        match self {
            Self::UrlSet => "urlset",
            Self::SitemapIndex => "sitemapindex",
            Self::Text => "text",
        }
    }

    /// Whether entries are child sitemaps rather than pages.
    pub fn lists_child_sitemaps(self) -> bool {
        matches!(self, Self::SitemapIndex)
    }

    /// What one entry is called in user-facing copy.
    pub fn entry_label(self) -> &'static str {
        if self.lists_child_sitemaps() {
            "child-sitemap"
        } else {
            "URL"
        }
    }
}

/// A sitemap document that satisfied the strict grammar.
#[derive(Debug, Clone)]
pub struct SitemapDocument {
    pub kind: SitemapKind,
    /// Every direct entry's location, in document order.
    pub locs: Vec<String>,
}

/// The outcome of reading one sitemap response body.
#[derive(Debug, Clone)]
pub enum SitemapParse {
    /// Well-formed: the document is a valid sitemap of its kind.
    WellFormed(SitemapDocument),
    /// Invalid document with readable locations retained for discovery.
    /// `kind` keeps sitemap indexes distinct from page-url sets.
    Salvaged {
        reason: &'static str,
        kind: Option<SitemapKind>,
        locs: Vec<String>,
    },
    /// Nothing usable: not a sitemap, or too broken to read locations from.
    Unusable { reason: &'static str },
}

impl SitemapParse {
    /// The locations this response yields, whatever its condition. Empty for
    /// an unusable response.
    pub fn locs(&self) -> &[String] {
        match self {
            Self::WellFormed(document) => &document.locs,
            Self::Salvaged { locs, .. } => locs,
            Self::Unusable { .. } => &[],
        }
    }

    /// Whether the locations are child sitemaps rather than pages. A document
    /// too broken to parse still declares its root, so this stays answerable.
    pub fn lists_child_sitemaps(&self) -> bool {
        match self {
            Self::WellFormed(document) => document.kind.lists_child_sitemaps(),
            Self::Salvaged { kind, .. } => kind.is_some_and(SitemapKind::lists_child_sitemaps),
            Self::Unusable { .. } => false,
        }
    }
}

/// Parse plain-text or XML sitemaps, salvaging recoverable `<loc>` values.
pub fn parse_sitemap_document(body: &str) -> SitemapParse {
    if !body.contains('<') {
        return match text_sitemap_locs(body) {
            Some(locs) => SitemapParse::WellFormed(SitemapDocument {
                kind: SitemapKind::Text,
                locs,
            }),
            None => SitemapParse::Unusable {
                reason: "the response is neither sitemap XML nor a plain-text URL list",
            },
        };
    }

    match parse_sitemap_xml(body) {
        Ok(document) => SitemapParse::WellFormed(document),
        Err(reason) => {
            let locs = salvage_locs(body);
            if locs.is_empty() {
                SitemapParse::Unusable { reason }
            } else {
                SitemapParse::Salvaged {
                    reason,
                    kind: declared_root_kind(body),
                    locs,
                }
            }
        }
    }
}

/// Summarize a well-formed sitemap root and its direct entries.
pub fn sitemap_document_summary(body: &str) -> Result<(&'static str, usize), &'static str> {
    match parse_sitemap_document(body) {
        SitemapParse::WellFormed(document) => Ok((document.kind.label(), document.locs.len())),
        SitemapParse::Salvaged { reason, .. } | SitemapParse::Unusable { reason } => Err(reason),
    }
}

/// The sitemaps.org text format: one absolute URL per line, blank lines
/// ignored. Returns None when no line carries a URL, so an arbitrary text
/// response is not mistaken for an empty sitemap.
fn text_sitemap_locs(body: &str) -> Option<Vec<String>> {
    let locs: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("http://") || line.starts_with("https://"))
        .map(str::to_string)
        .collect();
    (!locs.is_empty()).then_some(locs)
}

/// The root element a broken document claims, read as a token rather than
/// parsed. Only the two sitemap roots count; anything else (an HTML error
/// page, say) declares nothing.
fn declared_root_kind(body: &str) -> Option<SitemapKind> {
    let lower = body.to_ascii_lowercase();
    let index = lower.find("<sitemapindex");
    let urlset = lower.find("<urlset");
    match (index, urlset) {
        (Some(index_at), Some(urlset_at)) if urlset_at < index_at => Some(SitemapKind::UrlSet),
        (Some(_), _) => Some(SitemapKind::SitemapIndex),
        (None, Some(_)) => Some(SitemapKind::UrlSet),
        (None, None) => None,
    }
}

/// Recover `<loc>` values from a document the grammar rejected. Deliberately
/// lenient: this exists so a malformed sitemap still lists pages for
/// discovery, never to soften a validity verdict.
fn salvage_locs(body: &str) -> Vec<String> {
    let mut locs = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<loc>") {
        rest = &rest[start + "<loc>".len()..];
        let Some(end) = rest.find("</loc>") else {
            break;
        };
        let loc = rest[..end].trim();
        if !loc.is_empty() {
            locs.push(loc.to_string());
        }
        rest = &rest[end + "</loc>".len()..];
    }
    locs
}

/// Assemble a `<loc>` value split across text and entity-reference events.
#[derive(Default)]
struct LocText {
    value: String,
}

impl LocText {
    fn push_text(&mut self, bytes: &[u8]) {
        self.value.push_str(&String::from_utf8_lossy(bytes));
    }

    /// Resolve an entity reference. An unknown or undecodable entity is kept
    /// verbatim: a URL with one odd entity is still better evidence than a
    /// dropped entry.
    fn push_reference(&mut self, reference: &quick_xml::events::BytesRef) {
        let raw = String::from_utf8_lossy(reference.as_ref()).into_owned();
        match reference.resolve_char_ref() {
            Ok(Some(resolved)) => self.value.push(resolved),
            _ => match quick_xml::escape::resolve_predefined_entity(&raw) {
                Some(resolved) => self.value.push_str(resolved),
                None => {
                    self.value.push('&');
                    self.value.push_str(&raw);
                    self.value.push(';');
                }
            },
        }
    }

    fn finish(self) -> Option<String> {
        let trimmed = self.value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

/// Validate sitemap structure and direct `<loc>` entries without external checks.
fn parse_sitemap_xml(body: &str) -> Result<SitemapDocument, &'static str> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut kind = None;
    let mut expected_entry = None;
    let mut depth = 0usize;
    let mut root_closed = false;
    let mut locs: Vec<String> = Vec::new();
    let mut entry_loc: Option<String> = None;
    let mut loc_depth = None;
    let mut loc_text = LocText::default();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let local = element.name().local_name();
                let local = local.as_ref();
                if root_closed {
                    return Err("the XML contains content after its root element");
                }
                if depth == 0 {
                    match local {
                        b"urlset" => {
                            kind = Some(SitemapKind::UrlSet);
                            expected_entry = Some(b"url".as_slice());
                        }
                        b"sitemapindex" => {
                            kind = Some(SitemapKind::SitemapIndex);
                            expected_entry = Some(b"sitemap".as_slice());
                        }
                        _ => return Err("the XML root is not urlset or sitemapindex"),
                    }
                } else if depth == 1 {
                    if Some(local) != expected_entry {
                        return Err("the sitemap root contains an unexpected entry element");
                    }
                    entry_loc = None;
                } else if depth == 2 && local == b"loc" {
                    loc_depth = Some(depth + 1);
                    loc_text = LocText::default();
                }
                depth += 1;
            }
            Ok(Event::Empty(element)) => {
                let local = element.name().local_name();
                let local = local.as_ref();
                if root_closed {
                    return Err("the XML contains content after its root element");
                }
                if depth == 0 {
                    kind = match local {
                        b"urlset" => Some(SitemapKind::UrlSet),
                        b"sitemapindex" => Some(SitemapKind::SitemapIndex),
                        _ => return Err("the XML root is not urlset or sitemapindex"),
                    };
                    root_closed = true;
                } else if depth == 1 {
                    if Some(local) != expected_entry {
                        return Err("the sitemap root contains an unexpected entry element");
                    }
                    return Err("a sitemap entry has no non-empty loc element");
                } else if depth == 2 && local == b"loc" {
                    return Err("a sitemap entry has an empty loc element");
                }
            }
            Ok(Event::Text(text)) => {
                let bytes: &[u8] = text.as_ref();
                let nonblank = !bytes.iter().all(u8::is_ascii_whitespace);
                if nonblank && (depth == 0 || depth == 1) {
                    return Err("the sitemap XML has text outside an entry");
                }
                if loc_depth == Some(depth) {
                    loc_text.push_text(bytes);
                }
            }
            Ok(Event::CData(text)) => {
                let bytes: &[u8] = text.as_ref();
                let nonblank = !bytes.iter().all(u8::is_ascii_whitespace);
                if nonblank && (depth == 0 || depth == 1) {
                    return Err("the sitemap XML has text outside an entry");
                }
                if loc_depth == Some(depth) {
                    // CDATA is literal by definition: no entity resolution.
                    loc_text.push_text(bytes);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if loc_depth == Some(depth) {
                    loc_text.push_reference(&reference);
                }
            }
            Ok(Event::End(element)) => {
                if depth == 0 {
                    return Err("the XML has an unmatched closing element");
                }
                let local = element.name().local_name();
                let local = local.as_ref();
                if loc_depth == Some(depth) && local == b"loc" {
                    entry_loc = std::mem::take(&mut loc_text).finish();
                    loc_depth = None;
                }
                if depth == 2 {
                    if Some(local) != expected_entry {
                        return Err("the sitemap entry closes with an unexpected element");
                    }
                    match entry_loc.take() {
                        Some(loc) => locs.push(loc),
                        None => return Err("a sitemap entry has no non-empty loc element"),
                    }
                }
                depth -= 1;
                if depth == 0 {
                    root_closed = true;
                }
            }
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_)) => {}
            Err(_) => return Err("the response is not well-formed XML"),
        }
    }

    match (kind, root_closed, depth) {
        (Some(kind), true, 0) => Ok(SitemapDocument { kind, locs }),
        (None, _, _) => Err("the response has no sitemap XML root"),
        _ => Err("the sitemap XML root is not closed"),
    }
}

#[cfg(test)]
#[path = "sitemap_document_tests.rs"]
mod tests;
