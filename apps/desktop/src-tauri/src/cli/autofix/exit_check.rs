//! Check the text that autofix sends to GitHub against the file answers.

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use similar::{ChangeTag, TextDiff};
use sitecmd_engine_host::redact_evidence;
use sitecmd_protocol::brief_copy::FIXED_LINES;
use sitecmd_protocol::engine_abi::{Brief, BriefTarget, Listing, Patch, RelPath};
use sitecmd_protocol::log_sanitizer::{
    log_safe_page_url, prepare_issue_evidence, redact_evidence_provider_tokens,
};

#[path = "exit_check_normalization.rs"]
mod normalization;
use normalization::{fingerprints, text_lines};

#[path = "exit_check_metadata.rs"]
mod metadata;
use metadata::{BriefMetadata, MASKED_FIELD};

const SHINGLE_CHARS: usize = 24;
const MAX_BRIEF_BYTES: usize = 128 * 1024;

// Schleimer, Wilkerson and Aiken, "Winnowing: Local Algorithms for Document
// Fingerprinting" (MOSS, https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf).
// The guarantee t = k + w - 1 requires w = 1 to catch every shared 24-gram.
// Keep every window as exact text and use Aho-Corasick to search the checkout.
fn shingles(line: &str) -> impl Iterator<Item = &str> {
    let offsets = || line.char_indices().map(|(i, _)| i).chain([line.len()]);
    offsets()
        .zip(offsets().skip(SHINGLE_CHARS))
        .map(|(start, end)| &line[start..end])
}

#[derive(Default)]
pub struct HandedLines {
    raw_lines: HashSet<String>,
    lines: HashSet<String>,
    patch_bases: HashMap<RelPath, Vec<u8>>,
}

impl HandedLines {
    pub(super) fn record(&mut self, path: &RelPath, bytes: &[u8]) {
        self.record_lines(bytes);
        self.patch_bases.insert(path.clone(), bytes.to_vec());
    }

    pub(super) fn record_lines(&mut self, bytes: &[u8]) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            for line in text_lines(text)
                .map(str::trim)
                .filter(|line| !trivial(line))
            {
                if !self.raw_lines.contains(line) {
                    self.raw_lines.insert(line.to_owned());
                    self.lines
                        .extend(line_forms(line).filter(|line| !trivial(line)));
                }
            }
        }
    }

    fn has_quote(
        &self,
        exact: &HashSet<String>,
        segments: &HashSet<String>,
        patches: &[Patch],
    ) -> Result<bool, ExitRefusal> {
        let windows: HashSet<_> = segments.iter().flat_map(|line| shingles(line)).collect();
        if exact.is_empty() && windows.is_empty() {
            return Ok(false);
        }
        let matcher = AhoCorasick::new(windows).map_err(|_| ExitRefusal::BriefTooLarge)?;
        let mut quoted = self
            .lines
            .iter()
            .map(String::as_str)
            .filter(|line| exact.contains(*line) || matcher.is_match(line));
        if patches.is_empty() {
            return Ok(quoted.next().is_some());
        }
        let mut quoted = quoted.collect();
        self.remove_patch_lines(patches, &mut quoted);
        Ok(!quoted.is_empty())
    }

    fn remove_patch_lines(&self, patches: &[Patch], quoted: &mut HashSet<&str>) {
        for patch in patches {
            if quoted.is_empty() {
                break;
            }
            let Some(base) = self.patch_bases.get(&patch.path) else {
                continue;
            };
            if Patch::hash_base(base) != patch.base_sha256 {
                continue;
            }
            if let Ok(before) = std::str::from_utf8(base) {
                let diff = TextDiff::from_lines(before, &patch.content);
                for change in diff
                    .iter_all_changes()
                    .filter(|change| change.tag() != ChangeTag::Equal)
                {
                    for line in line_forms(change.value().trim()) {
                        quoted.remove(line.as_str());
                    }
                }
            }
        }
    }
}

fn redact_text(text: &str) -> String {
    redact_evidence(prepare_issue_evidence(text, log_safe_page_url))
}

fn commit_subject(title: &str) -> String {
    // Git folds LF-delimited lines from the first paragraph using ASCII whitespace.
    title
        .split('\n')
        .map(str::trim_ascii)
        .skip_while(|line| line.is_empty())
        .take_while(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn line_forms(line: &str) -> impl Iterator<Item = String> {
    let masked = redact_evidence(line.to_owned());
    let provider_masked = redact_evidence_provider_tokens(line);
    let prepared = prepare_issue_evidence(line, log_safe_page_url);
    let prepared_masked = (prepared != line).then(|| redact_evidence(prepared));
    [
        Some(line),
        (masked != line).then_some(masked.as_str()),
        (provider_masked != line && provider_masked != masked).then_some(provider_masked.as_ref()),
        prepared_masked.as_deref().filter(|&prepared| {
            prepared != line && prepared != masked && prepared != provider_masked
        }),
    ]
    .map(|form| form.map(fingerprints))
    .into_iter()
    .flatten()
    .flatten()
}

fn trivial(line: &str) -> bool {
    line.chars().all(|c| "{}[](),;".contains(c))
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExitRefusal {
    #[error("The brief quotes a line from the checkout outside the fix.")]
    HandedLine,
    #[error("The brief is too large to check for checkout quotes.")]
    BriefTooLarge,
    #[error("A patch targets a file outside the checkout listing.")]
    PatchOutsideListing,
}

pub fn check_brief(
    brief: Brief,
    handed: &HandedLines,
    patches: &[Patch],
) -> Result<Brief, ExitRefusal> {
    check(brief, handed, patches, &BriefMetadata::default())
}

pub(crate) fn check_hosted_brief(
    brief: Brief,
    handed: &HandedLines,
    target: &BriefTarget,
) -> Result<Brief, ExitRefusal> {
    check(brief, handed, &[], &BriefMetadata::new(target))
}

fn check(
    brief: Brief,
    handed: &HandedLines,
    patches: &[Patch],
    metadata: &BriefMetadata,
) -> Result<Brief, ExitRefusal> {
    // Bound matcher construction before normalizing or copying the brief.
    if brief.title.len().saturating_add(brief.body.len()) > MAX_BRIEF_BYTES {
        return Err(ExitRefusal::BriefTooLarge);
    }
    let redacted = Brief {
        title: redact_text(&brief.title),
        body: redact_text(&brief.body),
    };
    let titles = [brief.title.as_str(), redacted.title.as_str()];
    let subjects = titles.map(commit_subject);
    let whole = titles.map(|title| text_lines(title).collect::<Vec<_>>().join(" "));
    // Limits include partial quotes shorter than 24 characters, even on their
    // own line or between verified metadata. In
    // `const API = "https://www.example-shop.com" + secretPath`, each piece
    // around the verified URL is shorter than 24 characters.
    // Quotes split across lines, base64 and other unsupported encodings,
    // nesting beyond the decoding pass limit, right-to-left override reordering,
    // and homoglyphs outside the Unicode confusables data (such as U+1959) can
    // also evade matching.
    let bodies = [&brief.body, &redacted.body]
        .into_iter()
        .flat_map(|text| text_lines(text))
        .filter(|line| !FIXED_LINES.contains(line));
    let lines = bodies
        .chain(titles.into_iter().flat_map(text_lines))
        .chain(whole.iter().chain(&subjects).map(String::as_str));
    let mut exact = HashSet::new();
    let mut segments = HashSet::new();
    for line in lines {
        let Some(masked) = metadata.mask(line) else {
            continue;
        };
        let has_mask = masked.contains(MASKED_FIELD);
        if has_mask {
            exact.extend(fingerprints(line).filter(|line| !trivial(line)));
        }
        for form in masked
            .split(MASKED_FIELD)
            .flat_map(fingerprints)
            .filter(|line| !trivial(line))
        {
            if form.chars().take(SHINGLE_CHARS).count() == SHINGLE_CHARS {
                segments.insert(form);
            } else if !has_mask {
                exact.insert(form);
            }
        }
    }
    if handed.has_quote(&exact, &segments, patches)? {
        Err(ExitRefusal::HandedLine)
    } else {
        Ok(redacted)
    }
}

pub(super) struct CheckedBrief(Brief);

impl CheckedBrief {
    #[cfg(test)]
    pub(super) fn issue(brief: Brief, handed: &HandedLines) -> Result<Self, ExitRefusal> {
        check_brief(brief, handed, &[]).map(Self)
    }

    pub(super) fn hosted(
        brief: Brief,
        handed: &HandedLines,
        target: &BriefTarget,
    ) -> Result<Self, ExitRefusal> {
        check_hosted_brief(brief, handed, target).map(Self)
    }

    pub(super) fn as_brief(&self) -> &Brief {
        &self.0
    }
}

pub(super) fn check_publish_brief(
    listing: &Listing,
    brief: Brief,
    handed: &HandedLines,
    patches: &[Patch],
) -> Result<CheckedBrief, ExitRefusal> {
    if patches.iter().any(|patch| !listing.is_file(&patch.path)) {
        return Err(ExitRefusal::PatchOutsideListing);
    }
    check_brief(brief, handed, patches).map(CheckedBrief)
}

#[cfg(all(test, unix))]
#[path = "exit_check_tests.rs"]
mod tests;
