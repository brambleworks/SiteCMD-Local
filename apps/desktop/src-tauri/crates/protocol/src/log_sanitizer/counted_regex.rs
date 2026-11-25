//! Regex operations with work accounting in redaction tests.

use std::borrow::Cow;

#[cfg(any(test, feature = "test-support"))]
pub(super) use regex::escape;
pub(super) use regex::{
    bytes::{Captures as AsciiCaptures, Match as AsciiMatch},
    Captures, Match as UnicodeMatch,
};

pub struct CountedRegex(regex::Regex);

impl CountedRegex {
    pub(super) fn new(pattern: &str) -> Result<Self, regex::Error> {
        regex::Regex::new(pattern).map(Self)
    }

    pub(super) fn case_insensitive(pattern: &str, insensitive: bool) -> Result<Self, regex::Error> {
        regex::RegexBuilder::new(pattern)
            .case_insensitive(insensitive)
            .build()
            .map(Self)
    }

    pub(super) fn is_match(&self, text: &str) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(text.len());
        self.0.is_match(text)
    }

    pub(super) fn find_iter<'r, 'h>(&'r self, text: &'h str) -> regex::Matches<'r, 'h> {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(text.len());
        self.0.find_iter(text)
    }

    pub(super) fn captures_iter<'r, 'h>(&'r self, text: &'h str) -> regex::CaptureMatches<'r, 'h> {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(text.len());
        self.0.captures_iter(text)
    }

    pub(super) fn replace_all<'h>(
        &self,
        text: &'h str,
        replacer: impl regex::Replacer,
    ) -> Cow<'h, str> {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(text.len());
        self.0.replace_all(text, replacer)
    }

    pub(super) fn captures_at<'h>(&self, text: &'h str, offset: usize) -> Option<Captures<'h>> {
        let captures = self.0.captures_at(text, offset);
        #[cfg(any(test, feature = "test-support"))]
        count_capture(
            text.len(),
            offset,
            captures
                .as_ref()
                .and_then(|captures| captures.get(0))
                .map(|m| m.end()),
        );
        captures
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub struct CountedAsciiRegex(regex::bytes::Regex);

impl CountedAsciiRegex {
    pub(super) fn new(pattern: &str, insensitive: bool) -> Result<Self, regex::Error> {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(insensitive)
            .build()
            .map(Self)
    }

    pub(super) fn captures_at<'h>(
        &self,
        text: &'h [u8],
        offset: usize,
    ) -> Option<regex::bytes::Captures<'h>> {
        let captures = self.0.captures_at(text, offset);
        #[cfg(any(test, feature = "test-support"))]
        count_capture(
            text.len(),
            offset,
            captures
                .as_ref()
                .and_then(|captures| captures.get(0))
                .map(|m| m.end()),
        );
        captures
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(any(test, feature = "test-support"))]
fn count_capture(len: usize, offset: usize, end: Option<usize>) {
    super::shared_test_support::count_redaction_work(end.unwrap_or(len) - offset + 1);
}

#[cfg(test)]
mod tests {
    #[test]
    fn all_redaction_regexes_use_counted_operations() {
        // Direct regex imports let a redaction scan bypass the work counter.
        let raw_regex =
            regex::Regex::new(r"\bregex\s*::|\b(?:use|extern\s+crate)\s+[^;]*\bregex\b").unwrap();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut paths = vec![src.join("log_sanitizer.rs"), src.join("log_sanitizer")];
        while let Some(path) = paths.pop() {
            if path.is_dir() {
                paths.extend(
                    std::fs::read_dir(path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && path != src.join("log_sanitizer/counted_regex.rs")
            {
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !raw_regex.is_match(&source),
                    "{} uses regex directly",
                    path.display(),
                );
            }
        }
    }
}
