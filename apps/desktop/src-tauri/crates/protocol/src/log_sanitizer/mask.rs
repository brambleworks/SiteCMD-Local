//! Credential captures and replacements use ASCII automata on ASCII text.

use super::counted_regex::{
    AsciiCaptures, AsciiMatch, Captures as UnicodeCaptures, CountedAsciiRegex, CountedRegex,
    UnicodeMatch,
};
use std::borrow::Cow;
use std::sync::OnceLock;

#[derive(Default)]
pub struct Mask {
    ascii: OnceLock<CountedAsciiRegex>,
    unicode: OnceLock<CountedRegex>,
}

impl Mask {
    pub const fn new() -> Self {
        Self {
            ascii: OnceLock::new(),
            unicode: OnceLock::new(),
        }
    }

    pub fn regex(&self, pattern: &str, insensitive: bool, ascii: bool) -> MaskRegex<'_> {
        self.regex_with_unicode(pattern, pattern, insensitive, ascii)
    }

    pub fn regex_with_unicode(
        &self,
        pattern: &str,
        unicode_pattern: &str,
        insensitive: bool,
        ascii: bool,
    ) -> MaskRegex<'_> {
        let unicode = || {
            self.unicode.get_or_init(|| {
                CountedRegex::case_insensitive(unicode_pattern, insensitive)
                    .expect("static credential mask") // allow-expect: compile-time credential regex
            })
        };
        if ascii {
            MaskRegex::Ascii {
                regex: self.ascii.get_or_init(|| {
                    CountedAsciiRegex::new(pattern, insensitive)
                        .expect("static ASCII credential regex") // allow-expect: compile-time credential regex
                }),
                #[cfg(any(test, feature = "test-support"))]
                unicode: unicode(),
            }
        } else {
            MaskRegex::Unicode(unicode())
        }
    }
}

pub enum MaskRegex<'r> {
    Ascii {
        regex: &'r CountedAsciiRegex,
        #[cfg(any(test, feature = "test-support"))]
        unicode: &'r CountedRegex,
    },
    Unicode(&'r CountedRegex),
}

impl MaskRegex<'_> {
    pub fn captures_at<'h>(&self, text: &'h str, offset: usize) -> Option<Captures<'h>> {
        match self {
            Self::Ascii { regex, .. } => {
                let captures = regex.captures_at(text.as_bytes(), offset);
                #[cfg(any(test, feature = "test-support"))]
                if let Self::Ascii { unicode, .. } = self {
                    let spans = captures.as_ref().map(|captures| {
                        captures
                            .iter()
                            .map(|value| value.map(|m| m.range()))
                            .collect::<Vec<_>>()
                    });
                    let expected = unicode.captures_at(text, offset).map(|captures| {
                        captures
                            .iter()
                            .map(|value| value.map(|m| m.range()))
                            .collect::<Vec<_>>()
                    });
                    assert_eq!(spans, expected, "ASCII captures: {}", regex.as_str());
                }
                captures.map(Captures::Ascii)
            }
            Self::Unicode(regex) => regex.captures_at(text, offset).map(Captures::Unicode),
        }
    }

    pub fn replace_all<'h>(
        &self,
        text: &'h str,
        replace: impl Fn(&Captures<'_>) -> String,
    ) -> Cow<'h, str> {
        let result = self.replace_matches(text, &replace);
        #[cfg(any(test, feature = "test-support"))]
        if let Self::Ascii { unicode, .. } = self {
            let expected = Self::Unicode(unicode).replace_matches(text, &replace);
            assert_eq!(result, expected, "ASCII replacement: {}", unicode.as_str());
        }
        result
    }

    fn replace_matches<'h>(
        &self,
        text: &'h str,
        replace: &impl Fn(&Captures<'_>) -> String,
    ) -> Cow<'h, str> {
        let mut output = String::new();
        let mut offset = 0;
        while let Some(captures) = self.captures_at(text, offset) {
            if captures.name("basic_body").is_some() {
                return super::basic::redact(text);
            }
            let whole = captures.get(0).expect("whole credential capture"); // allow-expect: every regex match has group zero
            assert!(
                whole.end() > whole.start(),
                "credential masks cannot be empty"
            );
            if offset == 0 {
                output.reserve(text.len());
            }
            output.push_str(&text[offset..whole.start()]);
            let replacement = replace(&captures);
            output.push_str(&replacement);
            offset = whole.end();
        }
        if offset == 0 {
            Cow::Borrowed(text)
        } else {
            output.push_str(&text[offset..]);
            Cow::Owned(output)
        }
    }
}

pub enum Captures<'h> {
    Ascii(AsciiCaptures<'h>),
    Unicode(UnicodeCaptures<'h>),
}

impl<'h> Captures<'h> {
    pub fn get(&self, index: usize) -> Option<Match<'h>> {
        match self {
            Self::Ascii(captures) => captures.get(index).map(ascii_match),
            Self::Unicode(captures) => captures.get(index).map(unicode_match),
        }
    }

    pub fn name(&self, name: &str) -> Option<Match<'h>> {
        match self {
            Self::Ascii(captures) => captures.name(name).map(ascii_match),
            Self::Unicode(captures) => captures.name(name).map(unicode_match),
        }
    }

    pub fn expand(&self, replacement: &str, output: &mut String) {
        match self {
            Self::Ascii(captures) => {
                let mut bytes = Vec::new();
                captures.expand(replacement.as_bytes(), &mut bytes);
                output.push_str(std::str::from_utf8(&bytes).expect("ASCII replacement"));
                // allow-expect: ASCII templates and captures produce valid UTF-8
            }
            Self::Unicode(captures) => captures.expand(replacement, output),
        }
    }
}

pub struct Match<'h> {
    text: &'h str,
    start: usize,
    end: usize,
}

impl<'h> Match<'h> {
    pub fn as_str(&self) -> &'h str {
        self.text
    }
    pub fn start(&self) -> usize {
        self.start
    }
    pub fn end(&self) -> usize {
        self.end
    }
}

fn ascii_match(found: AsciiMatch<'_>) -> Match<'_> {
    Match {
        text: std::str::from_utf8(found.as_bytes()).expect("ASCII match"), // allow-expect: byte masks only receive ASCII text
        start: found.start(),
        end: found.end(),
    }
}

fn unicode_match(found: UnicodeMatch<'_>) -> Match<'_> {
    Match {
        text: found.as_str(),
        start: found.start(),
        end: found.end(),
    }
}

impl std::ops::Index<usize> for Captures<'_> {
    type Output = str;
    fn index(&self, index: usize) -> &str {
        self.get(index).expect("required mask capture").as_str() // allow-expect: static replacements reference required captures
    }
}

impl std::ops::Index<&str> for Captures<'_> {
    type Output = str;
    fn index(&self, name: &str) -> &str {
        self.name(name)
            .expect("required named mask capture") // allow-expect: static replacements reference required captures
            .as_str()
    }
}
