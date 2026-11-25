//! Versioned route canonicalization shared across runtimes.
//!
//! Version 3 preserves case and slash distinctions, resolves dot segments,
//! encodes non-ASCII, controls, and ten printable ASCII characters as UTF-8 escapes,
//! removes tabs/newlines, folds backslashes to slashes, normalizes safe percent encoding,
//! and omits observed queries and fragments.

use serde::{Deserialize, Serialize};

/// Payload canonicalizer version. Rule changes require a new compatibility
/// version so stored route identities retain their original meaning.
pub const CANONICALIZER_VERSION: u8 = 3;

/// ASCII characters RFC 3986 calls unreserved. Percent-encoding any of these
/// is legal but meaningless, so the canonical form decodes them.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// One route: a canonical path plus whether the observation that produced it
/// carried a query string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub struct CanonicalRoute {
    pub route: String,
    #[serde(default)]
    pub query_dependent: bool,
}

impl Serialize for CanonicalRoute {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct WireRoute {
            route: crate::sync::wire::RoutePath,
            query_dependent: bool,
        }
        WireRoute {
            route: self
                .route
                .as_str()
                .try_into()
                .map_err(serde::ser::Error::custom)?,
            query_dependent: self.query_dependent,
        }
        .serialize(serializer)
    }
}

impl CanonicalRoute {
    pub fn new(route: impl Into<String>, query_dependent: bool) -> Self {
        Self {
            route: route.into(),
            query_dependent,
        }
    }
}

/// Canonicalize an observed URL into a route.
///
/// Takes the FINAL url after redirects: identity belongs to the resource the
/// scanner actually read, not the one it asked for.
pub fn canonical_route(url: &url::Url) -> CanonicalRoute {
    CanonicalRoute {
        route: canonical_path(url.path()),
        query_dependent: url.query().is_some_and(|query| !query.is_empty()),
    }
}

/// Canonicalize an authored or stored route path without observation metadata.
pub fn canonical_path(path: &str) -> String {
    let normalized = normalize_percent_encoding(path.trim_matches(|ch| ch <= '\u{20}'));
    let resolved = resolve_dot_segments(&normalized);
    if resolved.starts_with('/') {
        resolved
    } else {
        format!("/{resolved}")
    }
}

/// Encode raw non-ASCII and ten printable ASCII characters as uppercase UTF-8
/// escapes, including ASCII controls; decode only unreserved ASCII escapes.
/// Match URL paths by dropping tabs/newlines and folding backslashes to slashes.
fn normalize_percent_encoding(path: &str) -> String {
    let path = if path.contains(['\t', '\n', '\r', '\\']) {
        std::borrow::Cow::Owned(
            path.chars()
                .filter(|ch| !matches!(ch, '\t' | '\n' | '\r'))
                .map(|ch| if ch == '\\' { '/' } else { ch })
                .collect::<String>(),
        )
    } else {
        std::borrow::Cow::Borrowed(path)
    };
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'%' || index + 2 >= bytes.len() {
            let ch = path[index..].chars().next().expect("character boundary");
            if !ch.is_ascii()
                || ch.is_ascii_control()
                || matches!(
                    ch,
                    ' ' | '"' | '#' | '<' | '>' | '^' | '`' | '?' | '{' | '}'
                )
            {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                for byte in ch.encode_utf8(&mut [0; 4]).bytes() {
                    out.push('%');
                    out.push(HEX[(byte >> 4) as usize] as char);
                    out.push(HEX[(byte & 15) as usize] as char);
                }
            } else {
                out.push(ch);
            }
            index += ch.len_utf8();
            continue;
        }
        let (high, low) = (bytes[index + 1], bytes[index + 2]);
        let Some(decoded) = hex_pair(high, low) else {
            // Not a valid escape. Left exactly as sent: rewriting a malformed
            // path would invent a route the server never served.
            out.push('%');
            index += 1;
            continue;
        };
        if is_unreserved(decoded) {
            out.push(decoded as char);
        } else {
            out.push('%');
            out.push(high.to_ascii_uppercase() as char);
            out.push(low.to_ascii_uppercase() as char);
        }
        index += 3;
    }
    settle_percent_fragments(out)
}

fn settle_percent_fragments(path: String) -> String {
    let mut bytes = Vec::with_capacity(path.len());
    for byte in path.bytes() {
        bytes.push(byte);
        while bytes.len() >= 3 {
            let start = bytes.len() - 3;
            if bytes[start] != b'%' {
                break;
            }
            let Some(decoded) = hex_pair(bytes[start + 1], bytes[start + 2]) else {
                break;
            };
            if is_unreserved(decoded) {
                bytes.truncate(start);
                bytes.push(decoded);
            } else {
                bytes[start + 1].make_ascii_uppercase();
                bytes[start + 2].make_ascii_uppercase();
                break;
            }
        }
    }
    String::from_utf8(bytes).expect("ASCII canonical path") // allow-expect: normalization encodes all non-ASCII bytes
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    let value = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    };
    Some(value(high)? * 16 + value(low)?)
}

/// RFC 3986 dot-segment removal. Repeated slashes are NOT collapsed: `//a`
/// and `/a` can serve different content, and the rules say what is assumed
/// rather than what looks tidy.
fn resolve_dot_segments(path: &str) -> String {
    let leading_slash = path.starts_with('/');
    let trailing_slash = path.ends_with('/') && path.len() > 1;
    let mut segments: Vec<&str> = Vec::new();
    let mut ends_in_dot_segment = false;
    for (index, segment) in path.split('/').enumerate() {
        match segment {
            "." => ends_in_dot_segment = true,
            ".." => {
                segments.pop();
                ends_in_dot_segment = true;
            }
            other => {
                // Only the empty segment BEFORE the leading slash is
                // dropped. Every later one is a repeated slash, which is
                // preserved: `//a` and `/a` can serve different content.
                if !(index == 0 && leading_slash) {
                    segments.push(other);
                }
                ends_in_dot_segment = false;
            }
        }
    }
    let mut out = String::new();
    if leading_slash {
        out.push('/');
    }
    out.push_str(&segments.join("/"));
    if (trailing_slash || ends_in_dot_segment)
        && (!out.ends_with('/') || ends_in_dot_segment && segments.last() == Some(&""))
    {
        out.push('/');
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests;
