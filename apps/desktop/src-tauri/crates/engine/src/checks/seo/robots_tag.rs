//! The X-Robots-Tag header as the page-level readers read it.
//!
//! A field line is a comma-separated list of clauses, and a crawler `name:` clause
//! names the crawler the unprefixed clauses after it address, until the line
//! ends. A runtime that combined the lines hands over one value in which any
//! comma may have been where a line ended, after which no name carries.

use crate::header_lines::HeaderLines;

/// A directive that carries a value after its colon. Its name is never a
/// crawler's.
pub fn is_valued_robots_directive(name: &str) -> bool {
    matches!(
        name,
        "max-snippet" | "max-image-preview" | "max-video-preview" | "unavailable_after"
    )
}

/// A normalized crawler token, excluding valued directives and any name
/// that is not a crawler token, such as a date fragment.
pub(crate) fn crawler_name(name: &str) -> Option<String> {
    let name = name.trim().to_ascii_lowercase();
    (!is_valued_robots_directive(&name)
        && !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*')))
    .then_some(name)
}

/// The X-Robots-Tag lines a reader reads: as they arrived and, for lines that
/// arrived joined, at the ends of what they could have been.
pub struct RobotsTagReadings {
    /// The lines as they arrived. A joined value read this way carries every
    /// name across each of its commas.
    pub as_arrived: Vec<String>,
    /// For joined lines, one line per clause, so no name carries. In any split
    /// of the value an unprefixed clause after a name addresses that name's
    /// crawler, as it does read as it arrived, or every crawler, as here.
    pub per_clause: Option<Vec<String>>,
    /// For joined lines, one line per clause whose scope every split gives:
    /// every clause but an unprefixed one after a name.
    pub fixed: Option<Vec<String>>,
}

/// The page's X-Robots-Tag lines, read as `lines` says they arrived.
pub fn readings(headers: &http::HeaderMap, lines: HeaderLines) -> RobotsTagReadings {
    let as_arrived: Vec<String> = headers
        .get_all("x-robots-tag")
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    if lines == HeaderLines::Separate {
        return RobotsTagReadings {
            as_arrived,
            per_clause: None,
            fixed: None,
        };
    }
    let (mut per_clause, mut fixed) = (Vec::new(), Vec::new());
    for value in &as_arrived {
        let mut after_a_name = false;
        for clause in value
            .split(',')
            .map(str::trim)
            .filter(|clause| !clause.is_empty())
        {
            let named = clause
                .split_once(':')
                .is_some_and(|(name, _)| crawler_name(name).is_some());
            if clause.contains(':') || !after_a_name {
                fixed.push(clause.to_string());
            }
            after_a_name |= named;
            per_clause.push(clause.to_string());
        }
    }
    RobotsTagReadings {
        as_arrived,
        per_clause: Some(per_clause),
        fixed: Some(fixed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_joined_value_is_read_at_both_ends_and_by_its_fixed_clauses() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            "x-robots-tag",
            "noindex, bingbot: noarchive, nofollow, max-snippet: 2"
                .parse()
                .expect("value"),
        );
        let joined = readings(&headers, HeaderLines::Joined);
        assert_eq!(
            joined.as_arrived,
            ["noindex, bingbot: noarchive, nofollow, max-snippet: 2"]
        );
        assert_eq!(
            joined.per_clause.expect("joined"),
            [
                "noindex",
                "bingbot: noarchive",
                "nofollow",
                "max-snippet: 2"
            ]
        );
        assert_eq!(
            joined.fixed.expect("joined"),
            ["noindex", "bingbot: noarchive", "max-snippet: 2"]
        );
        let separate = readings(&headers, HeaderLines::Separate);
        assert!(separate.per_clause.is_none() && separate.fixed.is_none());
    }
}
