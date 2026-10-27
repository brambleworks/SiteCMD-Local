//! How a runtime hands the engine its response header field lines, and how
//! the engine reads each field.
//!
//! The desktop's HTTP client keeps every field line. The Workers `Headers`
//! iterator, following the Fetch standard, combines every repeated field but
//! `Set-Cookie` into one value joined with ", ". [`FIELD_READINGS`] lists
//! each field's reading: first-line fields are restored and list fields are
//! combined, while crawler-scoped and once-only fields retain received lines.
//! `tests/header_readings.rs` holds the engine's sources to these readings.

use serde::{Deserialize, Serialize};

use crate::probe::ProbeResponse;

/// How a runtime handed over its response header field lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderLines {
    /// Every field line as its own name and value.
    #[default]
    Separate,
    /// Every repeated field but `Set-Cookie` combined into one value with ", ".
    Joined,
}

/// How the engine reads one response header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldReading {
    /// Read by its first line, or counted by its lines. A valid line holds a
    /// comma only inside a quoted string or a parenthesized comment, so a
    /// joined value splits back into its lines.
    FirstLine,
    /// Read as every line combined with ", " ([`field_value`], or
    /// [`probe_field_value`] for a probe response): RFC 9110 section 5.3 lets
    /// a recipient combine a field's lines that way without changing its
    /// meaning, so this is the same text however the lines arrived, for a list
    /// field and for free text with no grammar to split.
    EveryLine,
    /// Read only for whether it is present.
    Presence,
    /// Read line by line; the Fetch standard never combines it.
    EachLine,
    /// Read as handed over: a valid response sends it once and a valid value
    /// may hold a comma, so only a malformed repeat reads by lane.
    Once,
    /// Read clauses while carrying a crawler scope across commas in one
    /// received line; joined input does not preserve original scope boundaries.
    CrawlerScoped,
}

/// Every response header field the engine reads, and fields the desktop's
/// checks read through `field_value`, by lowercase name, sorted.
pub const FIELD_READINGS: &[(&str, FieldReading)] = &[
    ("access-control-allow-credentials", FieldReading::FirstLine),
    ("access-control-allow-origin", FieldReading::FirstLine),
    ("alt-svc", FieldReading::EveryLine),
    ("cache-control", FieldReading::EveryLine),
    ("cf-cache-status", FieldReading::Presence),
    ("cf-mitigated", FieldReading::FirstLine),
    ("cf-ray", FieldReading::Presence),
    ("content-encoding", FieldReading::EveryLine),
    ("content-range", FieldReading::FirstLine),
    ("content-security-policy", FieldReading::EveryLine),
    (
        "content-security-policy-report-only",
        FieldReading::EveryLine,
    ),
    ("content-type", FieldReading::FirstLine),
    ("cross-origin-embedder-policy", FieldReading::FirstLine),
    ("cross-origin-opener-policy", FieldReading::FirstLine),
    ("cross-origin-resource-policy", FieldReading::FirstLine),
    ("etag", FieldReading::Presence),
    ("last-modified", FieldReading::Presence),
    ("location", FieldReading::Once),
    ("permissions-policy", FieldReading::EveryLine),
    ("referrer-policy", FieldReading::EveryLine),
    ("server", FieldReading::FirstLine),
    ("set-cookie", FieldReading::EachLine),
    ("strict-transport-security", FieldReading::FirstLine),
    ("vary", FieldReading::EveryLine),
    ("via", FieldReading::EveryLine),
    ("x-amz-cf-id", FieldReading::Presence),
    ("x-amz-request-id", FieldReading::Presence),
    ("x-content-type-options", FieldReading::FirstLine),
    ("x-fastly-request-id", FieldReading::Presence),
    ("x-frame-options", FieldReading::FirstLine),
    ("x-generator", FieldReading::EveryLine),
    ("x-github-request-id", FieldReading::Presence),
    ("x-netlify-request-id", FieldReading::Presence),
    ("x-nf-request-id", FieldReading::Presence),
    ("x-powered-by", FieldReading::EveryLine),
    ("x-robots-tag", FieldReading::CrawlerScoped),
    ("x-vercel-id", FieldReading::Presence),
];

/// The reading the engine gives a lowercase field name, if it reads it.
pub fn reading_of(name: &str) -> Option<FieldReading> {
    FIELD_READINGS
        .binary_search_by(|(field, _)| (*field).cmp(name))
        .ok()
        .map(|index| FIELD_READINGS[index].1)
}

/// The lines a joined value was combined from: split at each comma outside a
/// quoted string and a parenthesized comment, each line trimmed of the space
/// the combination added. An empty line stays, as it was one.
pub fn split_joined(value: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let (mut quoted, mut escaped, mut depth, mut start) = (false, false, 0usize, 0usize);
    for (at, character) in value.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted || depth > 0 => escaped = true,
            '"' if depth == 0 => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth > 0 => depth -= 1,
            ',' if !quoted && depth == 0 => {
                lines.push(value[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    lines.push(value[start..].trim());
    lines
}

/// Restore a joined `FirstLine` field's lines; keep every other reading whole.
pub fn lines_of<'a>(name: &str, value: &'a str) -> Vec<&'a str> {
    if reading_of(name) == Some(FieldReading::FirstLine) {
        split_joined(value)
    } else {
        vec![value]
    }
}

/// Every line of an `EveryLine` field decoded lossily and combined with ", ",
/// or `None` when the field is absent. An unreadable line spoils only its own
/// items, alike on both lanes, as RFC 9110 section 5.3 combines the lines.
pub fn field_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    combined(
        headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()),
    )
}

/// A probe response's `EveryLine` field, read by lowercase name. Like
/// [`field_value`] for a page, every line it carried is combined in arrival
/// order with ", ".
pub fn probe_field_value(response: &ProbeResponse, name: &str) -> Option<String> {
    combined(
        response
            .headers
            .iter()
            .filter(|(field, _)| field == name)
            .map(|(_, value)| value.clone()),
    )
}

/// The one way the engine combines a field's lines: in order, with ", ".
fn combined(lines: impl Iterator<Item = String>) -> Option<String> {
    let lines: Vec<String> = lines.collect();
    (!lines.is_empty()).then(|| lines.join(", "))
}

/// A probe response's lines as a joined page's are read: each `FirstLine`
/// field split back into its lines, and the content type its first line.
pub fn split_probe_lines(response: &mut ProbeResponse) {
    response.headers = std::mem::take(&mut response.headers)
        .into_iter()
        .flat_map(|(name, value)| {
            lines_of(&name, &value)
                .into_iter()
                .map(|line| (name.clone(), line.to_string()))
                .collect::<Vec<_>>()
        })
        .collect();
    if let Some(content_type) = response.content_type.as_deref() {
        response.content_type = lines_of("content-type", content_type)
            .first()
            .map(|line| line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_responses_list_field_reads_every_line_combined() {
        // Reading only the first Vary line hides the Accept-Encoding on the second.
        let response = ProbeResponse {
            status: 200,
            final_url: String::new(),
            content_type: None,
            content_length: None,
            headers: vec![
                ("vary".into(), "Cookie".into()),
                ("vary".into(), "Accept-Encoding".into()),
            ],
            body: None,
        };
        assert_eq!(
            probe_field_value(&response, "vary").as_deref(),
            Some("Cookie, Accept-Encoding")
        );
        assert_eq!(probe_field_value(&response, "content-encoding"), None);
    }

    #[test]
    fn a_joined_value_splits_at_commas_outside_quotes_and_comments() {
        assert_eq!(split_joined("DENY, SAMEORIGIN"), ["DENY", "SAMEORIGIN"]);
        assert_eq!(
            split_joined("max-age=1; ext=\"a,b\", max-age=0"),
            ["max-age=1; ext=\"a,b\"", "max-age=0"]
        );
        assert_eq!(split_joined("a=\"x\\\",y\", b"), ["a=\"x\\\",y\"", "b"]);
        assert_eq!(
            split_joined("Apache/2.4 (Ubuntu, (x64, arm)), nginx"),
            ["Apache/2.4 (Ubuntu, (x64, arm))", "nginx"]
        );
        // Flattening comment depth exposes a comma after the inner comment closes.
        assert_eq!(
            split_joined("Apache/2.4 (Ubuntu (x64), arm), nginx"),
            ["Apache/2.4 (Ubuntu (x64), arm)", "nginx"]
        );
        // An untrimmed middle line retains the space added by combination.
        assert_eq!(
            split_joined("DENY, SAMEORIGIN, DENY"),
            ["DENY", "SAMEORIGIN", "DENY"]
        );
        // A parenthesis inside a quote must not open a comment.
        assert_eq!(split_joined("a=\"(\", b"), ["a=\"(\"", "b"]);
        // A quote inside a comment must not hide the following separator.
        assert_eq!(split_joined("x (say \"hi), y"), ["x (say \"hi)", "y"]);
        // A bare backslash must not escape a separator.
        assert_eq!(split_joined("a\\, b"), ["a\\", "b"]);
        assert_eq!(split_joined(", nosniff"), ["", "nosniff"]);
        assert_eq!(split_joined(""), [""]);
    }

    #[test]
    fn a_field_is_found_by_its_lowercase_name() {
        assert_eq!(reading_of("x-frame-options"), Some(FieldReading::FirstLine));
        assert_eq!(reading_of("cache-control"), Some(FieldReading::EveryLine));
        // A previous-entry lookup or cookie reclassification loses the EachLine reading.
        assert_eq!(reading_of("set-cookie"), Some(FieldReading::EachLine));
        assert_eq!(reading_of("x-unlisted"), None);
    }

    #[test]
    fn only_first_line_fields_restore_joined_lines() {
        // Splitting another reading breaks cookies and list fields in both ingestion paths.
        assert_eq!(
            lines_of("server", "Apache (Ubuntu, x64), nginx"),
            ["Apache (Ubuntu, x64)", "nginx"]
        );
        for name in [
            "cache-control",
            "set-cookie",
            "location",
            "etag",
            "x-robots-tag",
            "x-unlisted",
        ] {
            assert_eq!(lines_of(name, "a, b"), ["a, b"], "{name}");
        }
    }
}
