//! URL paths expose normalized credentials before entering text sinks.

use std::borrow::Cow;

use super::{sanitize_page_url, Captures, UrlMask, EVIDENCE_URL};

pub(crate) fn redact_url_credentials(input: &str, mask_url: UrlMask) -> Cow<'_, str> {
    let absolute = EVIDENCE_URL.replace_all(input, |captures: &Captures<'_>| {
        let address = &captures[0];
        sanitized_reference(address, mask_url).unwrap_or_else(|| address.to_owned())
    });
    let mut cursor = 0;
    let mut copied = 0;
    let mut output = String::new();
    while let Some(slash) = memchr::memchr(b'/', &absolute.as_bytes()[cursor..]) {
        let start = cursor + slash;
        cursor = start + 1;
        if start > 0
            && matches!(absolute.as_bytes()[start - 1], b':' | b'/' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
        {
            continue;
        }
        let end = absolute[start..]
            .find(|ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '\"' | '\''))
            .map_or(absolute.len(), |length| start + length);
        cursor = end;
        if let Some(safe) = sanitized_reference(&absolute[start..end], mask_url) {
            output.push_str(&absolute[copied..start]);
            output.push_str(&safe);
            copied = end;
        }
    }
    if copied == 0 {
        absolute
    } else {
        output.push_str(&absolute[copied..]);
        Cow::Owned(output)
    }
}

fn sanitized_reference(address: &str, mask_url: UrlMask) -> Option<String> {
    #[cfg(any(test, feature = "test-support"))]
    super::shared_test_support::count_redaction_work(address.len());
    let parsed = if address.starts_with('/') {
        url::Url::parse("https://evidence.invalid/")
            .ok()?
            .join(address)
            .ok()?
    } else {
        url::Url::parse(address).ok()?
    };
    parsed
        .path()
        .split('/')
        .any(|segment| {
            private_path_segment(segment)
                || super::provider_tokens::encoded_segment_contains_credentials(segment, mask_url)
        })
        .then(|| {
            let safe = sanitize_page_url(parsed.as_str(), false, mask_url);
            let prefix = if address.starts_with("//") {
                "https:"
            } else if address.starts_with('/') {
                "https://evidence.invalid"
            } else {
                return safe;
            };
            safe.strip_prefix(prefix).unwrap_or(&safe).to_owned()
        })
}

pub(super) fn private_path_segment(segment: &str) -> bool {
    let Some(value) = crate::url_path::normalized_segment(segment) else {
        return true;
    };
    if value
        .split_once('@')
        .is_some_and(|(local, _)| local.contains(':'))
    {
        return true;
    }
    let folded = value.replace(crate::url_path::SSN_DASHES, "-");
    folded.as_bytes().windows(11).any(|part| {
        part[3] == b'-'
            && part[6] == b'-'
            && part
                .iter()
                .enumerate()
                .all(|(index, byte)| index == 3 || index == 6 || byte.is_ascii_digit())
    })
}
