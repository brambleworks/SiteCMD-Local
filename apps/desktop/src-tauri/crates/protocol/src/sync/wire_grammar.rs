//! Bounded identifier grammars shared by all connected request types.

use crate::time::UtcTimestamp;

pub(super) fn token(value: &str, max: usize, punctuation: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
}
pub(super) fn fact(v: &str, max: usize) -> bool {
    token(v, max, b"_.:@/+-") && v.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
}
pub(crate) fn hex(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn check_id(v: &str) -> bool {
    token(v, 128, b"_.-~!#$%&'*+^`|") && v.starts_with(|c: char| c.is_ascii_lowercase())
}
pub(super) fn canonical_route(v: &str) -> bool {
    v.starts_with('/')
        && v.encode_utf16().count() <= 2048
        && v.chars().all(|c| {
            !c.is_control()
                && !c.is_whitespace()
                && (c.is_ascii_alphanumeric() || "_~!$&'()*+,;=:@%./-[]|^".contains(c))
        })
        && crate::route::canonical_path(v) == v
}
pub(super) fn finding_identity(v: &str) -> bool {
    if let Some(check) = v.strip_prefix("web:*:") {
        return check_id(check);
    }
    if let Some(code) = v.strip_prefix("code:") {
        return hex(code, 64, 64);
    }
    let route = v.strip_prefix("web:").unwrap_or(v);
    canonical_route(route.strip_suffix('?').unwrap_or(route)) || hex(v, 64, 64)
}
pub(super) fn repository_slug(v: &str) -> bool {
    v.split('/').count() == 2 && v.split('/').all(|s| token(s, 100, b"_.-"))
}
pub(super) fn git_ref(v: &str) -> bool {
    !v.is_empty()
        && v.encode_utf16().count() <= 256
        && v != "@"
        && !v.starts_with('-')
        && !v.ends_with('.')
        && !v.contains("..")
        && !v.contains("@{")
        && !v
            .bytes()
            .any(|b| b <= b' ' || b == 0x7f || b"~^:?*[\\".contains(&b))
        && v.split('/')
            .all(|s| !s.is_empty() && !s.starts_with('.') && !s.ends_with(".lock"))
}
pub(super) fn workflow_ref(v: &str) -> bool {
    v.split_once("/.github/workflows/")
        .is_some_and(|(repo, file)| {
            repository_slug(repo)
                && token(file, 255, b"_.-")
                && (file.ends_with(".yml") || file.ends_with(".yaml"))
        })
}
pub(super) fn timestamp(v: &str) -> bool {
    let bytes = v.as_bytes();
    if !v.is_ascii() || bytes.len() < 20 || bytes.get(10) != Some(&b'T') || &v[17..19] > "59" {
        return false;
    }
    let tail = &v[19..];
    let zone = if let Some(fraction) = tail.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=9).contains(&digits) {
            return false;
        }
        &fraction[digits..]
    } else {
        tail
    };
    (zone == "Z"
        || (zone.len() == 6
            && (zone.starts_with('+') || zone.starts_with('-'))
            && zone.as_bytes()[3] == b':'))
        && UtcTimestamp::parse_from_rfc3339(v).is_ok()
}
