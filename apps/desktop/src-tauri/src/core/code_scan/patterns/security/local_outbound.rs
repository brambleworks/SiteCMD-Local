use std::borrow::Cow;
use std::sync::LazyLock;

/// Calls that look outbound but stay inside the process: a Stripe webhook
/// signature check, bundled assets, and Workers dispatch. Removed from the content
/// before outbound-HTTP matching so a file that also makes a real remote call
/// still counts as outbound.
pub(in crate::core::code_scan) static LOCAL_ONLY_OUTBOUND_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(
                r"\bfetch\s*\(\s*[A-Za-z_$][\w$]*\s*(?::\s*[A-Za-z_$][\w$.<>]*\s*)?,\s*env\b",
            )
            .expect("static local-only regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bASSETS\s*\.\s*fetch\s*\(").expect("static local-only regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bstripe\.webhooks\.\w*\s*\(").expect("static local-only regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r#"(?s)\bfetch\s*\(\s*new\s+URL\s*\(\s*["'`]\.{1,2}/"#)
                .expect("static local-only regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) fn outbound_view(content: &str) -> Cow<'_, str> {
    if !LOCAL_ONLY_OUTBOUND_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(content))
    {
        return Cow::Borrowed(content);
    }
    let mut bytes = content.as_bytes().to_vec();
    for pattern in LOCAL_ONLY_OUTBOUND_PATTERNS.iter() {
        for found in pattern.find_iter(content) {
            for byte in &mut bytes[found.range()] {
                if !matches!(*byte, b'\n' | b'\r') {
                    *byte = b' ';
                }
            }
        }
    }
    let scanned = String::from_utf8(bytes);
    Cow::Owned(scanned.expect("valid UTF-8")) // allow-expect: ASCII replacements preserve UTF-8
}
