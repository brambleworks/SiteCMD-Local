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
