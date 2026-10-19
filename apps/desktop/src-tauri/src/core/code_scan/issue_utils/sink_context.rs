/// Match sinks outside quoted or regex-literal rule definitions and documentation.
/// PHP and Blade markup sinks may follow an HTML attribute quote, so only a
/// preceding backtick excludes those matches.
pub(in crate::core::code_scan) fn has_any_unquoted(
    content: &str,
    patterns: &[regex::Regex],
) -> bool {
    patterns.iter().any(|pattern| {
        pattern
            .find_iter(content)
            .any(|found| is_executable_sink(content, &found))
    })
}

pub(in crate::core::code_scan) fn is_executable_sink(
    content: &str,
    matched: &regex::Match<'_>,
) -> bool {
    let markup_delimited =
        matched.as_str().starts_with("<?=") || matched.as_str().starts_with("{!!");
    let preceding = content[..matched.start()].chars().next_back();
    if markup_delimited {
        !matches!(preceding, Some('`'))
    } else {
        !matches!(preceding, Some('"' | '\'' | '`' | '/'))
    }
}
