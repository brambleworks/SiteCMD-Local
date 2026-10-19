/// Match sinks outside quoted data, including JS and template regex samples.
/// PHP and Blade markup sinks may follow an HTML attribute quote, so only a
/// preceding backtick excludes those matches.
pub(in crate::core::code_scan) fn has_any_unquoted(
    content: &str,
    patterns: &[regex::Regex],
) -> bool {
    patterns
        .iter()
        .any(|pattern| executable_sink_matches(content, pattern).next().is_some())
}

/// Retry inside rejected matches so quoted words cannot swallow a live sink.
pub(in crate::core::code_scan) fn executable_sink_matches<'a>(
    content: &'a str,
    pattern: &'a regex::Regex,
) -> impl Iterator<Item = regex::Match<'a>> + 'a {
    let mut offset = 0;
    std::iter::from_fn(move || {
        while offset <= content.len() {
            let found = pattern.find_at(content, offset)?;
            let executable = is_executable_sink(content, &found);
            let next = found.start()
                + content[found.start()..]
                    .chars()
                    .next()
                    .map_or(1, char::len_utf8);
            offset = if executable {
                found.end().max(next)
            } else {
                next
            };
            if executable {
                return Some(found);
            }
        }
        None
    })
}

fn is_executable_sink(content: &str, matched: &regex::Match<'_>) -> bool {
    let markup_delimited =
        matched.as_str().starts_with("<?=") || matched.as_str().starts_with("{!!");
    let preceding = content[..matched.start()].chars().next_back();
    if markup_delimited {
        !matches!(preceding, Some('`'))
    } else {
        let slash_is_data = preceding == Some('/')
            && ["dangerouslySetInnerHTML", "v-html", "innerHTML"]
                .iter()
                .any(|sink| matched.as_str().starts_with(sink))
            && !content[..matched.start()].ends_with("*/");
        !matches!(preceding, Some('"' | '\'' | '`')) && !slash_is_data
    }
}
