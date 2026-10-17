//! Shared robots.txt records and leading user-agent product tokens.

/// Read uncommented records across CR, LF and CRLF, normalizing agent values
/// to their leading ASCII product token while keeping the wildcard exact.
pub(crate) fn records(body: &str) -> impl Iterator<Item = (&str, &str)> {
    body.trim_start_matches('\u{feff}')
        .split(['\r', '\n'])
        .filter_map(|line| {
            let (name, value) = line.split('#').next()?.trim().split_once(':')?;
            let name = name.trim();
            let value = value.trim();
            let value = if name.eq_ignore_ascii_case("user-agent") && value != "*" {
                value
                    .split(|character: char| {
                        !character.is_ascii_alphabetic() && !matches!(character, '_' | '-')
                    })
                    .next()
                    .unwrap_or_default()
            } else {
                value
            };
            Some((name, value))
        })
}
