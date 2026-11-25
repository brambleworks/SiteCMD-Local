//! Conservative literal filtering before compiling credential automata.

pub fn may_contain_literal(text: &str, literals: &[&str]) -> bool {
    literals.iter().any(|literal| {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(text.len());
        if text.is_ascii() {
            return text
                .as_bytes()
                .windows(literal.len())
                .any(|window| window.eq_ignore_ascii_case(literal.as_bytes()));
        }
        // Only these two non-ASCII letters fold into ASCII credential literals.
        text.char_indices().any(|(start, _)| {
            let mut chars = text[start..].chars();
            literal.bytes().all(|byte| {
                chars.next().is_some_and(|ch| {
                    let folded = match ch {
                        '\u{17f}' => 's',
                        '\u{212a}' => 'k',
                        _ => ch,
                    };
                    folded.is_ascii() && (folded as u8).eq_ignore_ascii_case(&byte)
                })
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::may_contain_literal;

    #[test]
    fn ascii_filter_accepts_every_case_and_alternative() {
        assert!(may_contain_literal(
            "prefix BaSiC suffix",
            &["bearer", "basic"]
        ));
        assert!(!may_contain_literal(
            "https://example.com/keep/1",
            &["bearer", "basic"]
        ));
    }

    #[test]
    fn unicode_case_folds_reach_the_regex() {
        for text in ["ba\u{17f}ic", "s\u{212a}-live"] {
            assert!(may_contain_literal(text, &["basic", "sk"]));
        }
    }
}

#[cfg(test)]
mod unicode_filter_tests {
    #[test]
    fn non_ascii_paths_without_provider_literals_skip_masks() {
        // Decoded non-ASCII paths compile every credential mask without a matching literal.
        for text in ["café", "x\u{fffd}%A", "密钥"] {
            assert!(!super::may_contain_literal(
                text,
                &["basic", "bearer", "sk_test_", "AKIA", "key-"]
            ));
        }
    }
}
