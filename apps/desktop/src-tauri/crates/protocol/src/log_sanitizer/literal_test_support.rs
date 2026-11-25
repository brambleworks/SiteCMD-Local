//! Exhaustive ASCII language inclusion for credential literal prefilters.

use std::collections::{HashMap, VecDeque};

use regex_automata::dfa::{dense, Automaton, StartKind};
use regex_automata::util::{primitives::StateID, start, syntax};
use regex_automata::Anchored;

type StatePair = (StateID, StateID);
type Parents = HashMap<StatePair, Option<(StatePair, u8)>>;

pub fn mask_corpus(literals: &[&str]) -> Vec<String> {
    let mut corpus: Vec<_> = [
        "",
        "Bearer undefined",
        "Bearer undefined.",
        "Bearer short-token-body",
        "Bearer AbC+DeFgHi+JkLmNo",
        "Bearer AbC/DeFgHi/JkLmNo",
        r"Bearer AbC\U002BDeFgHi\U002BJkLmNo",
        r"Bearer AbC\U002FDeFgHi\U002FJkLmNo",
        r"Bearer AbC\U003DDeFgHi\U003DJkLmNo",
        r"Bearer AbC\u002bDeFgHi\u002bJkLmNo",
        r"Bearer AbC\u002BDeFgHi\u002BJkLmNo",
        r"Bearer AbC\u002fDeFgHi\u002fJkLmNo",
        r"Bearer AbC\u002FDeFgHi\u002FJkLmNo",
        r"Bearer AbC\u003dDeFgHi\u003dJkLmNo",
        r"Bearer AbC\u003DDeFgHi\u003DJkLmNo",
        r"Bearer AbC\/DeFgHi\/JkLmNo",
        "Bearer Bearer AbCdEfGhIjKl",
        "Bearer+Bearer+AbCdEfGhIjKl",
        "Bearer%20Bearer%20AbCdEfGhIjKl",
        "Basic Basic dXNlcjpwYXNz",
        "Basic+Basic+dXNlcjpwYXNz",
        "Basic%20Basic%20dXNlcjpwYXNz",
        "Bearer\nshort-token-body",
        "Bearer\r\n AbCdEfGhIjKl",
        "Basic YTo=",
        r"Basic YTo\u003d",
        r"Basic YTpi\u002f",
        "Basic YTpi%2F%2F",
        "Basic +Basic dXNlcjpwYXNz",
        "Basic a=Basic dXNlcjpwYXNz",
        "Authorization: Basic /Basic dXNlcjpwYXNzMQ==",
        "Basic ab=Basic dXNlcjpwYXNz",
        r"Basic \u002bBasic dXNlcjpwYXNz",
        r"Basic \u002B\u002BBasic dXNlcjpwYXNz",
        "Basic %2BBasic dXNlcjpwYXNz",
        "Basic ++Basic++dXNlcjpwYXNz",
        "Basic++dXNlcjpwYXNz",
        "Basic dXNlcjpwYXNz",
        "Basic%20dXNlcjpwYXNz",
        "Basic\ndXNlcjpwYXNz",
        "Basic\r\n dXNlcjpwYXNz",
        "Basic\u{b}dXNlcjpwYXNz",
        "Basic\u{c}dXNlcjpwYXNz",
        "Basic%09dXNlcjpwYXNz",
        "Basic%0AdXNlcjpwYXNz",
        "basic+bGxhOmxsYWFh",
        r"Basic dXNlcjpwYXNz%2Fnext",
        r"Basic dXNlcjpwYXNz\u002Fnext",
        "https://user:pass@host/path",
        "https://token@host/path",
        "ssh://git@host/repo",
        "docker://user:pass@sha256:digest",
        "docker://user@sha256:digest",
        "/docs/basic+auth+setup",
        "/guides/bearer%20tokens-explained",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for (prefix, length) in [
        ("bearer+", 8),
        ("basic+", 8),
        ("ya29.", 8),
        ("x.1//", 8),
        ("ghp_", 12),
        ("sk_live_", 12),
        ("AKIA", 16),
        ("sk-", 16),
        ("AIza", 16),
        ("sk-ant-", 20),
        ("sk_test_", 20),
        ("rk_live_", 20),
        ("github_pat_", 22),
        ("AIza", 35),
        ("ghp_", 36),
    ] {
        corpus.push(format!(
            "https://example.com/{prefix}{}",
            "0".repeat(length)
        ));
    }
    for literal in literals {
        for prefix in [
            literal.to_string(),
            literal.to_ascii_lowercase(),
            literal.to_ascii_uppercase(),
        ] {
            for length in [
                0, 7, 8, 9, 11, 12, 13, 15, 16, 17, 19, 20, 21, 22, 23, 31, 32, 33, 34, 35, 36, 37,
                42, 43, 44, 64,
            ] {
                for body in [
                    "0".repeat(length),
                    "aBcD".repeat(length.div_ceil(4))[..length].to_string(),
                    "aB3_+/=-".repeat(length.div_ceil(8))[..length].to_string(),
                ] {
                    let token = format!("{prefix}{body}");
                    corpus.extend([
                        token.clone(),
                        format!("x{token}"),
                        format!("_{token}_"),
                        format!("/{token}/{token}"),
                        format!("{token} {token}"),
                    ]);
                }
            }
            let token = format!("{prefix}{}", "aB3".repeat(12));
            for boundary in 0..=127u8 {
                corpus.push(format!("{}{token}", char::from(boundary)));
                corpus.push(format!("{token}{}", char::from(boundary)));
            }
        }
    }
    assert!(corpus.iter().all(|text| text.is_ascii()));
    corpus
}

fn ascii_witness(pattern: &str, insensitive: bool, literals: &[&str]) -> Option<Vec<u8>> {
    assert!(!literals.is_empty());
    assert!(literals
        .iter()
        .all(|literal| literal.is_ascii() && !literal.is_empty()));
    let regex = dense::Builder::new()
        .configure(
            dense::Config::new()
                .unicode_word_boundary(true)
                .start_kind(StartKind::Unanchored),
        )
        .syntax(syntax::Config::new().case_insensitive(insensitive))
        .build(pattern)
        .expect("credential DFA");
    let alternatives = literals
        .iter()
        .map(|literal| super::counted_regex::escape(literal))
        .collect::<Vec<_>>()
        .join("|");
    let filter = dense::Builder::new()
        .configure(dense::Config::new().start_kind(StartKind::Unanchored))
        .syntax(
            syntax::Config::new()
                .unicode(false)
                .utf8(false)
                .case_insensitive(true),
        )
        .build(&alternatives)
        .expect("literal DFA");
    let config = start::Config::new().anchored(Anchored::No);
    let initial = (
        regex.start_state(&config).expect("credential start"),
        filter.start_state(&config).expect("literal start"),
    );
    let mut parents = Parents::from([(initial, None)]);
    let mut queue = VecDeque::from([initial]);
    while let Some(node @ (credential, literal)) = queue.pop_front() {
        // DFA matches are delayed by one byte, including at the end of input.
        if filter.is_match_state(literal) || filter.is_match_state(filter.next_eoi_state(literal)) {
            continue;
        }
        if regex.is_match_state(credential)
            || regex.is_match_state(regex.next_eoi_state(credential))
        {
            let mut witness = Vec::new();
            let mut cursor = node;
            while let Some((previous, byte)) = parents[&cursor] {
                witness.push(byte);
                cursor = previous;
            }
            witness.reverse();
            return Some(witness);
        }
        for byte in 0..=127 {
            let next = (
                regex.next_state(credential, byte),
                filter.next_state(literal, byte),
            );
            assert!(!regex.is_quit_state(next.0), "ASCII must not quit the DFA");
            if regex.is_dead_state(next.0) {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = parents.entry(next) {
                entry.insert(Some((node, byte)));
                queue.push_back(next);
            }
        }
    }
    None
}

pub fn assert_literal_coverage(name: &str, pattern: &str, insensitive: bool, literals: &[&str]) {
    let witness = ascii_witness(pattern, insensitive, literals);
    assert!(
        witness.is_none(),
        "{name}: ASCII match without a required literal: {:?}",
        witness.map(|bytes| String::from_utf8(bytes).expect("ASCII witness"))
    );
}

#[test]
fn proof_finds_missing_alternatives_and_checks_end_of_input() {
    assert_eq!(ascii_witness("x|yz", false, &["x"]), Some(b"yz".to_vec()));
    assert_eq!(ascii_witness("x$", false, &["y"]), Some(b"x".to_vec()));
    assert_literal_coverage("case fold", "(?i)x$", false, &["X"]);
    assert_literal_coverage("delayed literal", "x", false, &["x"]);
}
