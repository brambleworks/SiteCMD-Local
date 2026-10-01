//! Shared formatting and replay assertions for Rust-written parity corpora.

pub(super) fn compact_fields(
    rendered: &mut String,
    value: &serde_json::Value,
    fields: &[&str],
    indent: usize,
) {
    for field in fields {
        let pretty = serde_json::to_string_pretty(&value[field])
            .expect("field serializes")
            .replace('\n', &format!("\n{}", " ".repeat(indent)));
        let source = format!("\"{field}\": {pretty}");
        assert!(rendered.contains(&source), "{field} compaction must match");
        let compact = serde_json::to_string(&value[field]).expect("field serializes");
        // Replace only the first match so identical fields in later cases still match.
        *rendered = rendered.replacen(&source, &format!("\"{field}\": {compact}"), 1);
    }
}

#[test]
fn compaction_replaces_only_the_first_matching_field() {
    let mut rendered =
        "\"locations\": [\n    1,\n    2\n  ]\n\"locations\": [\n    1,\n    2\n  ]".to_string();
    compact_fields(
        &mut rendered,
        &serde_json::json!({"locations": [1, 2]}),
        &["locations"],
        2,
    );
    assert_eq!(
        rendered,
        "\"locations\": [1,2]\n\"locations\": [\n    1,\n    2\n  ]"
    );
}

#[test]
#[should_panic(expected = "mode compaction must match")]
fn compaction_rejects_missing_mode() {
    compact_fields(&mut String::new(), &serde_json::json!({}), &["mode"], 6);
}

#[test]
#[should_panic(expected = "locations compaction must match")]
fn compaction_rejects_missing_locations() {
    compact_fields(
        &mut "\"mode\": null".to_string(),
        &serde_json::json!({}),
        &["mode", "locations"],
        6,
    );
}

#[test]
#[should_panic(expected = "locations compaction must match")]
fn compaction_rejects_an_incorrect_indent() {
    compact_fields(
        &mut "\"locations\": [\n    1,\n    2\n  ]".to_string(),
        &serde_json::json!({"locations": [1, 2]}),
        &["locations"],
        6,
    );
}

fn visible(c: char) -> bool {
    (' '..='~').contains(&c) || c == '\n'
}

pub(super) fn assert_printable_corpus(name: &str, source: &str) {
    if let Some((offset, character)) = source.char_indices().find(|(_, c)| !visible(*c)) {
        let line = source[..offset].bytes().filter(|c| *c == b'\n').count() + 1;
        panic!(
            "{name}:{line}: {} is not printable ASCII",
            character.escape_unicode()
        );
    }
}

pub(super) fn visible_json(rendered: &str) -> String {
    let mut output = String::new();
    for character in rendered.chars() {
        if visible(character) {
            output.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                output.push_str(&format!("\\u{unit:04X}"));
            }
        }
    }
    output
}

#[test]
fn unusual_characters_stay_escaped_without_changing_json() {
    let value = serde_json::json!([
        "\u{7f}",
        "\u{a0}",
        "\u{200b}",
        "\u{d7ff}",
        "\u{e000}",
        "\u{fffd}",
        "\u{10000}",
        "\u{1f600}"
    ]);
    let rendered = visible_json(&serde_json::to_string(&value).unwrap());
    assert_printable_corpus("rendered.json", &rendered);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&rendered).unwrap(),
        value
    );
}

#[test]
fn printable_corpus_text_accepts_ascii_and_newlines() {
    assert_printable_corpus("sample.json", "{\n  \"text\": \"visible ASCII ~\"\n}\n");
}

#[test]
fn printable_corpus_text_rejects_controls_and_unicode() {
    for character in [
        '\0',
        '\t',
        '\r',
        '\u{7f}',
        '\u{a0}',
        '\u{200b}',
        '\u{1f600}',
    ] {
        let source = format!("{{\"text\": \"{character}\"}}\n");
        assert!(
            std::panic::catch_unwind(|| assert_printable_corpus("sample.json", &source)).is_err(),
            "{character:?}"
        );
    }
}

#[test]
#[should_panic(expected = r"sample.json:2: \u{9}")]
fn non_printable_text_names_its_corpus_line_and_character() {
    assert_printable_corpus("sample.json", "{}\n  \t");
}

/// Require a replay failure to identify the broken case.
pub(super) fn assert_replay_panics_for_case(
    replay: impl FnOnce() + std::panic::UnwindSafe,
    name: &str,
) {
    let payload = std::panic::catch_unwind(replay).expect_err("missing key must fail replay");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("replay panic must contain a message");
    assert!(message.contains(name), "{message}");
}

#[test]
fn owned_and_borrowed_panics_identify_their_case() {
    for owned in [true, false] {
        assert_replay_panics_for_case(
            || {
                if owned {
                    std::panic::panic_any(String::from("broken_case"));
                } else {
                    std::panic::panic_any("broken_case");
                }
            },
            "broken_case",
        );
    }
}

#[test]
fn unrelated_panics_do_not_satisfy_a_case_failure() {
    let result = std::panic::catch_unwind(|| {
        assert_replay_panics_for_case(|| panic!("unrelated failure"), "broken_case");
    });
    assert!(result.is_err(), "a panic must identify the broken case");
}
