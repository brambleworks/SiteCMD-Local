//! Shared formatting and replay assertions for Rust-written parity corpora.

pub(super) fn insert_inputs(value: &mut serde_json::Value, inputs: Vec<serde_json::Value>) {
    let cases = value["cases"].as_array_mut().expect("cases array");
    let mut inserted = Vec::new();
    for input in inputs {
        assert!(
            input.get("expected").is_none(),
            "inputs carry no expected value"
        );
        if let Some(position) = cases.iter().position(|case| case["name"] == input["name"]) {
            let existing = cases.remove(position);
            let mut actual_input = existing.clone();
            actual_input
                .as_object_mut()
                .expect("case object")
                .remove("expected");
            assert_eq!(actual_input, input, "{} input changed", input["name"]);
            inserted.push(existing);
        } else {
            inserted.push(input);
        }
    }
    // Insert in Rust order before the final original case so its closing delimiter stays unchanged.
    let insertion = cases.len().saturating_sub(1);
    cases.splice(insertion..insertion, inserted);
}

pub(super) fn reset_inputs(value: &mut serde_json::Value, inputs: Vec<serde_json::Value>) {
    value["cases"]
        .as_array_mut()
        .expect("cases array")
        .retain(|case| !inputs.iter().any(|input| case["name"] == input["name"]));
    insert_inputs(value, inputs);
}

pub(super) fn assert_inputs_match_corpus(source: &str, inputs: Vec<serde_json::Value>) {
    let value: serde_json::Value = serde_json::from_str(source).expect("corpus parses");
    let mut with_inputs = value.clone();
    insert_inputs(&mut with_inputs, inputs);
    assert_eq!(with_inputs, value, "Rust inputs must be regenerated");
}

#[test]
#[should_panic(expected = "inputs carry no expected value")]
fn insertion_rejects_a_hand_written_expected_value() {
    insert_inputs(
        &mut serde_json::json!({"cases": []}),
        vec![serde_json::json!({"name": "new", "expected": null})],
    );
}

#[test]
#[should_panic(expected = "input changed")]
fn insertion_refuses_a_changed_input() {
    insert_inputs(
        &mut serde_json::json!({"cases": [{"name": "new", "input": 1}]}),
        vec![serde_json::json!({"name": "new", "input": 2})],
    );
}

#[test]
fn insertion_uses_rust_order_before_the_final_original_case() {
    let first = serde_json::json!({"name": "first"});
    let last = serde_json::json!({"name": "last"});
    let a = serde_json::json!({"name": "a", "input": 1});
    let b = serde_json::json!({"name": "b", "input": 2});
    let c = serde_json::json!({"name": "c", "input": 3});
    let mut value = serde_json::json!({"cases": [first, b, a, last]});
    value["cases"][1]["expected"] = serde_json::json!("kept");
    let expected_b = value["cases"][1].clone();
    insert_inputs(&mut value, vec![a.clone(), b, c.clone()]);
    assert_eq!(
        value,
        serde_json::json!({"cases": [first, a, expected_b, c, last]})
    );
}

#[test]
fn insertion_is_idempotent_without_original_cases() {
    let inputs = vec![
        serde_json::json!({"name": "a"}),
        serde_json::json!({"name": "b"}),
    ];
    let mut value = serde_json::json!({"cases": []});
    insert_inputs(&mut value, inputs.clone());
    let inserted = value.clone();
    insert_inputs(&mut value, inputs.clone());
    assert_eq!(value, inserted);
    assert_eq!(value["cases"], serde_json::json!(inputs));
}

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
