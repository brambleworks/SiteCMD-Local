use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use sitecmd_engine::checks::polish::word_lists::{
    decode_quote_entities, validate, word_lists, PlaceholderShape, WordLists,
};
use std::collections::BTreeSet;

const LIST_FIELDS: [&str; 13] = [
    "marketing_terms",
    "headline_formulas",
    "scaffold_titles",
    "placeholder_titles",
    "scaffold_favicons",
    "scaffold_markers",
    "scaffold_root_ids",
    "error_page_markers",
    "hosting_suffixes",
    "placeholder_phrases",
    "placeholder_image_hosts",
    "social_platforms",
    "client_template_markers",
];

fn recorded() -> &'static WordLists {
    word_lists()
}

fn encoded() -> Value {
    serde_json::to_value(word_lists()).expect("lists serialize")
}

fn reject(value: Value, rule: &str) {
    let text = serde_json::to_string(&value).expect("inline candidate serializes");
    let lists: WordLists = serde_json::from_str(&text).expect("candidate has the required schema");
    let error = validate(&lists).expect_err("broken list must be rejected");
    assert!(error.contains(rule), "expected {rule}, received {error}");
}

fn listed(value: &str, quote: &str) -> Value {
    json!({"value": value, "cites": [{
        "source": word_lists().sources.keys().next().expect("a source"), "quote": quote
    }]})
}

fn cited_entries(value: &Value) -> Vec<&Value> {
    match value {
        Value::Object(fields) if fields.contains_key("cites") => vec![value],
        Value::Object(fields) => fields.values().flat_map(cited_entries).collect(),
        Value::Array(values) => values.iter().flat_map(cited_entries).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn every_list_the_signals_read_is_present_and_non_empty() {
    // A polish word list entry ships without a recorded source, or a list the signals read is missing.
    let lists = recorded();
    let value = serde_json::to_value(lists).unwrap();
    for field in LIST_FIELDS {
        assert!(
            !value[field].as_array().expect("list").is_empty(),
            "{field}"
        );
    }
    assert!(!lists.headline_word_slots.is_empty());
    assert!(lists
        .headline_word_slots
        .values()
        .all(|words| !words.is_empty()));
    assert!(std::ptr::eq(lists, word_lists()));
}

#[test]
fn every_entry_cites_a_recorded_source_with_a_quote_that_shows_it() {
    // Verbatim HTML entity spellings can hide an entry from its supporting quote.
    let lists = recorded();
    let value = serde_json::to_value(lists).unwrap();
    for entry in cited_entries(&value) {
        let needle = entry
            .get("value")
            .or_else(|| entry.get("example"))
            .or_else(|| entry.get("domain"))
            .unwrap()
            .as_str()
            .unwrap()
            .to_lowercase();
        let cites = entry["cites"].as_array().unwrap();
        assert!(!cites.is_empty());
        for cite in cites {
            assert!(lists.sources.contains_key(cite["source"].as_str().unwrap()));
            let quote = cite["quote"].as_str().unwrap();
            assert!((1..=200).contains(&quote.chars().count()));
            assert!(!quote.contains(['\u{2014}', '\u{2013}']));
            assert!(decode_quote_entities(quote)
                .to_lowercase()
                .contains(&needle));
        }
    }
}

#[test]
fn every_source_records_its_address_publisher_license_and_date() {
    // A source can omit its provenance metadata or carry a malformed retrieval date.
    for source in recorded().sources.values() {
        assert!(source.url.starts_with("https://"));
        assert!([&source.title, &source.publisher, &source.license]
            .iter()
            .all(|s| !s.trim().is_empty()));
        assert_eq!(source.retrieved.len(), 10);
        let date = chrono::NaiveDate::parse_from_str(&source.retrieved, "%Y-%m-%d")
            .expect("retrieval date is a real calendar date");
        assert_eq!(date.format("%Y-%m-%d").to_string(), source.retrieved);
    }
}

#[test]
fn every_source_is_cited_and_no_list_repeats_an_entry() {
    // Unused sources and repeated entries can inflate a recorded vocabulary.
    let lists = recorded();
    let value = serde_json::to_value(lists).unwrap();
    let cited: BTreeSet<_> = cited_entries(&value)
        .iter()
        .flat_map(|entry| {
            entry["cites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cite| cite["source"].as_str().unwrap())
        })
        .collect();
    assert_eq!(cited, lists.sources.keys().map(String::as_str).collect());
    for field in LIST_FIELDS {
        let entries = value[field].as_array().unwrap();
        let key = entry_key(field);
        let unique: BTreeSet<_> = entries
            .iter()
            .map(|entry| entry[key].as_str().unwrap().to_lowercase())
            .collect();
        assert_eq!(unique.len(), entries.len(), "{field}");
    }
    for (name, entries) in &lists.headline_word_slots {
        let unique: BTreeSet<_> = entries
            .iter()
            .map(|entry| entry.value.to_lowercase())
            .collect();
        assert_eq!(unique.len(), entries.len(), "slot {name}");
    }
    for platform in &lists.social_platforms {
        let unique: BTreeSet<_> = platform
            .names
            .iter()
            .map(|name| name.to_lowercase())
            .collect();
        assert_eq!(unique.len(), platform.names.len(), "platform names");
    }
}

#[test]
fn no_formula_hides_a_word_alternation() {
    // A formula can hide unsourced alternatives or leave a recorded word slot unused.
    let lists = recorded();
    assert!(lists
        .headline_formulas
        .iter()
        .all(|formula| !formula.pattern.contains('|')));
    for name in lists.headline_word_slots.keys() {
        assert!(lists
            .headline_formulas
            .iter()
            .any(|formula| formula.pattern.contains(&format!("{{{name}}}"))));
    }
}

#[test]
fn every_headline_formula_compiles_and_matches_its_own_example() {
    // A recorded formula can fail to compile or miss its own cited example.
    // Validation compiles the expanded expression and checks its own example.
    assert!(validate(word_lists()).is_ok());
    assert!(recorded()
        .headline_formulas
        .iter()
        .all(|formula| !formula.example.is_empty()));
}

#[test]
fn every_placeholder_phrase_has_its_shape() {
    // An ordinary phrase or bare domain can masquerade as a complete placeholder.
    assert!(validate(word_lists()).is_ok());
    assert!(!recorded().placeholder_phrases.is_empty());
}

#[test]
fn hosts_and_suffixes_are_bare_lowercase_names() {
    // A recorded host can contain uppercase names, URL syntax, or a missing suffix dot.
    let lists = recorded();
    assert!(lists
        .hosting_suffixes
        .iter()
        .all(|entry| entry.value.starts_with('.')));
    for host in lists
        .placeholder_image_hosts
        .iter()
        .map(|entry| &entry.value)
        .chain(lists.social_platforms.iter().map(|entry| &entry.domain))
    {
        assert!(!host.contains(['/', ':']));
        assert_eq!(*host, host.to_ascii_lowercase());
    }
}

#[test]
fn a_missing_or_empty_list_is_rejected() {
    // A missing or empty word list silently disables a signal.
    for field in LIST_FIELDS {
        let mut value = encoded();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<WordLists>(value).is_err(),
            "{field}"
        );
        let mut value = encoded();
        value[field] = json!([]);
        reject(value, "empty");
    }
    let mut value = encoded();
    value["headline_word_slots"] = json!({});
    reject(value, "empty");
    let mut value = encoded();
    let name = word_lists().headline_word_slots.keys().next().unwrap();
    value["headline_word_slots"][name] = json!([]);
    reject(value, "empty");
}

#[test]
fn an_entry_without_a_citation_is_rejected() {
    // An uncited word can enter a supposedly sourced list.
    let mut value = encoded();
    value["marketing_terms"][0]["cites"] = json!([]);
    reject(value, "at least one");
}

#[test]
fn blank_values_and_platform_names_are_rejected() {
    // Blank vocabulary entries or platform names can satisfy a non-empty list check.
    for field in LIST_FIELDS {
        let mut value = encoded();
        let key = if field == "headline_formulas" {
            "pattern"
        } else if field == "social_platforms" {
            "domain"
        } else {
            "value"
        };
        value[field][0][key] = json!(" ");
        reject(value, "empty");
    }
    let mut value = encoded();
    value["headline_formulas"][0]["example"] = json!(" ");
    reject(value, "empty");
    for names in [json!([]), json!([" "]), json!(["Platform", "PLATFORM"])] {
        let mut value = encoded();
        value["social_platforms"][0]["names"] = names;
        reject(value, "names");
    }
}

#[test]
fn a_citation_to_an_unknown_source_is_rejected() {
    // A citation key can point to a source that was never recorded.
    let mut value = encoded();
    let missing = format!(
        "{}missing",
        word_lists()
            .sources
            .keys()
            .map(String::as_str)
            .collect::<String>()
    );
    value["marketing_terms"][0]["cites"][0]["source"] = json!(missing);
    reject(value, "unknown source");
}

#[test]
fn an_empty_quote_is_rejected() {
    // A citation with an empty quote provides no evidence for its word.
    let mut value = encoded();
    value["marketing_terms"][0]["cites"][0]["quote"] = json!("");
    reject(value, "1 to 200");
}

#[test]
fn a_quote_over_two_hundred_characters_is_rejected() {
    // An overlong quote exceeds the provenance excerpt bound.
    let mut value = encoded();
    value["marketing_terms"] = json!([listed("word", &format!("word{}", "x".repeat(200)))]);
    reject(value, "200");
}

#[test]
fn quotes_with_typographic_dashes_are_rejected() {
    // A source quote can introduce a forbidden em or en dash.
    for dash in ['\u{2014}', '\u{2013}'] {
        let mut value = encoded();
        value["marketing_terms"] = json!([listed("word", &format!("word{dash}"))]);
        reject(value, "dash");
    }
}

#[test]
fn a_quote_that_does_not_show_its_entry_is_rejected() {
    // A recorded quote can fail to contain the entry it supposedly supports.
    let mut value = encoded();
    value["marketing_terms"] = json!([listed("entry", "unrelated passage")]);
    reject(value, "show");
}

#[test]
fn incomplete_source_metadata_is_rejected() {
    // An untraceable source can omit its address, publisher, license, or retrieval date.
    let key = word_lists().sources.keys().next().unwrap();
    for (field, broken) in [
        ("url", "http://example.org"),
        ("url", "https://"),
        ("title", " "),
        ("publisher", ""),
        ("license", ""),
        ("retrieved", "2026-2-03"),
        ("retrieved", "2026-02-30"),
    ] {
        let mut value = encoded();
        value["sources"][key][field] = json!(broken);
        reject(value, "source");
    }
    let mut value = encoded();
    value["sources"] = json!({});
    reject(value, "empty");
}

#[test]
fn an_uncited_source_is_rejected() {
    // A provenance file can advertise a source that supports none of its entries.
    let mut value = encoded();
    let key = format!(
        "{}unused",
        word_lists()
            .sources
            .keys()
            .map(String::as_str)
            .collect::<String>()
    );
    value["sources"][key] = json!({
        "url":"https://example.org/reference", "title":"Reference", "publisher":"Publisher",
        "license":"CC0-1.0", "retrieved":"2026-11-04"
    });
    reject(value, "uncited");
}

#[test]
fn case_insensitive_duplicates_are_rejected_in_every_list() {
    // Case-only duplicates can inflate a word list or repeat a formula.
    for field in LIST_FIELDS {
        let mut value = encoded();
        append_case_duplicate(value[field].as_array_mut().unwrap(), entry_key(field));
        reject(value, "duplicate");
    }
    for name in word_lists().headline_word_slots.keys() {
        let mut value = encoded();
        append_case_duplicate(
            value["headline_word_slots"][name].as_array_mut().unwrap(),
            "value",
        );
        reject(value, "duplicate");
    }
}

fn entry_key(field: &str) -> &str {
    match field {
        "headline_formulas" => "pattern",
        "social_platforms" => "domain",
        _ => "value",
    }
}

fn append_case_duplicate(entries: &mut Vec<Value>, key: &str) {
    let mut original = entries
        .iter()
        .find(|entry| {
            entry[key]
                .as_str()
                .unwrap()
                .chars()
                .any(char::is_alphabetic)
        })
        .cloned()
        .unwrap_or_else(|| {
            let mut entry = entries[0].clone();
            entry[key] = json!("case_word");
            entry["cites"] = listed("case_word", "case_word")["cites"].clone();
            entries.push(entry.clone());
            entry
        });
    let value = original[key].as_str().unwrap();
    let changed = if value.to_uppercase() != value {
        value.to_uppercase()
    } else {
        value.to_lowercase()
    };
    assert_ne!(changed, value, "duplicate must differ in letter case");
    original[key] = json!(changed);
    entries.push(original);
}

#[test]
fn a_formula_word_alternation_is_rejected() {
    // A formula alternation hides words outside the sourced slot lists.
    let mut value = encoded();
    value["headline_formulas"][0]["pattern"] = json!("word|other");
    reject(value, "alternation");
}

#[test]
fn an_unknown_formula_slot_is_rejected() {
    // A formula can reference a word slot that has no recorded list.
    let mut value = encoded();
    let name = format!(
        "{}missing",
        word_lists()
            .headline_word_slots
            .keys()
            .map(String::as_str)
            .collect::<String>()
    );
    value["headline_formulas"][0]["pattern"] = json!(format!("{{{name}}}"));
    reject(value, "unknown slot");
}

#[test]
fn an_unused_word_slot_is_rejected() {
    // A recorded word slot can go unused by every headline formula.
    let mut value = encoded();
    let key = format!(
        "{}unused",
        word_lists()
            .headline_word_slots
            .keys()
            .map(String::as_str)
            .collect::<String>()
    );
    value["headline_word_slots"][key] = json!([listed("word", "word")]);
    reject(value, "unused slot");
}

#[test]
fn invalid_or_nonmatching_formulas_are_rejected() {
    // A sourced formula can be invalid regex or fail to match its own example.
    for (pattern, rule) in [("(", "invalid formula"), ("\\b\\B", "own example")] {
        let mut value = encoded();
        value["headline_formulas"][0]["pattern"] = json!(pattern);
        reject(value, rule);
    }
}

#[test]
fn placeholder_shapes_reject_bare_domains_and_mismatched_forms() {
    // A bare domain or ordinary phrase can be mislabeled as a full placeholder shape.
    for (shape, broken) in [
        ("reserved_address", "example.com"),
        ("reserved_address", "user@actual-site.com"),
        ("reserved_address", "@example.com"),
        ("reserved_address", "a b@example.com"),
        ("bracketed", "[company}"),
        ("here_suffixed", "somewhere"),
        ("copyright_placeholder", "company copyright"),
        ("copyright_placeholder", "copyright.example"),
        ("here_suffixed", "example.here"),
        ("filler", "word"),
        ("filler", "example.com"),
    ] {
        let mut value = encoded();
        let mut entry = listed(broken, broken);
        entry["shape"] = json!(shape);
        value["placeholder_phrases"] = json!([entry]);
        reject(value, "placeholder");
    }
}

#[test]
fn hosts_and_suffixes_reject_uppercase_schemes_and_paths() {
    // A host list can accidentally include uppercase names, URLs, or paths.
    for field in [
        "hosting_suffixes",
        "placeholder_image_hosts",
        "social_platforms",
    ] {
        let broken_hosts: &[&str] = if field == "hosting_suffixes" {
            &[
                ".Example.COM",
                ".example.com/path",
                ".example.com:80",
                ".https://example.com",
                "example.com",
            ]
        } else {
            &[
                "Example.COM",
                "https://example.com",
                "example.com/path",
                "example.com:80",
            ]
        };
        for broken in broken_hosts {
            let mut value = encoded();
            let mut entry = listed(broken, broken);
            if field == "social_platforms" {
                entry.as_object_mut().unwrap().remove("value");
                entry["domain"] = json!(broken);
                entry["names"] = json!(["Platform"]);
            }
            value[field] = json!([entry]);
            reject(
                value,
                if field == "hosting_suffixes" {
                    "hosting suffix must"
                } else {
                    "host must"
                },
            );
        }
    }
}

fn strict_fields<T: Serialize + DeserializeOwned>(value: &T) {
    let value = serde_json::to_value(value).unwrap();
    let mut extra = value.clone();
    extra["unexpected"] = json!(true);
    assert!(serde_json::from_value::<T>(extra).is_err());
    for key in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<T>(missing).is_err(),
            "missing {key}"
        );
    }
}

#[test]
fn every_object_rejects_unknown_and_missing_fields() {
    // Silent unknown or missing fields can disconnect recorded provenance from its schema.
    let lists = word_lists();
    strict_fields(lists);
    strict_fields(lists.sources.values().next().unwrap());
    strict_fields(&lists.marketing_terms[0]);
    strict_fields(&lists.marketing_terms[0].cites[0]);
    strict_fields(&lists.headline_formulas[0]);
    strict_fields(&lists.placeholder_phrases[0]);
    strict_fields(&lists.social_platforms[0]);
}

#[test]
fn placeholder_shapes_serialize_only_as_snake_case() {
    // Placeholder shapes can drift from the provenance file's snake_case contract.
    for (shape, name) in [
        (PlaceholderShape::ReservedAddress, "reserved_address"),
        (PlaceholderShape::Bracketed, "bracketed"),
        (PlaceholderShape::HereSuffixed, "here_suffixed"),
        (
            PlaceholderShape::CopyrightPlaceholder,
            "copyright_placeholder",
        ),
        (PlaceholderShape::Filler, "filler"),
    ] {
        assert_eq!(serde_json::to_value(&shape).unwrap(), json!(name));
        assert!(serde_json::from_value::<PlaceholderShape>(json!(name)).is_ok());
    }
    assert!(serde_json::from_value::<PlaceholderShape>(json!("ReservedAddress")).is_err());
}
