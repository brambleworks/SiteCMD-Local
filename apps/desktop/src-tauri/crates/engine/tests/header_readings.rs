//! Every response header field the engine reads is listed with its reading,
//! and read through an accessor that reading allows, so a field that arrived
//! joined reads as its lines did.

use std::path::{Path, PathBuf};

use sitecmd_engine::header_lines::{reading_of, FieldReading, FIELD_READINGS};
use sitecmd_engine::profile::SECURITY_HEADER_ALLOWLIST;

/// The sources that read fields by a name held elsewhere: `field_value`
/// itself, and the desktop's verified-good profile, which keeps each
/// allowlisted field's lines as received.
const NAMED_ELSEWHERE: &[&str] = &["header_lines.rs", "profile/projection.rs"];

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name != "tests.rs" && !name.ends_with("_tests.rs") {
                found.push(path);
            }
        }
    }
}

fn allowed(reading: FieldReading) -> &'static [&'static str] {
    match reading {
        FieldReading::FirstLine => &["get", "get_all", "contains_key", "header"],
        FieldReading::EveryLine => &["field_value", "contains_key"],
        FieldReading::Presence => &["contains_key"],
        FieldReading::EachLine => &["get_all"],
        FieldReading::Once => &["get", "header"],
        FieldReading::CrawlerScoped => &["get_all"],
    }
}

#[test]
fn every_header_read_names_a_listed_field_through_an_accessor_its_reading_allows() {
    let test_module = regex::Regex::new(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{").expect("pattern");
    let map_read = regex::Regex::new(
        r#"\b(?:headers|response_headers)\s*\.\s*(get_all|get|contains_key)\(\s*"([A-Za-z0-9-]+)"\s*\)"#,
    )
    .expect("pattern");
    let probe_read =
        regex::Regex::new(r#"\.(header)\(\s*"([A-Za-z0-9-]+)"\s*\)"#).expect("pattern");
    let value_read =
        regex::Regex::new(r#"(field_value)\(\s*&?[\w.]+\s*,\s*"([A-Za-z0-9-]+)"\s*\)"#)
            .expect("pattern");
    let unnamed_read = regex::Regex::new(
        r#"\b(?:headers|response_headers)\s*\.\s*(?:get_all|get|contains_key)\(\s*[^"\s)]"#,
    )
    .expect("pattern");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut failures = Vec::new();
    let mut reads = [0; 3];
    for file in files {
        let text = std::fs::read_to_string(&file).expect("source");
        // An inline test module closes a file; nothing but tests follows one.
        let code = test_module
            .find(&text)
            .map_or(text.as_str(), |found| &text[..found.start()]);
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if unnamed_read.is_match(code) && !NAMED_ELSEWHERE.contains(&shown.as_str()) {
            failures.push(format!(
                "{shown}: reads a header by a name that is not a literal"
            ));
        }
        for (index, pattern) in [&map_read, &probe_read, &value_read]
            .into_iter()
            .enumerate()
        {
            for found in pattern.captures_iter(code) {
                reads[index] += 1;
                let (accessor, name) = (&found[1], found[2].to_ascii_lowercase());
                match reading_of(&name) {
                    None => failures.push(format!("{shown}: reads `{name}`, which FIELD_READINGS does not list")),
                    // A direct reader can silently assume a joined value preserves crawler scope.
                    Some(FieldReading::CrawlerScoped) if shown != "checks/seo/robots_tag.rs" => failures.push(format!(
                        "{shown}: reads `{name}` outside the shared crawler reading in checks/seo/robots_tag.rs"
                    )),
                    Some(reading) if !allowed(reading).contains(&accessor) => failures.push(format!(
                        "{shown}: reads `{name}` through `{accessor}`, which a {reading:?} field may not use"
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    // A total count can hide a dead probe or combined-value pattern.
    for (pattern, count) in ["map", "probe", "value"].into_iter().zip(reads) {
        assert!(count > 0, "the {pattern} pattern still finds reads");
    }
    assert!(
        reads.iter().sum::<usize>() > FIELD_READINGS.len(),
        "the patterns still find the engine's reads ({reads:?})"
    );
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_readings_are_lowercase_sorted_and_list_every_profiled_field() {
    for pair in FIELD_READINGS.windows(2) {
        assert!(pair[0].0 < pair[1].0, "{} before {}", pair[0].0, pair[1].0);
    }
    for (name, _) in FIELD_READINGS {
        assert_eq!(*name, name.to_ascii_lowercase());
    }
    for name in SECURITY_HEADER_ALLOWLIST {
        assert!(reading_of(name).is_some(), "{name}");
    }
}
