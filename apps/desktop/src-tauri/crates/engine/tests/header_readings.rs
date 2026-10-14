//! Every response header field the engine reads is listed with its reading,
//! and read through an accessor that reading allows, so a field that arrived
//! joined reads as its lines did.

use std::path::{Path, PathBuf};

use regex::Regex;

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
        FieldReading::EveryLine => &["field_value", "probe_field_value", "contains_key"],
        FieldReading::Presence => &["contains_key"],
        FieldReading::EachLine => &["get_all"],
        FieldReading::Once => &["get", "header"],
        FieldReading::CrawlerScoped => &["get_all"],
    }
}

/// The patterns a read is found by, each capturing its accessor and its
/// field: a header map's, a probe response's and a combined value's; and a map
/// read whose name is not a literal.
struct Patterns {
    reads: [Regex; 3],
    unnamed: Regex,
    calls: Regex,
}

fn patterns() -> Patterns {
    let pattern = |source: &str| Regex::new(source).expect("pattern");
    Patterns {
        reads: [
            pattern(
                r#"\b(?:headers|response_headers)\s*\.\s*(get_all|get|contains_key)\(\s*"([A-Za-z0-9-]+)"\s*,?\s*\)"#,
            ),
            pattern(r#"\.(header)\(\s*"([A-Za-z0-9-]+)"\s*,?\s*\)"#),
            pattern(r#"\b((?:probe_)?field_value)\(\s*&?[\w.]+\s*,\s*"([A-Za-z0-9-]+)"\s*,?\s*\)"#),
        ],
        unnamed: pattern(
            r#"\b(?:headers|response_headers)\s*\.\s*(?:get_all|get|contains_key)\(\s*[^"\s)]"#,
        ),
        calls: pattern(r"(\bfn\s+)?\b(?:probe_)?field_value\("),
    }
}

fn call_count(patterns: &Patterns, code: &str) -> usize {
    patterns
        .calls
        .captures_iter(code)
        .filter(|found| found.get(1).is_none())
        .count()
}

/// Each read in one file's code that its field's reading does not allow, with
/// every read counted under the pattern that found it.
fn read_failures(
    patterns: &Patterns,
    shown: &str,
    code: &str,
    reads: &mut [usize; 3],
) -> Vec<String> {
    let mut failures = Vec::new();
    if patterns.unnamed.is_match(code) && !NAMED_ELSEWHERE.contains(&shown) {
        failures.push(format!(
            "{shown}: reads a header by a name that is not a literal"
        ));
    }
    let value_reads_before = reads[2];
    for (index, pattern) in patterns.reads.iter().enumerate() {
        for found in pattern.captures_iter(code) {
            reads[index] += 1;
            let (accessor, spelling) = (&found[1], &found[2]);
            let name = spelling.to_ascii_lowercase();
            if matches!(accessor, "header" | "probe_field_value") && spelling != name {
                failures.push(format!(
                    "{shown}: reads `{spelling}` through `{accessor}` with a name that is not lowercase"
                ));
                continue;
            }
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
    if call_count(patterns, code) > reads[2] - value_reads_before {
        failures.push(format!(
            "{shown}: calls a combined value reader in a form this guardrail cannot read"
        ));
    }
    failures
}

#[test]
fn every_header_read_names_a_listed_field_through_an_accessor_its_reading_allows() {
    let test_module = regex::Regex::new(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{").expect("pattern");
    let patterns = patterns();
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
        failures.extend(read_failures(&patterns, &shown, code, &mut reads));
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

#[test]
fn a_first_line_field_read_as_a_probe_responses_combined_value_fails() {
    // Combining a first-line field's lines would re-join what a joined session
    // split back, so the probe reader is for every-line fields only.
    let failures = read_failures(
        &patterns(),
        "checks/example.rs",
        r#"let framing = header_lines::probe_field_value(response, "x-frame-options");"#,
        &mut [0; 3],
    );
    assert_eq!(
        failures,
        ["checks/example.rs: reads `x-frame-options` through `probe_field_value`, which a FirstLine field may not use"]
    );
}

#[test]
fn a_wrapped_first_line_probe_field_read_fails() {
    // A trailing comma must not hide a forbidden combined value read.
    let failures = read_failures(
        &patterns(),
        "checks/example.rs",
        r#"let framing = header_lines::probe_field_value(
            response,
            "x-frame-options",
        );"#,
        &mut [0; 3],
    );
    assert_eq!(
        failures,
        ["checks/example.rs: reads `x-frame-options` through `probe_field_value`, which a FirstLine field may not use"]
    );
}

#[test]
fn an_indexed_probe_field_read_that_escapes_checking_fails() {
    // An indexed response must not let a combined value read escape checking.
    let failures = read_failures(
        &patterns(),
        "checks/example.rs",
        r#"let vary = header_lines::probe_field_value(&answers[0], "vary");"#,
        &mut [0; 3],
    );
    assert_eq!(
        failures,
        ["checks/example.rs: calls a combined value reader in a form this guardrail cannot read"]
    );
}

#[test]
fn probe_header_names_that_are_not_lowercase_fail() {
    // Uppercase literals otherwise pass checking but the probe lookups answer nothing.
    let failures = read_failures(
        &patterns(),
        "checks/example.rs",
        r#"let server = response.header("Server");
        let vary = header_lines::probe_field_value(response, "Vary");"#,
        &mut [0; 3],
    );
    assert_eq!(
        failures,
        [
            "checks/example.rs: reads `Server` through `header` with a name that is not lowercase",
            "checks/example.rs: reads `Vary` through `probe_field_value` with a name that is not lowercase",
        ]
    );
}
