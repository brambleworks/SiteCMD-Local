import { expect, it } from "vitest";
import fs from "node:fs";
import { redactionOrderFailures } from "./lib/guardrail-redaction-order-rules.mjs";

it("log_sanitizer_has_no_key_table", () => {
  // Detector content in the public redactor.
  const root = "apps/desktop/src-tauri/crates/protocol/src";
  const paths = [`${root}/log_sanitizer.rs`, `${root}/log_sanitizer/provider_tokens.rs`];
  const check = (addition) =>
    redactionOrderFailures(
      (name) => fs.readFileSync(name, "utf8") + addition,
      (dir, predicate) => paths.filter((name) => name.startsWith(`${dir}/`) && predicate(name)),
    );
  expect(check("\nuse crate::checks::security::key_patterns;\n")).toEqual(
    paths.map((name) => `${name} - keep the detector key table out of the log sanitizer.`),
  );
  expect(check("")).toEqual([]);
});

it.each([
  "fn sample() { crate::checks::security::provider_key_prefixes(); }",
  "use crate::checks::security::*;",
  'fn sample() { crate::evidence_redaction::redact_evidence(""); }',
  "use crate::evaluation::storable;",
  "#[cfg(test)] fn sample() { crate::literal_coverage_tests::mask_corpus(&[]); }",
  '#[path = "../checks/security/key_patterns.rs"] mod sample;',
  '#[cfg_attr(test, path = r"../checks/security/key_patterns.rs")] mod sample;',
  'include!("../checks/security/key_patterns.rs");',
])("rejects private paths in the log sanitizer: %s", (source) => {
  // Indirect imports and calls can bring private redaction into the public sanitizer.
  const file = "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/provider_tokens.rs";
  expect(
    redactionOrderFailures(
      () => source,
      (dir, predicate) => (file.startsWith(`${dir}/`) && predicate(file) ? [file] : []),
    ),
  ).toEqual([`${file} - keep the detector key table out of the log sanitizer.`]);
});

it("ignores string-path lookalikes in log sanitizer comments and strings", () => {
  // Matching a path directive inside a fixture or comment would refuse unrelated tests.
  const file = "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/provider_tokens.rs";
  const source = `
    // #[path = "../checks/security/key_patterns.rs"] mod sample;
    const FIXTURE: &str = r#"include!("../checks/security/key_patterns.rs");"#;
    `;
  expect(
    redactionOrderFailures(
      () => source,
      (dir, predicate) => (file.startsWith(`${dir}/`) && predicate(file) ? [file] : []),
    ),
  ).toEqual([]);
});

const file = "apps/desktop/src-tauri/crates/runtime/src/redaction_fixture.rs";
function failures(source) {
  return redactionOrderFailures(
    () => source,
    (dir, predicate) => (file.startsWith(`${dir}/`) && predicate(file) ? [file] : []),
  );
}

it("rejects line iterators and windows returned by helpers", () => {
  // Bug: line cuts and helper-returned windows bypass the cut-before-redact guard.
  for (const source of [
    "redact_secrets(&value.lines().take(2).collect::<String>());",
    "let lines = value.lines(); let sample = lines.skip(1).take(2).collect::<String>(); redact_secrets(&sample);",
    "redact_secrets(value.lines().nth(1).unwrap());",
    "redact_secrets(value.split_inclusive('x').take(2).collect::<String>());",
    "fn preview(value: &str) -> &str { &value[..70] } fn sink(value: &str) { redact_secrets(preview(value)); }",
    "fn first(value: &str) -> &str { value.lines().next().unwrap() } fn sink(value: &str) { let sample = first(value); redact_secrets(sample); }",
    "fn cut(value: &str) -> &str { &value[..70] } fn preview(value: &str) -> &str { cut(value) } fn sink(value: &str) { redact_secrets(preview(value)); }",
  ])
    expect(failures(source)).toHaveLength(1);
});

it("distinguishes helpers returning raw windows from already redacted windows", () => {
  // Bug: helper summaries must follow the returned value without exempting unrelated raw cuts.
  expect(
    failures(
      "fn preview(value: &str) -> String { let safe = redact_secrets(value); safe.lines().take(2).collect() } fn sink(value: &str) { redact_secrets(preview(value)); }",
    ),
  ).toEqual([]);
  expect(
    failures(
      "fn preview(value: &str) -> String { let safe = redact_secrets(value); let raw = &value[..70]; raw.to_string() } fn sink(value: &str) { redact_secrets(preview(value)); }",
    ),
  ).toHaveLength(1);
});

it("rejects redaction after a direct or indirect cut", () => {
  // Bug: fragments cut before redaction bypass whole-token patterns.
  for (const source of [
    "redact_secrets(&truncate(value, 70));",
    "redact_issue_evidence(&value[..70]);",
    "redact_evidence(&value.chars().take(70).collect::<String>());",
    "let preview = truncate(value, 70);\nredact_secrets(&preview);",
    "let window = value[start..end].to_string();\nlet evidence = window;\nredact_issue_evidence(&evidence);",
    "redact_secrets(\n &window(value, 70)\n);",
  ])
    expect(failures(source)).toHaveLength(1);
  expect(failures("truncate(&redact_secrets(value), 70);")).toEqual([]);
});

it("keeps temporary checkout fixtures out of the source tree", () => {
  // Bug: a sandbox-only fallback created temporary Git repositories in the crate source tree.
  const source = fs.readFileSync("apps/desktop/src-tauri/src/cli/test_support.rs", "utf8");
  expect(source).not.toContain('tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR"))');
});

it("redacts a malformed URL reference before removing its query suffix", () => {
  // Bug: fallback URL cleanup cut a value before its final redaction boundary.
  const source = fs.readFileSync(
    "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer.rs",
    "utf8",
  );
  expect(source).toContain("let redacted = redact_diagnostic(trimmed);");
  expect(source).toContain("let without_query = redacted.split(['?', '#'])");
});

it("rejects range getters, in-place truncation, and named character iterators", () => {
  // Bug: alternate slicing and truncation spellings can bypass the order guard.
  for (const source of [
    "redact_secrets(value.get(..70).unwrap());",
    "let mut preview = value.to_string(); preview.truncate(70); redact_secrets(&preview);",
    "let mut chars = value.chars(); let preview = chars.by_ref().take(70).collect::<String>(); redact_secrets(&preview);",
  ])
    expect(failures(source)).toHaveLength(1);
});
