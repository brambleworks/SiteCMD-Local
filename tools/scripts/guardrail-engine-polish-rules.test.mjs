// The CLI's polish phase grades with its own copy of the signal table, the signal runner or the conversion, or names the engine's only in a comment, while the hosted runners grade the engine's.

import { describe, expect, it } from "vitest";

import {
  POLISH_PHASE,
  POLISH_PHASE_BASE,
  POLISH_VERIFY,
  POLISH_VERIFY_BASE,
  RUNTIME_POLISH,
  RUNTIME_POLISH_BASE,
  run,
} from "./lib/engine-artifact-test-fixtures.mjs";

const CSS_FETCH = "apps/desktop/src-tauri/src/checks/polish/css_fetch.rs";

describe("the CLI's polish phase", () => {
  it("accepts both phases calling the engine's functions", () => {
    expect(run()).toEqual([]);
  });

  describe.each([POLISH_PHASE, POLISH_VERIFY])("comment handling in %s", (phase) => {
    it.each([
      ["a trailing line comment", "let x = 1; // polish::polish_check_result("],
      ["a single-line block comment", "/* polish::polish_check_result( */"],
      ["a multiline block comment", "/*\npolish::polish_check_result(\n*/"],
      ["a line doc comment", "/// polish::polish_check_result("],
      ["a block doc comment", "/** polish::polish_check_result( */"],
      ["an inner block doc comment", "/*!\npolish::polish_check_result(\n*/"],
      ["a nested block comment", "/* outer /* inner */ polish::polish_check_result( */"],
    ])("rejects the conversion only in %s", (_, comment) => {
      const source = `let results = polish::run_all_signals(&ctx);\n${comment}`;
      expect(run({ [phase]: source }).some((failure) => failure.includes(phase))).toBe(true);
    });

    it.each([
      ["absent", ""],
      ["a comment", "// polish::grade_stylesheet_coverage(&mut rows, discovered, fetched);"],
      [
        "a string",
        'let proof = "polish::grade_stylesheet_coverage(&mut rows, discovered, fetched);";',
      ],
    ])("rejects coverage grading present only as %s", (_, replacement) => {
      // Dropping the CLI coverage call must not let unread stylesheets produce passing results.
      const base = phase === POLISH_PHASE ? POLISH_PHASE_BASE : POLISH_VERIFY_BASE;
      const source = base.replace(/^.*grade_stylesheet_coverage.*$/m, replacement);
      expect(run({ [phase]: source }).some((failure) => failure.includes(phase))).toBe(true);
    });

    it("accepts a real conversion followed by a trailing comment", () => {
      const source = `${POLISH_PHASE_BASE} // Convert every signal.`;
      expect(run({ [phase]: source })).toEqual([]);
    });

    it.each([
      'let url = "https://example.com/*path*/";',
      'let quoted = "\\"//";',
      'let raw = r#""// /*"#;',
      "let quote = '\"';",
    ])("preserves a literal before a real call: %s", (literal) => {
      const source = `${literal} ${POLISH_PHASE_BASE}`;
      expect(run({ [phase]: source })).toEqual([]);
    });
  });

  it.each([
    [
      "defines its own run_all_signals",
      RUNTIME_POLISH,
      `${RUNTIME_POLISH_BASE}\npub fn run_all_signals(ctx: &PolishContext) -> Vec<PolishResult> {}`,
    ],
    [
      "defines its own polish_check_result",
      CSS_FETCH,
      "pub(crate) fn polish_check_result(r: &PolishResult) -> CheckResult {}",
    ],
    [
      "defines its own POLISH_SIGNALS",
      RUNTIME_POLISH,
      `${RUNTIME_POLISH_BASE}\npub const POLISH_SIGNALS: &[PolishSignal] = &[];`,
    ],
    [
      "names run_all_signals only in a comment",
      POLISH_PHASE,
      POLISH_PHASE_BASE.replace("let signal_results =", "// let signal_results ="),
    ],
    [
      "converts without the engine's polish_check_result",
      POLISH_PHASE,
      POLISH_PHASE_BASE.replace("polish::polish_check_result", "local_conversion"),
    ],
    [
      "copies the stylesheet counter",
      CSS_FETCH,
      "pub fn css_signal_counts(text: &str) -> CssSignalCounts {}",
    ],
    ["copies the stylesheet grade", CSS_FETCH, "pub fn grade_stylesheet_signals() {}"],
    ["copies the CSS coverage rule", CSS_FETCH, "pub fn grade_stylesheet_coverage() {}"],
    ["copies the page signal runner", RUNTIME_POLISH, "pub fn run_page_signals() {}"],
    ["copies the sample limit", CSS_FETCH, "const STYLESHEET_SAMPLE_LIMIT: usize = 8;"],
    ["verifies without the engine's functions", POLISH_VERIFY, "let rows = Vec::new();"],
  ])("rejects a phase that %s", (_, file, source) => {
    const failures = run({ [file]: source });
    expect(failures.some((failure) => failure.includes(file))).toBe(true);
  });
});
