// A polish source file keeps a word list outside the recorded file, so its entries ship without a source.
import { describe, expect, it } from "vitest";
import { polishWordListFailures } from "./lib/guardrail-polish-word-lists.mjs";
import { repoGuardrailIo } from "./check-repo-guardrails.mjs";

const FILE = "apps/desktop/src-tauri/crates/engine/src/checks/polish/copy_content.rs";
function run(source, file = FILE) {
  return polishWordListFailures(
    () => source,
    () => true,
    (_dir, predicate) => (predicate(file) ? [file] : []),
  );
}

describe("recorded polish word lists", () => {
  it.each([
    'static W: LazyLock<Vec<&str>> = LazyLock::new(|| vec!["a", "b"]);',
    'static W: LazyLock<HashSet<&str>> = LazyLock::new(|| ["a", "b"].into_iter().collect());',
    'fn f() -> &\'static [&\'static str] { &["a", "b"] }',
    'fn f(w: &str) -> bool { matches!(w, "a" | "b") }',
  ])("rejects a wrapped vocabulary: %s", (source) => {
    // Wrappers and literal match alternatives can conceal a vocabulary outside the recorded file.
    expect(run(source)).toHaveLength(1);
    expect(run(`// technical vocabulary: https://example.org/spec\n${source}`)).toEqual([]);
  });
  it("excludes test functions and permits attributes after a source marker", () => {
    // Test-only helpers and annotated items with attributes must not be reported as production lists.
    expect(run('#[cfg(test)] fn helper() { let w = ["a", "b"]; }')).toEqual([]);
    expect(
      run(
        '// technical vocabulary: https://example.org/spec\n#[allow(dead_code)]\nconst W: &[&str] = &["a", "b"];',
      ),
    ).toEqual([]);
  });
  it("rejects a constant word array with its source line", () => {
    // A constant dictionary can bypass the recorded provenance file.
    expect(run('// vocabulary\nconst TIER_1_WORDS: &[&str] = &["seamlessly", "elevate"];')).toEqual(
      [expect.stringContaining(`${FILE}:2`)],
    );
  });
  it("rejects a local marker array", () => {
    // A local word list can evade a check limited to constants.
    expect(run('fn check() {\n let markers = ["a", "b"];\n}')).toHaveLength(1);
  });
  it("accepts a sourced technical vocabulary", () => {
    // A technical vocabulary with a source annotation must remain allowed.
    expect(
      run('// technical vocabulary: https://example.org/spec\nlet markers = ["a", "b"];'),
    ).toEqual([]);
  });
  it("excludes test modules while checking production after them", () => {
    // Test fixtures can look like dictionaries, and production can follow a test module.
    expect(run('#[cfg(test)] mod tests { fn x() { let markers = ["a", "b"]; } }')).toEqual([]);
    expect(run('#[cfg(test)] mod tests {}\nlet markers = ["a", "b"];')).toHaveLength(1);
  });
  it("ignores test files, comments, strings, and non-string arrays", () => {
    // Apparent declarations inside inert text or other array types are not word lists.
    expect(run('let words = ["a", "b"];', FILE.replace("copy_content.rs", "tests.rs"))).toEqual([]);
    expect(
      run(
        '// let words = ["a", "b"];\nlet text = r#"const X = ["a", "b"];"#;\nlet chars = [\'a\', \'b\'];\nlet pairs = [("a", 1), ("b", 2)];',
      ),
    ).toEqual([]);
  });
  it("rejects static, mutable, raw-string, and multiline arrays", () => {
    // Alternative Rust array spellings can hide an unsourced vocabulary.
    for (const source of [
      'static WORDS: &[&str] = &["a", "b"];',
      'let mut markers = [r#"a"#, r"b"];',
      'let markers = &mut ["a", "b"];',
      'const MARKERS: [&str; 2] = ["a", "b"];',
      'let words = [\n "a",\n "b",\n];',
    ])
      expect(run(source)).toHaveLength(1);
  });
  it("checks only an immediately preceding HTTPS annotation", () => {
    // A stale or non-HTTPS comment can accidentally authorize a word list.
    expect(
      run('// technical vocabulary: http://example.org/spec\nlet x = ["a", "b"];'),
    ).toHaveLength(1);
    expect(
      run('// technical vocabulary: https://example.org/spec\n\nlet x = ["a", "b"];'),
    ).toHaveLength(1);
  });
  it("accepts the real production tree", () => {
    // A production word list can remain outside the recorded file.
    const io = repoGuardrailIo(process.cwd());
    expect(polishWordListFailures(io.read, io.exists, io.listFiles)).toEqual([]);
  });
});
