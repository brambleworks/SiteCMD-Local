import { describe, expect, it } from "vitest";
import { rules } from "./guardrail-test-support.mjs";

const { commentQualityFailures } = rules;

describe("commentQualityFailures", () => {
  const run = (fixture) => {
    const read = (file) => fixture[file] ?? "";
    const listFiles = (dir, predicate) =>
      Object.keys(fixture).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
    return commentQualityFailures(read, listFiles);
  };

  it("accepts comments that state things plainly", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/clean.rs":
        "// Cache the parsed value; the raw payload is re-read every tick.\nexport const x = 1;\n",
    });
    expect(failures).toEqual([]);
  });

  it("flags a filler word in a line comment", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/bad.rs":
        "// This is simply a passthrough.\nexport const y = 2;\n",
    });
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain("bad.rs:1");
    expect(failures[0]).toContain("simply");
  });

  it("flags filler in a block comment and reports the physical line", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/block.rs":
        "/**\n * A parser.\n *\n * Note that empty input yields an empty result.\n */\nexport const z = 3;\n",
    });
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain("block.rs:4");
    expect(failures[0]).toContain("note that");
  });

  it("ignores filler words inside string literals and JSX text", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/copy.rs": 'export const msg = "Simply enter your key.";\n',
      "apps/desktop/src-tauri/src/note.rs":
        "export const Note = () => <p>Basically done, of course.</p>;\n",
    });
    expect(failures).toEqual([]);
  });

  it("does not match well / lets / Let's (the false-positive trap)", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/probe.rs":
        "/// Returns a well-formed response; the cap lets callers retry.\n/// Healthy Let's Encrypt certs renew early.\npub fn probe() {}\n",
    });
    expect(failures).toEqual([]);
  });

  it("does not treat // inside a Rust raw string as a comment", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/raw.rs":
        'let url = r#"https://example.test//path basically"#;\n// A real comment is clean.\n',
    });
    expect(failures).toEqual([]);
  });

  it("respects the allow-comment-phrase marker", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/allowed.rs":
        '/// The word "simply" is the subject here. allow-comment-phrase\npub fn f() {}\n',
    });
    expect(failures).toEqual([]);
  });

  it("flags a comment that cites a maintainer-only design tool", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/deploys_fixture.rs":
        '/**\n * Deploys - Stitch "Kinetic Console" style.\n */\npub fn deploys() {}\n',
      "apps/desktop/src-tauri/src/markdown_fixture.rs":
        "// Styled to match the dark Stitch theme.\npub fn markdown() {}\n",
    });
    expect(failures).toHaveLength(2);
    expect(failures.every((f) => f.includes("cites Stitch"))).toBe(true);
  });

  it("does not flag 'stitch' used as an ordinary verb", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/cli/output.rs":
        "/// Critical plus a confirmed weaker sibling never stitch into a\n/// floor-piercing score.\npub fn score() {}\n",
    });
    expect(failures).toEqual([]);
  });

  it("scans Rust doc comments and block comments", () => {
    const failures = run({
      "apps/desktop/src-tauri/src/x.rs":
        "/* Here we recess the control. */\n.x {\n  color: red;\n}\n",
      "apps/desktop/src-tauri/src/y.rs": "//! Now we boot the loop.\npub fn y() {}\n",
    });
    expect(failures).toHaveLength(2);
    expect(failures.some((f) => f.includes("x.rs") && f.includes("here we"))).toBe(true);
    expect(failures.some((f) => f.includes("y.rs") && f.includes("now we"))).toBe(true);
  });
});
