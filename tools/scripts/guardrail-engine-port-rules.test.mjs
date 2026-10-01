import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { enginePortFailures } from "./lib/guardrail-engine-port-rules.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const RUNTIME_POLICY = "apps/desktop/src-tauri/src/core/severity_policy.rs";
const ENGINE_POLICY = "apps/desktop/src-tauri/crates/engine/src/severity_policy/mod.rs";
const RUNTIME_DETECTOR = "apps/desktop/src-tauri/src/core/detector.rs";
const WASM_LIB = "apps/desktop/src-tauri/crates/engine-wasm/src/lib.rs";
const SCORER_SCRIPT = "tools/scripts/build-scorer-wasm.mjs";
const CHECKS_SCRIPT = "tools/scripts/build-checks-wasm.mjs";
const PORTED_SCRIPT = "tools/scripts/vendor-ported-fixtures.mjs";
const PARITY_DIR = "apps/desktop/src-tauri/tests/fixtures/parity";
const read = (file) => readFileSync(path.join(ROOT, file), "utf8");
function listFiles(dir, predicate) {
  return readdirSync(path.join(ROOT, dir), { withFileTypes: true }).flatMap((entry) => {
    const file = `${dir}/${entry.name}`;
    return entry.isDirectory() ? listFiles(file, predicate) : predicate(file) ? [file] : [];
  });
}
const failures = (overrides = {}, list = listFiles) =>
  enginePortFailures((file) => overrides[file] ?? read(file), list);

describe("enginePortFailures", () => {
  it("accepts the engine policy and runtime adapters", () => {
    expect(failures()).toEqual([]);
  });

  it("rejects a severity table in the runtime", () => {
    const source = `${read(RUNTIME_POLICY)}\n"seo.title" => Severity::Medium,\n`;
    expect(failures({ [RUNTIME_POLICY]: source })).toEqual([
      expect.stringContaining(ENGINE_POLICY),
    ]);
  });

  it("requires the runtime to delegate to the engine policy", () => {
    const source = read(RUNTIME_POLICY);
    expect(source).toContain("sitecmd_engine::severity_policy");
    expect(
      failures({
        [RUNTIME_POLICY]: source.replaceAll("sitecmd_engine::severity_policy", "other_policy"),
      }),
    ).toEqual([expect.stringContaining("must delegate to sitecmd_engine::severity_policy")]);
  });

  it("requires the engine batch entry point", () => {
    const source = read(ENGINE_POLICY);
    expect(source).toContain("pub fn apply(");
    expect(
      failures({ [ENGINE_POLICY]: source.replace("pub fn apply(", "pub fn evaluate(") }),
    ).toEqual([expect.stringContaining("must keep `apply`")]);
  });

  it("rejects a local grade when a doc comment and a pub use re-export remain", () => {
    const source = read(RUNTIME_POLICY).replace(/^use sitecmd_engine::severity_policy.*\n/gm, "");
    expect(source).toContain("sitecmd_engine::severity_policy");
    expect(source).toContain("pub use sitecmd_engine::severity_policy::polish_signal_severity;");
    const mutant = `${source}\nfn grade() -> Severity { Severity::Low }\n`;
    expect(failures({ [RUNTIME_POLICY]: mutant })).toEqual([
      expect.stringContaining("must delegate to sitecmd_engine::severity_policy"),
      expect.stringContaining(ENGINE_POLICY),
    ]);
  });

  it("rejects a severity regrade in a runtime conditional", () => {
    const source = `${read(RUNTIME_POLICY)}\nif result.check_id == "seo.title" { result.severity = Severity::High; }\n`;
    expect(failures({ [RUNTIME_POLICY]: source })).toEqual([
      expect.stringContaining(ENGINE_POLICY),
    ]);
  });

  it("rejects a runtime regrade through an aliased severity", () => {
    const source = `${read(RUNTIME_POLICY)}\nuse crate::checks::Severity as Sev;\nif result.check_id == "seo.title" { return Sev::High; }\n`;
    expect(failures({ [RUNTIME_POLICY]: source })).toEqual([
      expect.stringContaining(ENGINE_POLICY),
    ]);
  });

  it("rejects a runtime severity table expressed with matches", () => {
    const source = `${read(RUNTIME_POLICY)}\nlet high = matches!(severity, Severity::High | Severity::Critical);\n`;
    expect(failures({ [RUNTIME_POLICY]: source })).toEqual([
      expect.stringContaining(ENGINE_POLICY),
    ]);
  });

  it("rejects a runtime CMS detector", () => {
    const source = `${read(RUNTIME_DETECTOR)}\nfn detect_cms() {}\n`;
    expect(failures({ [RUNTIME_DETECTOR]: source })).toEqual([
      expect.stringContaining("must re-export sitecmd_engine::stack"),
    ]);
  });

  it("requires the engine detector re-export", () => {
    expect(failures({ [RUNTIME_DETECTOR]: "" })).toEqual([
      expect.stringContaining("must re-export sitecmd_engine::stack"),
    ]);
  });

  it("rejects a commented-out engine detector re-export", () => {
    const source = read(RUNTIME_DETECTOR);
    expect(source).toMatch(/^pub use sitecmd_engine::stack::/m);
    const mutant = source.replace(
      /^pub use sitecmd_engine::stack::/m,
      "// pub use sitecmd_engine::stack::",
    );
    expect(failures({ [RUNTIME_DETECTOR]: mutant })).toEqual([
      expect.stringContaining("must re-export sitecmd_engine::stack"),
    ]);
  });

  it("requires the severity export", () => {
    const source = read(WASM_LIB).replace(/severity_apply/g, "other_apply");
    expect(failures({ [WASM_LIB]: source })).toEqual([
      expect.stringContaining("no longer exports `severity_apply`"),
    ]);
  });

  it("rejects a severity export behind the checks feature", () => {
    const source =
      '#[cfg(feature = "checks")]\n#[no_mangle]\npub unsafe extern "C" fn severity_apply(';
    expect(failures({ [WASM_LIB]: source })).toEqual([
      expect.stringContaining("`severity_apply` is behind the checks feature"),
    ]);
  });

  it("rejects a commented-out severity export", () => {
    const source = '// pub unsafe extern "C" fn severity_apply(';
    expect(failures({ [WASM_LIB]: source })).toEqual([
      expect.stringContaining("no longer exports `severity_apply`"),
    ]);
  });

  it("keeps the default severity export independent of a previous item's feature", () => {
    const source = [
      '#[cfg(feature = "checks")]',
      'pub unsafe extern "C" fn engine_evaluate() {}',
      "",
      "#[no_mangle]",
      'pub unsafe extern "C" fn severity_apply(',
    ].join("\n");
    expect(failures({ [WASM_LIB]: source })).toEqual([]);
  });

  it.each([
    [SCORER_SCRIPT, "severity-golden.json", "severity"],
    [CHECKS_SCRIPT, "stack-golden.json", "stack"],
  ])("requires %s to vendor its corpus", (file, name, kind) => {
    const source = read(file).replaceAll(name, "other-golden.json");
    expect(failures({ [file]: source })).toEqual([
      expect.stringContaining(`must vendor the ${kind} corpus and record its digest`),
    ]);
  });

  it.each([
    [SCORER_SCRIPT, "severity"],
    [CHECKS_SCRIPT, "stack"],
  ])("requires %s to record its corpus digest", (file, kind) => {
    const source = read(file).replace(`${kind}_corpus_sha256:`, "other_corpus_sha256:");
    expect(failures({ [file]: source })).toEqual([
      expect.stringContaining(`must vendor the ${kind} corpus and record its digest`),
    ]);
  });

  it.each([
    [SCORER_SCRIPT, "severity-golden.json", "severity"],
    [CHECKS_SCRIPT, "stack-golden.json", "stack"],
  ])("rejects a commented-out corpus in %s", (file, name, kind) => {
    const source = read(file).replace(
      new RegExp(`^\\s*\\{ name: "${name.replace(".", "\\.")}".*$`, "m"),
      (line) => `// ${line}`,
    );
    expect(failures({ [file]: source })).toEqual([
      expect.stringContaining(`must vendor the ${kind} corpus and record its digest`),
    ]);
  });

  it.each([
    [SCORER_SCRIPT, "severity"],
    [CHECKS_SCRIPT, "stack"],
  ])("rejects a commented-out corpus digest in %s", (file, kind) => {
    const source = read(file).replace(
      new RegExp(`^\\s*${kind}_corpus_sha256:.*$`, "m"),
      (line) => `// ${line}`,
    );
    expect(failures({ [file]: source })).toEqual([
      expect.stringContaining(`must vendor the ${kind} corpus and record its digest`),
    ]);
  });

  it.each([SCORER_SCRIPT, CHECKS_SCRIPT, PORTED_SCRIPT])(
    "requires %s to default to Connect",
    (file) => {
      const source = read(file).replace(
        /outDirFrom\(args, \["[^"]+",/,
        'outDirFrom(args, ["Elsewhere",',
      );
      expect(failures({ [file]: source })).toEqual([
        expect.stringContaining("must default to the SiteCMD-Connect checkout"),
      ]);
    },
  );
});

describe("ported corpus vendoring", () => {
  it.each([
    "event_correlations.json",
    "event_correlations_boundaries.json",
    "regression_blame.json",
    "work_item_projection.json",
    "work_item_projection_boundaries.json",
    "fix_brief.json",
    "check_aliases.json",
  ])("requires the included corpus %s", (corpus) => {
    const source = read(PORTED_SCRIPT).replace(
      new RegExp(`^\\s*(?:\\{ )?source: "${corpus.replaceAll(".", "\\.")}",.*$`, "m"),
      "",
    );
    expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
      expect.stringContaining(`does not vendor ${corpus}`),
    ]);
  });

  it("requires every JSON file in the corpus folder", () => {
    const file = `${PARITY_DIR}/nested/New-logic2.json`;
    const list = (dir, predicate) => [
      ...listFiles(dir, predicate),
      ...(dir === PARITY_DIR && predicate(file) ? [file] : []),
    ];
    expect(failures({}, list)).toEqual([
      expect.stringContaining("does not vendor nested/New-logic2.json"),
    ]);
  });

  it("rejects a vendored source with no corpus file", () => {
    const source = read(PORTED_SCRIPT).replace(
      "const PORTED = [",
      'const PORTED = [\n  { source: "missing.json", name: "missing-golden.json" },',
    );
    expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
      expect.stringContaining("vendors missing.json but no corpus file exists"),
    ]);
  });

  it.each(["fix_brief.json", "event_correlations_boundaries.json"])(
    "rejects a commented source entry for %s",
    (corpus) => {
      const source = read(PORTED_SCRIPT).replace(
        new RegExp(`^\\s*(?:\\{ )?source: "${corpus.replaceAll(".", "\\.")}",.*$`, "m"),
        (line) => `// ${line}`,
      );
      expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
        expect.stringContaining(`does not vendor ${corpus}`),
      ]);
    },
  );

  it.each(["writeFileSync", "copyFileSync"])("rejects writing with %s", (writer) => {
    const source = `${read(PORTED_SCRIPT)}\n${writer}("destination", "bytes");\n`;
    expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
      expect.stringContaining("must write the set through one vendorSet call"),
    ]);
  });

  it("requires the shared set writer", () => {
    const source = read(PORTED_SCRIPT).replaceAll("vendorSet(", "otherWriter(");
    expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
      expect.stringContaining("must write the set through one vendorSet call"),
    ]);
  });

  it("requires the dirty-tree check", () => {
    const source = read(PORTED_SCRIPT).replaceAll("engineTreeSuffix(", "otherSuffix(");
    expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
      expect.stringContaining("must check its dirty scope"),
    ]);
  });
});

describe("vendoring provenance", () => {
  it.each([SCORER_SCRIPT, CHECKS_SCRIPT, PORTED_SCRIPT])(
    "rejects a constant dirty suffix in %s",
    (file) => {
      const source = read(file).replace(
        /const dirtySuffix = engineTreeSuffix\([\s\S]*?\);/,
        'const dirtySuffix = "";',
      );
      expect(failures({ [file]: source })).toEqual([
        expect.stringContaining(`${file} must check its dirty scope`),
      ]);
    },
  );

  it.each([SCORER_SCRIPT, CHECKS_SCRIPT, PORTED_SCRIPT])(
    "requires %s to carry the dirty suffix in its commit",
    (file) => {
      const source = read(file).replace(" + dirtySuffix,", ",");
      expect(failures({ [file]: source })).toEqual([
        expect.stringContaining(`${file} must carry + dirtySuffix`),
      ]);
    },
  );

  it("rejects the default crate scope for the ported corpora", () => {
    const source = read(PORTED_SCRIPT).replace(
      /engineTreeSuffix\(allowDirty, \[[\s\S]*?\]\)/,
      "engineTreeSuffix(allowDirty)",
    );
    expect(failures({ [PORTED_SCRIPT]: source })).toEqual([
      expect.stringContaining("must check its dirty scope"),
    ]);
  });

  it.each([SCORER_SCRIPT, CHECKS_SCRIPT])("rejects a crate-only scope in %s", (file) => {
    const source = read(file).replace(
      /engineTreeSuffix\([^;]*\)/,
      'engineTreeSuffix(allowDirty, ["apps/desktop/src-tauri/crates"])',
    );
    expect(failures({ [file]: source })).toEqual([
      expect.stringContaining(`${file} must check its dirty scope`),
    ]);
  });

  it.each([SCORER_SCRIPT, CHECKS_SCRIPT])("rejects a scope without generators in %s", (file) => {
    const source = read(file).replace(
      /engineTreeSuffix\([^;]*\)/,
      'engineTreeSuffix(allowDirty, ["apps/desktop/src-tauri"])',
    );
    expect(failures({ [file]: source })).toEqual([
      expect.stringContaining(`${file} must check its dirty scope`),
    ]);
  });

  it.each([SCORER_SCRIPT, CHECKS_SCRIPT, PORTED_SCRIPT])(
    "rejects a commented dirty check in %s",
    (file) => {
      const source = read(file).replace(/^const dirtySuffix =/m, "// const dirtySuffix =");
      expect(failures({ [file]: source })).toEqual([
        expect.stringContaining(`${file} must check its dirty scope`),
      ]);
    },
  );

  it.each([SCORER_SCRIPT, CHECKS_SCRIPT, PORTED_SCRIPT])(
    "rejects a commented engine commit in %s",
    (file) => {
      const source = read(file).replace(/^(\s*)engine_commit:/m, "$1// engine_commit:");
      expect(failures({ [file]: source })).toEqual([
        expect.stringContaining(`${file} must carry + dirtySuffix`),
      ]);
    },
  );
});
