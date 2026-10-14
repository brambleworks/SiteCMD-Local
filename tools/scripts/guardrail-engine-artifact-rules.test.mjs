import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { engineArtifactFailures } from "./lib/guardrail-engine-artifact-rules.mjs";

import {
  WASM_LIB,
  WASM_MANIFEST,
  RUNNERS,
  RUNNERS_SEO,
  PROBE_CHECKS,
  PROBE_SCHEMA,
  SCHEMA,
  SESSION,
  MANIFEST,
  CHECKS_SCRIPT,
  SCORER_SCRIPT,
  gated,
  WASM_LIB_BASE,
  WASM_MANIFEST_BASE,
  SCHEMA_BASE,
  RUNNERS_BASE,
  RUNNERS_SEO_BASE,
  PROBE_CHECKS_BASE,
  PROBE_SCHEMA_BASE,
  REGISTRATION,
  REGISTRATION_BASE,
  CHECKS_SCRIPT_BASE,
  SCORER_SCRIPT_BASE,
  run,
} from "./lib/engine-artifact-test-fixtures.mjs";

const flags = (failures, fragment) => failures.some((failure) => failure.includes(fragment));

describe("engineArtifactFailures", () => {
  it("accepts a tree where every rule holds", () => {
    expect(run()).toEqual([]);
  });

  it.each(["&[]", '&["seo.orphan_pages", "seo.unlisted"]', ""])(
    "rejects an inconsistent session list %s",
    (ids) => {
      const failures = run({ [SESSION]: `pub const SESSION_CHECK_IDS: &[&str] = ${ids};` });
      expect(failures.join("\n")).toContain(ids ? "session checks disagree" : "no longer declares");
    },
  );

  it("rejects a missing session export", () => {
    const failures = run({
      [WASM_LIB]: WASM_LIB_BASE.replace(gated("engine_session_evaluate"), ""),
    });
    expect(flags(failures, "no longer exports `engine_session_evaluate`")).toBe(true);
  });

  it("rejects a renamed scorer ABI symbol the connect worker resolves by name", () => {
    const failures = run({
      [WASM_LIB]: WASM_LIB_BASE.replace('extern "C" fn scorer_score(', 'extern "C" fn evaluate('),
    });
    expect(flags(failures, "no longer exports `scorer_score`")).toBe(true);
  });

  it("rejects a route export that is not behind the checks feature", () => {
    const failures = run({
      [WASM_LIB]: WASM_LIB_BASE.replace('#[cfg(feature = "checks")]\n', ""),
    });
    expect(flags(failures, "is not behind")).toBe(true);
  });

  it("rejects a missing evaluate export", () => {
    const failures = run({
      [WASM_LIB]: WASM_LIB_BASE.replace(
        'pub unsafe extern "C" fn engine_route_evaluate(ptr: *mut u8, len: u32) -> *const u8 {}',
        "",
      ),
    });
    expect(flags(failures, "no longer exports `engine_route_evaluate`")).toBe(true);
  });

  it("rejects a default feature set that would change connect's vendored artifact", () => {
    const failures = run({
      [WASM_MANIFEST]: WASM_MANIFEST_BASE.replace("default = []", 'default = ["checks"]'),
    });
    expect(flags(failures, "default feature set must stay empty")).toBe(true);
  });

  it("rejects removing the checks feature that separates the two artifacts", () => {
    const failures = run({
      [WASM_MANIFEST]: WASM_MANIFEST_BASE.replace("checks = []", ""),
    });
    expect(flags(failures, "the `checks` feature is gone")).toBe(true);
  });

  it("rejects a request schema redefined inside the wasm wrapper", () => {
    const failures = run({
      [WASM_LIB]: `${WASM_LIB_BASE}\nstruct EvaluationRequest { page: PageArtifact }`,
    });
    expect(flags(failures, "authored in the engine crate")).toBe(true);
  });

  it("rejects an engine crate that lost the not-evaluated vocabulary", () => {
    const failures = run({
      [SCHEMA]: SCHEMA_BASE.replace("pub enum NotEvaluatedReason {", "pub enum Unused {"),
    });
    expect(flags(failures, "NotEvaluatedReason")).toBe(true);
  });

  it("rejects an artifact-lane check with no runner and no documented exclusion", () => {
    const failures = run({
      [RUNNERS]: RUNNERS_BASE.replace('covers: &["performance.page_weight"]', 'covers: &["x.y"]'),
    });
    expect(flags(failures, "performance.page_weight")).toBe(true);
  });

  it("rejects an id claimed by two runners", () => {
    const failures = run({
      [RUNNERS]: RUNNERS_BASE.replace(
        'covers: &["performance.page_weight"]',
        'covers: &["performance.page_weight", "security.mixed_content"]',
      ),
    });
    expect(flags(failures, "claimed by more than one runner")).toBe(true);
  });

  it("rejects an exclusion with no reason", () => {
    const failures = run({
      [RUNNERS_SEO]: RUNNERS_SEO_BASE.replace(
        '("seo.headings.h1", "HeadingCheck is unregistered on the desktop")',
        '("seo.headings.h1", "")',
      ),
    });
    expect(flags(failures, "carry no reason")).toBe(true);
  });

  it("flags the rules as stale when the runner table is renamed away", () => {
    const failures = run({ [RUNNERS]: "pub const TABLE: &[Runner] = &[];" });
    expect(flags(failures, "update these rules with them")).toBe(true);
  });

  it("flags the rules as stale when the SEO runner table is renamed away", () => {
    const failures = run({
      [RUNNERS_SEO]: RUNNERS_SEO_BASE.replace("pub const SEO_RUNNERS", "pub const OTHER"),
    });
    expect(flags(failures, "`SEO_RUNNERS`")).toBe(true);
  });

  it("rejects vendoring a corpus other than the one the golden test embeds", () => {
    const failures = run({
      [CHECKS_SCRIPT]: CHECKS_SCRIPT_BASE.replace('"fixtures", "checks"', '"generated", "hosted"'),
    });
    expect(flags(failures, "does not vendor the corpus")).toBe(true);
  });

  it("rejects a build script that writes a vendored file directly", () => {
    const failures = run({
      [CHECKS_SCRIPT]: `${CHECKS_SCRIPT_BASE}\nwriteFileSync(path.join(outDir, "extra.json"), "{}");`,
    });
    expect(flags(failures, "writes a vendored file directly")).toBe(true);
  });

  it("rejects a checks artifact that omits the shared browser payloads", () => {
    const failures = run({
      [CHECKS_SCRIPT]: CHECKS_SCRIPT_BASE.replace(
        '{ name: "browser-assets.json", bytes: browserAssets },',
        "",
      ),
    });
    expect(flags(failures, "browser instrumentation payloads")).toBe(true);
  });

  it("rejects a build script that hardcodes the axe version beside the shared payload", () => {
    const failures = run({
      [CHECKS_SCRIPT]: CHECKS_SCRIPT_BASE.replace(
        "axe_core_version: browserPayload.axe_core_version,",
        'axe_core_version: "4.11.2",',
      ),
    });
    expect(flags(failures, "axe version from the shared browser payload")).toBe(true);
  });

  it("rejects a build script that stops vendoring through the atomic writer", () => {
    const failures = run({
      [SCORER_SCRIPT]: SCORER_SCRIPT_BASE.replace("vendorSet(", "emitFiles("),
    });
    expect(flags(failures, "does not vendor through")).toBe(true);
  });

  it.each(["corpus_sha256", "session_corpus_sha256"])(
    "rejects a provenance record missing %s",
    (field) => {
      const failures = run({
        [CHECKS_SCRIPT]: CHECKS_SCRIPT_BASE.replace(new RegExp(`^  ${field}:.*\\n`, "m"), ""),
      });
      expect(flags(failures, field)).toBe(true);
    },
  );

  it("rejects a hosted runner for a check no desktop scan registers", () => {
    const failures = run({ [REGISTRATION]: "pub fn sync_checks() { vec![] }" });
    expect(flags(failures, "not registered in any desktop")).toBe(true);
  });

  it("rejects a brace-wrapped hosted runner whose desktop registration was deleted", () => {
    const failures = run({
      [REGISTRATION]: REGISTRATION_BASE.replace(
        "        Box::new(cross_origin::CrossOriginIsolationCheck),\n",
        "",
      ),
    });
    expect(flags(failures, "not registered in any desktop")).toBe(true);
    expect(flags(failures, "CrossOriginIsolationCheck")).toBe(true);
    expect(flags(failures, "MixedContentCheck")).toBe(false);
  });

  it("rejects an SEO hosted runner whose desktop registration was deleted", () => {
    const failures = run({
      [REGISTRATION]: REGISTRATION_BASE.replace("        Box::new(meta::ViewportCheck),\n", ""),
    });
    expect(flags(failures, "not registered in any desktop")).toBe(true);
    expect(flags(failures, "ViewportCheck")).toBe(true);
  });

  it("rejects a runner formatting the extraction cannot read rather than exempting it", () => {
    const failures = run({
      [RUNNERS]: RUNNERS_BASE.replace(
        "        run: |inputs| MixedContentCheck.run(inputs.page),",
        ["        run: |inputs|", "            MixedContentCheck.run(inputs.page),"].join("\n"),
      ),
    });
    expect(flags(failures, "reads 2 of the 3 check invocations")).toBe(true);
  });

  it("does not read a covers list below the table terminator as a claim", () => {
    const failures = run({
      [RUNNERS]: [
        RUNNERS_BASE.replace('covers: &["performance.page_weight"]', 'covers: &["config.robots"]'),
        "",
        "fn page_weight_example() -> Runner {",
        "    // The row this replaced used to read:",
        '    //     covers: &["performance.page_weight"],',
        "    unimplemented!()",
        "}",
      ].join("\n"),
    });
    expect(flags(failures, "performance.page_weight")).toBe(true);
  });

  it("rejects vendoring worker TypeScript through the artifact path", () => {
    const failures = run({
      [CHECKS_SCRIPT]: CHECKS_SCRIPT_BASE.replace(
        '{ name: "golden.json", bytes: corpus },',
        '{ name: "golden.json", bytes: corpus },\n    { name: "csp-check.ts", bytes: source },',
      ),
    });
    expect(flags(failures, "reimplementation the parity contract exists to forbid")).toBe(true);
  });

  it("reports an unparseable capability manifest rather than passing silently", () => {
    const failures = run({ [MANIFEST]: "{ not json" });
    expect(flags(failures, "unparseable")).toBe(true);
  });

  it("rejects a missing probe-plan export", () => {
    const failures = run({
      [WASM_LIB]: WASM_LIB_BASE.replace(gated("engine_route_plan"), ""),
    });
    expect(flags(failures, "no longer exports `engine_route_plan`")).toBe(true);
  });

  it("rejects a probe-plan export gated only by the open export's own cfg", () => {
    const failures = run({
      [WASM_LIB]: WASM_LIB_BASE.replace(
        gated("engine_route_plan"),
        gated("engine_route_plan").replace('#[cfg(feature = "checks")]\n', ""),
      ),
    });
    expect(flags(failures, "`engine_route_plan` is not behind")).toBe(true);
    expect(flags(failures, "`engine_route_open` is not behind")).toBe(false);
  });

  it("rejects a plan schema redefined inside the wasm wrapper", () => {
    const failures = run({
      [WASM_LIB]: `${WASM_LIB_BASE}\n\nstruct ProbePlan { probes: Vec<PlannedProbe> }`,
    });
    expect(flags(failures, "two definitions of one plan")).toBe(true);
  });

  it("rejects an engine crate that lost the executed-probe definition", () => {
    const failures = run({
      [PROBE_SCHEMA]: PROBE_SCHEMA_BASE.replace("pub struct ExecutedProbe {}", ""),
    });
    expect(flags(failures, "struct ExecutedProbe")).toBe(true);
  });

  it("rejects a probe-lane check with no probe check and no documented exclusion", () => {
    const failures = run({
      [PROBE_CHECKS]: PROBE_CHECKS_BASE.replace('covers: &["config.favicon"]', 'covers: &["x.y"]'),
    });
    expect(flags(failures, "config.favicon")).toBe(true);
    expect(flags(failures, "probe-lane checks have no probe check")).toBe(true);
  });

  it("rejects an id claimed by two probe checks", () => {
    const failures = run({
      [PROBE_CHECKS]: PROBE_CHECKS_BASE.replace(
        'covers: &["config.favicon"]',
        'covers: &["config.favicon", "config.favicon"]',
      ),
    });
    expect(flags(failures, "claimed by more than one probe check")).toBe(true);
  });

  it("rejects a probe exclusion with no reason", () => {
    const failures = run({
      [PROBE_SCHEMA]: PROBE_SCHEMA_BASE.replace(
        '"the robots.txt fetch is still planned by the desktop shell"',
        '""',
      ),
    });
    expect(flags(failures, "carry no reason")).toBe(true);
  });

  it("rejects an id that is both planned and excluded", () => {
    const failures = run({
      [PROBE_CHECKS]: PROBE_CHECKS_BASE.replace(
        'covers: &["config.favicon"]',
        'covers: &["config.favicon", "seo.robots_txt"]',
      ),
    });
    expect(flags(failures, "both claimed and excluded")).toBe(true);
  });

  it("flags the rules as stale when the probe table is renamed away", () => {
    const failures = run({ [PROBE_CHECKS]: "pub const TABLE: &[ProbeCheck] = &[];" });
    expect(flags(failures, "update these rules with them")).toBe(true);
  });

  it("does not demand a planner for a probe-lane check no fetch can supply", () => {
    expect(flags(run(), "security.dns.spf")).toBe(false);
  });
});

const readRepo = (file) => readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");

function failuresFor(file, from, to) {
  const source = readRepo(file);
  expect(source).toContain(from);
  return engineArtifactFailures((name) =>
    name === file ? source.replace(from, to) : readRepo(name),
  );
}

describe("vendored native corpora", () => {
  it("accepts each corpus embedded by its native replay", () => {
    expect(engineArtifactFailures(readRepo)).toEqual([]);
  });

  it("rejects a scorer artifact pointing at another corpus", () => {
    const failures = failuresFor(SCORER_SCRIPT, '"fixtures", "score"', '"fixtures", "severity"');
    expect(failures.some((failure) => failure.includes("golden_score.rs embeds"))).toBe(true);
    expect(failures.some((failure) => failure.includes("engine-wasm/tests/abi.rs embeds"))).toBe(
      true,
    );
  });

  it("rejects a score replay pointing at another corpus", () => {
    const file = "apps/desktop/src-tauri/crates/engine/tests/golden_score.rs";
    const failures = failuresFor(file, "fixtures/score/", "fixtures/severity/");
    expect(failures.some((failure) => failure.includes("golden_score.rs embeds"))).toBe(true);
  });

  it("rejects a scoring ABI replay pointing at another corpus", () => {
    const file = "apps/desktop/src-tauri/crates/engine-wasm/tests/abi.rs";
    const failures = failuresFor(file, "fixtures/score/", "fixtures/severity/");
    expect(failures.some((failure) => failure.includes("engine-wasm/tests/abi.rs embeds"))).toBe(
      true,
    );
  });

  it("rejects a severity artifact pointing at another corpus", () => {
    const failures = failuresFor(SCORER_SCRIPT, '"severity",', '"score",');
    expect(failures.some((failure) => failure.includes("golden_severity.rs embeds"))).toBe(true);
  });

  it("rejects a stack artifact pointing at another corpus", () => {
    const failures = failuresFor(CHECKS_SCRIPT, '"stack",', '"checks",');
    expect(failures.some((failure) => failure.includes("golden_stack.rs embeds"))).toBe(true);
  });
  it.each([
    ["apps/desktop/src-tauri/crates/engine-wasm/tests/severity_abi.rs", "severity", "score"],
    ["apps/desktop/src-tauri/crates/engine/tests/evaluation_policy_facts.rs", "stack", "checks"],
    ["apps/desktop/src-tauri/crates/engine/tests/golden_session.rs", "session", "checks"],
    ["apps/desktop/src-tauri/crates/engine-wasm/tests/session_abi.rs", "session", "checks"],
  ])("rejects a different corpus in %s", (file, corpus, other) => {
    expect(failuresFor(file, `fixtures/${corpus}/`, `fixtures/${other}/`)).toEqual([
      expect.stringContaining(`${file} embeds`),
    ]);
  });
});
