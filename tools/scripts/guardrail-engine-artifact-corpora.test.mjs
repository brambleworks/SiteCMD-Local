import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { repoGuardrailIo } from "./check-repo-guardrails.mjs";
import { engineArtifactFailures } from "./lib/guardrail-engine-artifact-rules.mjs";
import { CHECKS_SCRIPT, SCORER_SCRIPT } from "./lib/engine-artifact-test-fixtures.mjs";

const { read: readRepo, listFiles } = repoGuardrailIo(
  fileURLToPath(new URL("../../", import.meta.url)),
);

function failuresFor(file, from, to) {
  const source = readRepo(file);
  expect(source).toContain(from);
  return engineArtifactFailures(
    (name) => (name === file ? source.replace(from, to) : readRepo(name)),
    listFiles,
  );
}

describe("vendored native corpora", () => {
  it("accepts each corpus embedded by its native replay", () => {
    expect(engineArtifactFailures(readRepo, listFiles)).toEqual([]);
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
