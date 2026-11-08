// An empty exclusion table makes the parser read later code as exclusions.

import { expect, it } from "vitest";
import {
  claimedChecks,
  excludedChecks,
  isPreviewOnlySources,
  runnerDispatches,
} from "./lib/guardrail-engine-lane-parsing.mjs";

import {
  RUNNERS,
  RUNNERS_BASE,
  REGISTRATION,
  REGISTRATION_BASE,
  run,
} from "./lib/engine-artifact-test-fixtures.mjs";

it.each([
  ["missing emitters", undefined, false],
  ["no emitters", [], false],
  [
    "only engine preview emitters",
    ["apps/desktop/src-tauri/crates/engine/src/checks/predeploy/mod.rs"],
    true,
  ],
  ["runtime preview emitters", ["apps/desktop/src-tauri/src/checks/predeploy/mod.rs"], false],
  [
    "a lookalike engine directory",
    ["apps/desktop/src-tauri/crates/engine/src/checks/predeploy_extra/mod.rs"],
    false,
  ],
  [
    "preview and live emitters",
    [
      "apps/desktop/src-tauri/crates/engine/src/checks/predeploy/mod.rs",
      "apps/desktop/src-tauri/crates/engine/src/checks/seo/meta.rs",
    ],
    false,
  ],
])("classifies %s with the shared preview predicate", (_name, files, expected) => {
  // Empty or non-preview emitters incorrectly exempt a live-site check from hosted coverage.
  expect(isPreviewOnlySources(files)).toBe(expected);
});

it.each(["&[];", "&[\n];"])("stops at an empty table written %s", (table) => {
  const source = `pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = ${table}\nconst LATER: (&str, &str) = ("later.check", "not an exclusion");`;
  expect(excludedChecks(source, "EXCLUDED_PROBE_CHECKS")).toEqual([]);
});

// A row whose own code holds `];` cuts the table short and drops later rows.
it("reads past a row whose own code holds ];", () => {
  const source = `pub const RUNNERS: &[Runner] = &[\n    Runner { covers: &["a.check"], run: |inputs| { let _ = vec![1]; a(inputs) } },\n    Runner { covers: &["b.check"], run: |inputs| b(inputs) },\n];`;
  expect(claimedChecks(source, "pub const RUNNERS")).toEqual(["a.check", "b.check"]);
});

it("maps the HTTP/2 fact runner to the registered Http2Check", () => {
  // A fact-aware method call must remain subject to desktop registration parity.
  const runner = `Runner {
    covers: &["performance.http2"],
    run: |inputs| crate::checks::performance::protocol::Http2Check.run_with_protocol(inputs.page, inputs.negotiated_protocol),
  },`;
  const source = `pub const RUNNERS: &[Runner] = &[
${runner}
];`;
  expect(runnerDispatches(source, "pub const RUNNERS")).toEqual({
    types: ["Http2Check"],
    invocations: 1,
  });
  const runners = RUNNERS_BASE.replace(
    "pub const RUNNERS: &[Runner] = &[",
    `pub const RUNNERS: &[Runner] = &[
${runner}`,
  );
  expect(
    run({
      [RUNNERS]: runners,
      [REGISTRATION]: `${REGISTRATION_BASE}
Box::new(Http2Check)`,
    }),
  ).toEqual([]);
  expect(run({ [RUNNERS]: runners }).join("\n")).toContain("Http2Check");
});
