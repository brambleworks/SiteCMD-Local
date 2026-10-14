// A hosted runner that dispatches through an associated `evaluate` stays in the
// desktop-registration parity, as a `.run` dispatch does.

import { describe, expect, it } from "vitest";

import {
  REGISTRATION,
  REGISTRATION_BASE,
  RUNNERS_SEO,
  RUNNERS_SEO_BASE,
  run,
} from "./lib/engine-artifact-test-fixtures.mjs";

const flags = (failures, fragment) => failures.some((failure) => failure.includes(fragment));

const EVALUATED = RUNNERS_SEO_BASE.replace(
  "meta::ViewportCheck.run(inputs.page)",
  "meta::ViewportCheck::evaluate(inputs.page, inputs.header_lines)",
);

describe("a runner dispatched through `::evaluate`", () => {
  it("reads as a dispatch, so its registered check passes", () => {
    expect(run({ [RUNNERS_SEO]: EVALUATED })).toEqual([]);
  });

  it("fails the parity when its desktop registration is deleted", () => {
    const failures = run({
      [RUNNERS_SEO]: EVALUATED,
      [REGISTRATION]: REGISTRATION_BASE.replace("        Box::new(meta::ViewportCheck),\n", ""),
    });
    expect(flags(failures, "not registered in any desktop")).toBe(true);
  });
});

describe("runner dispatch coverage", () => {
  it.each(["::grade", ".evaluate"])("counts an unread %s dispatch", (dispatch) => {
    // An unread call must count or a missing registration silently escapes parity.
    const failures = run({
      [RUNNERS_SEO]: RUNNERS_SEO_BASE.replace(
        "meta::ViewportCheck.run(inputs.page)",
        `meta::ViewportCheck${dispatch}(inputs.page)`,
      ),
      [REGISTRATION]: REGISTRATION_BASE.replace("        Box::new(meta::ViewportCheck),\n", ""),
    });
    expect(flags(failures, "runner-extraction pattern")).toBe(true);
  });
});
