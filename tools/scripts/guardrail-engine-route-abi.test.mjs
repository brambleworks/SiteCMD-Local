// The wasm crate exports only the supported ABI and authors none of the
// route request shapes itself.

import { describe, expect, it } from "vitest";

import {
  ROUTE_SCHEMA,
  ROUTE_SCHEMA_BASE,
  WASM_LIB,
  WASM_LIB_BASE,
  gated,
  run,
} from "./lib/engine-artifact-test-fixtures.mjs";

const flags = (failures, fragment) => failures.some((failure) => failure.includes(fragment));

describe("the route ABI", () => {
  it.each(["engine_evaluate", "engine_probe_plan", "engine_session_page"])(
    "refuses a page-carrying export %s beside the route calls",
    (symbol) => {
      const failures = run({ [WASM_LIB]: `${WASM_LIB_BASE}\n\n${gated(symbol)}` });
      expect(flags(failures, `exports \`${symbol}\`, which the scan worker does not call`)).toBe(
        true,
      );
    },
  );

  it("refuses an extra export without the engine prefix", () => {
    const failures = run({ [WASM_LIB]: `${WASM_LIB_BASE}\n\n${gated("checks_evaluate")}` });
    expect(flags(failures, "exports `checks_evaluate`, which the scan worker does not call")).toBe(
      true,
    );
  });

  it.each(["RouteOpenRequest", "RouteCall", "RouteEvaluationRequest", "RouteSessionPageRequest"])(
    "refuses a route request %s the engine crate stopped defining",
    (type) => {
      const failures = run({ [ROUTE_SCHEMA]: ROUTE_SCHEMA_BASE.replace(`struct ${type} {`, "") });
      expect(flags(failures, `no longer defines \`struct ${type}\``)).toBe(true);
    },
  );

  it("refuses a route request the wasm crate defines itself", () => {
    const failures = run({ [WASM_LIB]: `${WASM_LIB_BASE}\npub struct RouteCall {}` });
    expect(flags(failures, "defines `struct RouteCall` itself")).toBe(true);
  });
});
