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
  it("requires the sitemap routes export behind the checks feature", () => {
    const missing = WASM_LIB_BASE.replace(
      'extern "C" fn engine_route_sitemap_routes(',
      'extern "C" fn omitted_sitemap_routes(',
    );
    expect(
      flags(run({ [WASM_LIB]: missing }), "no longer exports `engine_route_sitemap_routes`"),
    ).toBe(true);
    const ungated = WASM_LIB_BASE.replace(
      gated("engine_route_sitemap_routes"),
      gated("engine_route_sitemap_routes").replace('#[cfg(feature = "checks")]\n', ""),
    );
    expect(flags(run({ [WASM_LIB]: ungated }), "`engine_route_sitemap_routes` is not behind")).toBe(
      true,
    );
  });

  it.each(["request.rs", "nested/wire.rs"])("refuses an extra export in %s", (name) => {
    const file = WASM_LIB.replace("lib.rs", name);
    const failures = run({ [file]: gated("checks_evaluate") });
    expect(flags(failures, `${file} exports \`checks_evaluate\``)).toBe(true);
  });

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

  it.each([
    "RouteOpenRequest",
    "RouteCall",
    "RouteEvaluationRequest",
    "RouteSessionPageRequest",
    "RouteDiscoverRequest",
    "RouteSitemapRoutesRequest",
  ])("refuses a route request %s the engine crate stopped defining", (type) => {
    const failures = run({ [ROUTE_SCHEMA]: ROUTE_SCHEMA_BASE.replace(`struct ${type} {`, "") });
    expect(flags(failures, `no longer defines \`struct ${type}\``)).toBe(true);
  });

  it.each(["lib.rs", "request.rs", "nested/wire.rs"])(
    "refuses a route request defined in %s",
    (name) => {
      const file = WASM_LIB.replace("lib.rs", name);
      const failures = run({
        [file]: `${name === "lib.rs" ? WASM_LIB_BASE : ""}\npub struct RouteCall {}`,
      });
      expect(flags(failures, "defines `struct RouteCall` itself")).toBe(true);
    },
  );
});
