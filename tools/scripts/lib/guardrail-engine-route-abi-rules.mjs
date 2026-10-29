// The wasm crate exports only the default and route ABI calls.
// The route exports are gated, and the engine authors their request shapes.

import { attributeBlock } from "./guardrail-engine-lane-parsing.mjs";

const WASM_SRC = "apps/desktop/src-tauri/crates/engine-wasm/src";
const WASM_LIB = `${WASM_SRC}/lib.rs`;
const ROUTE_SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/route_session.rs";
const DEFAULT_ABI = ["scorer_alloc", "scorer_free", "scorer_score", "severity_apply"];
const ROUTE_ABI = [
  "engine_route_open",
  "engine_route_plan",
  "engine_route_evaluate",
  "engine_route_session_page",
  "engine_route_discover",
  "engine_route_sitemap_routes",
  "engine_session_evaluate",
];
const ROUTE_REQUESTS = [
  "struct RouteOpenRequest",
  "struct RouteCall",
  "struct RouteEvaluationRequest",
  "struct RouteSessionPageRequest",
  "struct RouteDiscoverRequest",
  "struct RouteSitemapRoutesRequest",
];

export function routeAbiFailures(read, listFiles) {
  const failures = [];
  const sources = listFiles(WASM_SRC, (file) => file.endsWith(".rs")).map((file) => [
    file,
    read(file),
  ]);
  for (const symbol of ROUTE_ABI) {
    const exporting = sources.filter(([, source]) => source.includes(`extern "C" fn ${symbol}(`));
    if (exporting.length === 0) {
      failures.push(`${WASM_LIB} no longer exports \`${symbol}\`; the scan worker calls it`);
    }
    for (const [file, source] of exporting) {
      const exportedAt = source.indexOf(`extern "C" fn ${symbol}(`);
      if (!attributeBlock(source, exportedAt).includes('#[cfg(feature = "checks")]')) {
        failures.push(
          `${file}: \`${symbol}\` is not behind \`#[cfg(feature = "checks")]\`; an exported ` +
            `symbol is a link root, so an ungated one pulls the whole check tree into connect's artifact`,
        );
      }
    }
  }
  // A page-carrying export beside the route calls is a second way in.
  for (const [file, source] of sources) {
    for (const [, symbol] of source.matchAll(/extern "C" fn (\w+)\(/g)) {
      if (!ROUTE_ABI.includes(symbol) && !DEFAULT_ABI.includes(symbol)) {
        failures.push(`${file} exports \`${symbol}\`, which the scan worker does not call`);
      }
    }
  }
  const routeSchema = read(ROUTE_SCHEMA);
  for (const type of ROUTE_REQUESTS) {
    if (!routeSchema.includes(type)) {
      failures.push(
        `${ROUTE_SCHEMA} no longer defines \`${type}\`; it is the shared wire definition`,
      );
    }
    for (const [file, source] of sources) {
      if (source.includes(type)) {
        failures.push(
          `${file} defines \`${type}\` itself; the request shapes are authored in the engine crate`,
        );
      }
    }
  }
  return failures;
}
