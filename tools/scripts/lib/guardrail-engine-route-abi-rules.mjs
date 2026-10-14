// The wasm crate exports only the default and route ABI calls.
// The route exports are gated, and the engine authors their request shapes.

import { attributeBlock } from "./guardrail-engine-lane-parsing.mjs";

const WASM_LIB = "apps/desktop/src-tauri/crates/engine-wasm/src/lib.rs";
const ROUTE_SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/route_session.rs";
const DEFAULT_ABI = ["scorer_alloc", "scorer_free", "scorer_score", "severity_apply"];
const ROUTE_ABI = [
  "engine_route_open",
  "engine_route_plan",
  "engine_route_evaluate",
  "engine_route_session_page",
  "engine_session_evaluate",
];
const ROUTE_REQUESTS = [
  "struct RouteOpenRequest",
  "struct RouteCall",
  "struct RouteEvaluationRequest",
  "struct RouteSessionPageRequest",
];

export function routeAbiFailures(read) {
  const failures = [];
  const wasmLib = read(WASM_LIB);
  for (const symbol of ROUTE_ABI) {
    const exportedAt = wasmLib.indexOf(`extern "C" fn ${symbol}(`);
    if (exportedAt === -1) {
      failures.push(`${WASM_LIB} no longer exports \`${symbol}\`; the scan worker calls it`);
    } else if (!attributeBlock(wasmLib, exportedAt).includes('#[cfg(feature = "checks")]')) {
      failures.push(
        `${WASM_LIB}: \`${symbol}\` is not behind \`#[cfg(feature = "checks")]\`; an exported ` +
          `symbol is a link root, so an ungated one pulls the whole check tree into connect's artifact`,
      );
    }
  }
  // A page-carrying export beside the route calls is a second way in.
  for (const [, symbol] of wasmLib.matchAll(/extern "C" fn (\w+)\(/g)) {
    if (!ROUTE_ABI.includes(symbol) && !DEFAULT_ABI.includes(symbol)) {
      failures.push(`${WASM_LIB} exports \`${symbol}\`, which the scan worker does not call`);
    }
  }
  const routeSchema = read(ROUTE_SCHEMA);
  for (const type of ROUTE_REQUESTS) {
    if (!routeSchema.includes(type)) {
      failures.push(
        `${ROUTE_SCHEMA} no longer defines \`${type}\`; it is the shared wire definition`,
      );
    }
    if (wasmLib.includes(type)) {
      failures.push(
        `${WASM_LIB} defines \`${type}\` itself; the request shapes are authored in the engine crate`,
      );
    }
  }
  return failures;
}
