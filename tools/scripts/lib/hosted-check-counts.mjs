// The hosted scan's own check count, read from the engine: inventory checks
// whose manifest entry names a hosted lane and which no exclusion table lists,
// the session-scoped share of those, and the axe rules when the browser lane
// is hosted.

import { excludedChecks } from "./guardrail-engine-lane-parsing.mjs";

const INVENTORY = "apps/desktop/src-tauri/check-inventory.json";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const RUNNERS_SEO = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_seo.rs";
const PROBES = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
const AXE_FAMILY = "accessibility.axe.";

/** An id's manifest entry: its own, else its longest matching family prefix. */
function manifestEntry(entries, id) {
  const own = entries.find((entry) => entry.check === id);
  if (own) return own;
  return entries
    .filter((entry) => entry.family && id.startsWith(entry.check))
    .sort((a, b) => b.check.length - a.check.length)[0];
}

/** Whether an exclusion table names the id or a family it belongs to. */
function excluded(id, exclusions) {
  return exclusions.some(
    ({ check }) => check === id || (check.endsWith(".") && id.startsWith(check)),
  );
}

function exclusions(read, file, table) {
  const found = excludedChecks(read(file), table);
  if (found === null) {
    throw new Error(
      `product-facts: ${file} no longer declares ${table}; update lib/hosted-check-counts.mjs`,
    );
  }
  return found;
}

/** Derives the hosted count from inventory, capabilities, exclusions and axe rules. */
export function deriveHostedCheckCounts(read, axeRules) {
  const inventory = JSON.parse(read(INVENTORY)).web;
  const { entries } = JSON.parse(read(MANIFEST));
  const artifactExcluded = exclusions(read, RUNNERS_SEO, "pub const EXCLUDED_ARTIFACT_CHECKS");
  const probeExcluded = exclusions(read, PROBES, "pub const EXCLUDED_PROBE_CHECKS");
  let web = 0;
  let crossPage = 0;
  for (const id of inventory) {
    const entry = manifestEntry(entries, id);
    if (entry === undefined) {
      throw new Error(`product-facts: ${id} has no capability-manifest entry`);
    }
    if (entry.hosted === "unsupported") continue;
    if (entry.hosted === "artifact" && excluded(id, artifactExcluded)) continue;
    if (entry.hosted === "probe_adapter" && excluded(id, probeExcluded)) continue;
    web += 1;
    if (entry.scope === "session") crossPage += 1;
  }
  const axeEntry = manifestEntry(entries, AXE_FAMILY);
  const axe = axeEntry !== undefined && axeEntry.hosted !== "unsupported" ? axeRules : 0;
  return { web, crossPage, axe, total: web + axe };
}
