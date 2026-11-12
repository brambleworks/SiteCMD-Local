// The hosted scan's own check count, read from the engine: inventory checks
// whose manifest entry names a hosted lane and which no exclusion table lists,
// the session-scoped share of those, the axe rules when their family has a
// hosted lane, and every polish signal. Only engine preview checks may be unsupported.

import {
  excludedChecks,
  isPreviewOnlySources,
  polishSignals,
} from "./guardrail-engine-lane-parsing.mjs";

const INVENTORY = "apps/desktop/src-tauri/check-inventory.json";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const RUNNERS_SEO = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_seo.rs";
const PROBES = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
const POLISH_TABLE = "apps/desktop/src-tauri/crates/engine/src/checks/polish/mod.rs";
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

/** Counts hosted checks, refusing any gap except web ids emitted only by preview checks. */
export function deriveHostedCheckCounts(read, axeRules, sources) {
  const inventory = JSON.parse(read(INVENTORY)).web;
  const { entries } = JSON.parse(read(MANIFEST));
  const artifactExcluded = exclusions(read, RUNNERS_SEO, "pub const EXCLUDED_ARTIFACT_CHECKS");
  const probeExcluded = exclusions(read, PROBES, "pub const EXCLUDED_PROBE_CHECKS");
  const signals = polishSignals(read(POLISH_TABLE));
  if (signals === null) {
    throw new Error(
      `product-facts: ${POLISH_TABLE} no longer declares POLISH_SIGNALS; update lib/hosted-check-counts.mjs`,
    );
  }
  let web = 0;
  let previewCheckCount = 0;
  let crossPage = 0;
  const hosted = (id, allowPreview = false) => {
    const entry = manifestEntry(entries, id);
    const files = sources.get(id);
    if (allowPreview && entry?.hosted === "unsupported" && isPreviewOnlySources(files)) {
      previewCheckCount += 1;
      return null;
    }
    let cause = null;
    if (entry === undefined) cause = "no capability-manifest entry";
    else if (entry.hosted === "unsupported") cause = "unsupported in the capability manifest";
    else if (entry.hosted === "artifact" && excluded(id, artifactExcluded)) {
      cause = "listed in EXCLUDED_ARTIFACT_CHECKS";
    } else if (entry.hosted === "probe_adapter" && excluded(id, probeExcluded)) {
      cause = "listed in EXCLUDED_PROBE_CHECKS";
    }
    if (cause !== null) {
      throw new Error(
        `product-facts: ${id} runs neither on the hosted lane nor as a preview check (${cause})`,
      );
    }
    return entry;
  };
  for (const id of inventory) {
    const entry = hosted(id, true);
    if (entry === null) continue;
    web += 1;
    if (entry.scope === "session") crossPage += 1;
  }
  for (const { id } of signals) hosted(`polish.${id}`);
  const polish = signals.length;
  const axeEntry = manifestEntry(entries, AXE_FAMILY);
  const axe = axeEntry !== undefined && axeEntry.hosted !== "unsupported" ? axeRules : 0;
  return { web, previewCheckCount, crossPage, axe, polish, total: web + axe + polish };
}
