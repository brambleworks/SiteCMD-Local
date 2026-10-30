import { constList } from "./guardrail-engine-lane-parsing.mjs";

import {
  productionHalf,
  webCheckIdPrefixes,
  webCheckIdSources,
  WEB_CHECK_TREES,
} from "./product-facts.mjs";

const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const REGISTRY = "apps/desktop/src-tauri/crates/engine/src/manifest/registry/mod.rs";
// Cross-page verdicts are manifest entries but not public check-count inputs.
const SESSION_CHECKS = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";

// The hosted runtime cannot observe the negotiated protocol for these checks.
const UNOBSERVABLE_HOSTED_CHECKS = ["performance.http2"];

// Runner ids emit dynamic families rather than their own result rows.
function runnerIds(read) {
  const source = read(REGISTRY);
  const block = source.slice(source.indexOf("pub const RUNNER_IDS"));
  return new Map(
    [...block.matchAll(/\(\s*"([^"]+)",\s*\n?\s*"([^"]*)",?\s*\)/g)].map((m) => [m[1], m[2]]),
  );
}

export function capabilityManifestFailures(read, listFiles) {
  const failures = [];

  let manifest;
  try {
    manifest = JSON.parse(read(MANIFEST));
  } catch (error) {
    return [
      `${MANIFEST} is missing or unparseable (${error.message}); regenerate it with \`cargo test -p sitecmd-engine --test capability_manifest -- --ignored regenerate\``,
    ];
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    return [`${MANIFEST} has no entries; the registry cannot be empty`];
  }
  if (typeof manifest.manifest_digest !== "string" || manifest.manifest_digest.length === 0) {
    failures.push(
      `${MANIFEST} carries no manifest_digest; it is the value observations are resolved by`,
    );
  }

  const families = manifest.entries.filter((entry) => entry.family);
  const byId = new Map(manifest.entries.map((entry) => [entry.check, entry]));
  const runners = runnerIds(read);
  const emitted = webCheckIdSources(read, listFiles);
  const sessionIds = constList(read(SESSION_CHECKS), "SESSION_CHECK_IDS") ?? [];
  for (const id of sessionIds) {
    emitted.set(id, [...(emitted.get(id) ?? []), SESSION_CHECKS]);
  }
  const engineIds = new Set(webCheckIdSources(read, listFiles, [WEB_CHECK_TREES.engine]).keys());
  for (const id of sessionIds) engineIds.add(id);
  const enginePrefixes = new Set(
    webCheckIdPrefixes(read, listFiles, [WEB_CHECK_TREES.engine]).keys(),
  );

  // Enforce completeness in both directions.
  const unregistered = [...emitted.keys()].filter((id) => !byId.has(id) && !runners.has(id));
  if (unregistered.length > 0) {
    failures.push(
      `these check ids have no capability-manifest entry, so an observation carrying one would be quarantined as unresolvable; add a row in apps/desktop/src-tauri/crates/engine/src/manifest/registry/ (or declare it in RUNNER_IDS if it never appears on a result row): ${unregistered.sort().join(", ")}`,
    );
  }
  const orphaned = manifest.entries
    .filter((entry) => !entry.family && !emitted.has(entry.check))
    .map((entry) => entry.check);
  if (orphaned.length > 0) {
    failures.push(
      `these capability-manifest entries name check ids no check tree emits any more; publishing a contract for a check that no longer exists invites comparisons against nothing: ${orphaned.sort().join(", ")}`,
    );
  }
  for (const family of families) {
    if (!enginePrefixes.has(family.check)) {
      failures.push(
        `capability-manifest family '${family.check}' does not match any CHECK_ID_PREFIX constant in the engine check tree; a family keyed by a prefix nothing carries covers no ids at all`,
      );
    }
  }

  // Only the engine crate can back a hosted-lane claim.
  const overclaimed = manifest.entries
    .filter((entry) => entry.hosted !== "unsupported" && !entry.family)
    .filter((entry) => !engineIds.has(entry.check))
    .map((entry) => `${entry.check} (claims ${entry.hosted})`);
  if (overclaimed.length > 0) {
    failures.push(
      `these capability-manifest entries claim a hosted lane while their verdict code is still outside the engine crate, which would let a hosted scan be treated as able to speak to them: ${overclaimed.sort().join(", ")}`,
    );
  }
  const understated = manifest.entries
    .filter((entry) => entry.hosted === "unsupported" && engineIds.has(entry.check))
    .filter((entry) => !UNOBSERVABLE_HOSTED_CHECKS.includes(entry.check))
    // Localhost-only checks have no hosted findings to preserve in comparisons.
    .filter(
      (entry) =>
        !emitted
          .get(entry.check)
          ?.every((file) => file.startsWith(`${WEB_CHECK_TREES.engine}/predeploy/`)),
    )
    .map((entry) => entry.check);
  if (understated.length > 0) {
    failures.push(
      `these capability-manifest entries are marked unsupported although the engine crate emits them; an entry that undersells the engine silently drops findings from cross-vantage comparison: ${understated.sort().join(", ")}`,
    );
  }

  // Keep scope aligned with the desktop's origin-scoped declaration.
  for (const file of listFiles(WEB_CHECK_TREES.desktop, (f) => f.endsWith(".rs"))) {
    const source = read(file);
    for (const [, body, id] of source.matchAll(
      /fn origin_scoped\(&self\) -> bool \{\s*([a-z]+)\s*\}\s*\n\s*fn id\(&self\) -> &str \{\s*"([^"]+)"/g,
    )) {
      const entry = byId.get(id);
      if (!entry) continue;
      const declaredOrigin = body === "true";
      if (declaredOrigin !== (entry.scope === "origin")) {
        failures.push(
          `${file}: '${id}' is origin_scoped=${body} on the desktop but scope='${entry.scope}' in the capability manifest; the two decide the same coverage question and must not disagree`,
        );
      }
    }
  }

  // A verdict that reads evaluation_time must class at
  //    least one of the ids it emits as clock-dependent.
  for (const [file, ids] of filesWithIds(emitted)) {
    // Fixtures may populate evaluation_time without reading it.
    if (!productionHalf(read(file)).includes("evaluation_time")) continue;
    const covered = ids.filter((id) => byId.has(id));
    if (covered.length === 0) continue;
    if (!covered.some((id) => byId.get(id).class === "clock_dependent")) {
      failures.push(
        `${file} reads evaluation_time but none of the checks it emits (${covered.sort().join(", ")}) is classed clock_dependent; a verdict that moves when time passes must not be attributed to the site changing`,
      );
    }
  }

  return failures;
}

/** Invert the id -> files map into files -> ids. */
function filesWithIds(emitted) {
  const byFile = new Map();
  for (const [id, files] of emitted) {
    for (const file of files) {
      byFile.set(file, [...(byFile.get(file) ?? []), id]);
    }
  }
  return byFile;
}
