import { capabilityManifestFailures } from "./guardrail-capability-manifest-rules.mjs";

export const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const REGISTRY = "apps/desktop/src-tauri/crates/engine/src/manifest/registry/mod.rs";
const DESKTOP = "apps/desktop/src-tauri/src/checks";
const ENGINE = "apps/desktop/src-tauri/crates/engine/src/checks";
const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";

export function entry(check, overrides = {}) {
  return {
    check,
    contract: "0000000000000000",
    hosted: "artifact",
    class: "deterministic",
    scope: "page",
    requires: ["page_artifact"],
    compare_on: [],
    ...overrides,
  };
}

export function emits(id, extra = "") {
  return `pub fn run() -> CheckResult {\n    CheckResult { check_id: "${id}".into() }\n}\n${extra}`;
}

export function repo({ entries = [], runners = [], desktop = {}, engine = {}, session = [] }) {
  const files = {
    [MANIFEST]: JSON.stringify({
      schema_version: 1,
      manifest_digest: "b5fef8de083e1976",
      entries,
    }),
    [REGISTRY]: [
      "pub const RUNNER_IDS: &[(&str, &str)] = &[",
      ...runners.map(([id, why]) => `    (\n        "${id}",\n        "${why}",\n    ),`),
      "];",
    ].join("\n"),
    [SESSION]: [
      "pub const SESSION_CHECK_IDS: &[&str] = &[",
      ...session.map((id) => `    "${id}",`),
      "];",
    ].join("\n"),
  };
  for (const [name, source] of Object.entries(desktop)) files[`${DESKTOP}/${name}`] = source;
  for (const [name, source] of Object.entries(engine)) files[`${ENGINE}/${name}`] = source;

  const read = (file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  };
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
  return [read, listFiles];
}

export function failures(fixture) {
  return capabilityManifestFailures(...repo(fixture));
}
