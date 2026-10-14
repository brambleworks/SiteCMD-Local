import path from "node:path";

import {
  claimedChecks,
  constList,
  excludedChecks,
  isFetchPlannable,
  laneCoverageFailures,
  runnerDispatches,
} from "./guardrail-engine-lane-parsing.mjs";
import { routeAbiFailures } from "./guardrail-engine-route-abi-rules.mjs";

const WASM_LIB = "apps/desktop/src-tauri/crates/engine-wasm/src/lib.rs";
const WASM_MANIFEST = "apps/desktop/src-tauri/crates/engine-wasm/Cargo.toml";
const RUNNERS = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners.rs";
const RUNNERS_SEO = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_seo.rs";
const PROBE_CHECKS = "apps/desktop/src-tauri/crates/engine/src/evaluation/probe_checks.rs";
const PROBE_SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";
const SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/mod.rs";
const GOLDEN_TEST = "apps/desktop/src-tauri/crates/engine/tests/golden_checks.rs";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const CHECKS_SCRIPT = "tools/scripts/build-checks-wasm.mjs";
const SCORER_SCRIPT = "tools/scripts/build-scorer-wasm.mjs";
const VENDOR_LIB = "tools/scripts/lib/wasm-vendor.mjs";

const REGISTRATION_SOURCES = [
  "apps/desktop/src-tauri/src/checks/security/mod.rs",
  "apps/desktop/src-tauri/src/checks/seo/mod.rs",
  "apps/desktop/src-tauri/src/checks/performance/mod.rs",
  "apps/desktop/src-tauri/src/checks/accessibility/mod.rs",
  "apps/desktop/src-tauri/src/checks/compliance/mod.rs",
  "apps/desktop/src-tauri/src/checks/config/mod.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/predeploy/mod.rs",
];

const SCORER_ABI = ["scorer_alloc", "scorer_score", "scorer_free"];

const REQUIRED_PROVENANCE = [
  "features",
  "engine_commit",
  "rustc",
  "target",
  "profile",
  "artifact_sha256",
  "corpus_sha256",
  "session_corpus_sha256",
  "browser_assets_sha256",
  "manifest_digest",
];

export function engineArtifactFailures(read) {
  const failures = [];
  const wasmLib = read(WASM_LIB);
  const wasmManifest = read(WASM_MANIFEST);
  const runners = read(RUNNERS);
  const runnersSeo = read(RUNNERS_SEO);
  const probeChecks = read(PROBE_CHECKS);
  const probeSchema = read(PROBE_SCHEMA);
  const schema = read(SCHEMA);
  const checksScript = read(CHECKS_SCRIPT);
  const scorerScript = read(SCORER_SCRIPT);

  for (const symbol of SCORER_ABI) {
    if (!wasmLib.includes(`extern "C" fn ${symbol}(`)) {
      failures.push(
        `${WASM_LIB} no longer exports \`${symbol}\`; the connect worker resolves that symbol by ` +
          `name from its vendored artifact, and renaming it breaks a worker in another repository`,
      );
    }
  }

  failures.push(...routeAbiFailures(read));

  if (!/\bdefault\s*=\s*\[\s*\]/.test(wasmManifest)) {
    failures.push(
      `${WASM_MANIFEST}: the default feature set must stay empty; connect vendors the default ` +
        `build and its parity test pins those bytes`,
    );
  }
  if (!/^checks\s*=\s*\[/m.test(wasmManifest)) {
    failures.push(
      `${WASM_MANIFEST}: the \`checks\` feature is gone; the scan worker's artifact is the same ` +
        `crate built with it, and without the feature there is only one artifact again`,
    );
  }

  for (const type of ["struct EvaluationRequest", "struct EvaluationResponse"]) {
    if (!schema.includes(type)) {
      failures.push(`${SCHEMA} no longer defines \`${type}\`; it is the shared wire definition`);
    }
    if (wasmLib.includes(type)) {
      failures.push(
        `${WASM_LIB} defines \`${type}\` itself; the schema is authored in the engine crate so the ` +
          `desktop and the hosted runner cannot read two definitions of one request`,
      );
    }
  }
  if (!schema.includes("enum NotEvaluatedReason")) {
    failures.push(
      `${SCHEMA} no longer defines \`NotEvaluatedReason\`; a check that did not run must come back ` +
        `with a named reason, never as a silent omission and never as free text the consumer parses`,
    );
  }
  for (const type of ["struct ProbePlan", "struct ExecutedProbe"]) {
    if (!probeSchema.includes(type)) {
      failures.push(
        `${PROBE_SCHEMA} no longer defines \`${type}\`; it is the shared wire definition of the ` +
          `probe plan and of the outcomes a caller hands back`,
      );
    }
    if (wasmLib.includes(type)) {
      failures.push(
        `${WASM_LIB} defines \`${type}\` itself; the schema is authored in the engine crate so the ` +
          `desktop and the hosted runner cannot read two definitions of one plan`,
      );
    }
  }

  const sharedClaims = claimedChecks(runners, "pub const RUNNERS");
  const seoClaims = claimedChecks(runnersSeo, "pub const SEO_RUNNERS");
  const claimed =
    sharedClaims === null || seoClaims === null ? null : [...sharedClaims, ...seoClaims];
  const excluded = excludedChecks(runnersSeo, "pub const EXCLUDED_ARTIFACT_CHECKS");
  const planned = claimedChecks(probeChecks, "pub const PROBE_CHECKS");
  const probeExcluded = excludedChecks(probeSchema, "pub const EXCLUDED_PROBE_CHECKS");
  if (claimed === null || excluded === null) {
    failures.push(
      `${RUNNERS} or ${RUNNERS_SEO} no longer declares \`RUNNERS\`, \`SEO_RUNNERS\` or \`EXCLUDED_ARTIFACT_CHECKS\`; update these rules with them`,
    );
  }
  if (planned === null || probeExcluded === null) {
    failures.push(
      `${PROBE_CHECKS} no longer declares \`PROBE_CHECKS\`, or ${PROBE_SCHEMA} no longer declares ` +
        `\`EXCLUDED_PROBE_CHECKS\`; update these rules with them`,
    );
  }
  let manifest;
  try {
    manifest = JSON.parse(read(MANIFEST));
  } catch (error) {
    failures.push(`${MANIFEST} is missing or unparseable (${error.message})`);
    manifest = { entries: [] };
  }
  const entries = manifest.entries ?? [];
  if (claimed !== null && excluded !== null) {
    failures.push(
      ...laneCoverageFailures({
        lane: "artifact",
        entries: entries.filter(
          (entry) => entry.hosted === "artifact" && entry.scope !== "session",
        ),
        claimed,
        excluded,
        table: `${RUNNERS} and ${RUNNERS_SEO}`,
        subject: "runner",
      }),
    );
  }
  if (planned !== null && probeExcluded !== null) {
    failures.push(
      ...laneCoverageFailures({
        lane: "probe",
        entries: entries.filter(
          (entry) => entry.hosted === "probe_adapter" && isFetchPlannable(entry),
        ),
        claimed: planned,
        excluded: probeExcluded,
        table: PROBE_CHECKS,
        subject: "probe check",
      }),
    );
  }

  // The cross-page checks are produced once per scan by the engine's analysis,
  // so the analysis's own list and the manifest's session checks must agree.
  const analyzed = constList(read(SESSION), "SESSION_CHECK_IDS");
  if (analyzed === null) {
    failures.push(
      `${SESSION} no longer declares \`SESSION_CHECK_IDS\`; update these rules with it`,
    );
  } else {
    const sessionChecks = entries
      .filter((entry) => entry.scope === "session")
      .map((entry) => entry.check);
    const unproduced = sessionChecks.filter((check) => !analyzed.includes(check));
    const unlisted = analyzed.filter((check) => !sessionChecks.includes(check));
    if (unproduced.length > 0 || unlisted.length > 0) {
      failures.push(
        `${SESSION}'s SESSION_CHECK_IDS and the manifest's session checks disagree (` +
          `${[...unproduced, ...unlisted].sort().join(", ")}); a session check nothing produces is a ` +
          `check a hosted scan claims and never grades`,
      );
    }
  }

  for (const [test, script, source, variable] of [
    [GOLDEN_TEST, CHECKS_SCRIPT, checksScript, "corpusPath"],
    [
      "apps/desktop/src-tauri/crates/engine/tests/golden_session.rs",
      CHECKS_SCRIPT,
      checksScript,
      "sessionCorpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine-wasm/tests/session_abi.rs",
      CHECKS_SCRIPT,
      checksScript,
      "sessionCorpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine/tests/golden_score.rs",
      SCORER_SCRIPT,
      scorerScript,
      "corpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine-wasm/tests/abi.rs",
      SCORER_SCRIPT,
      scorerScript,
      "corpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine/tests/golden_severity.rs",
      SCORER_SCRIPT,
      scorerScript,
      "severityCorpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine-wasm/tests/severity_abi.rs",
      SCORER_SCRIPT,
      scorerScript,
      "severityCorpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine/tests/evaluation_policy_facts.rs",
      CHECKS_SCRIPT,
      checksScript,
      "stackCorpusPath",
    ],
    [
      "apps/desktop/src-tauri/crates/engine/tests/golden_stack.rs",
      CHECKS_SCRIPT,
      checksScript,
      "stackCorpusPath",
    ],
  ]) {
    const embedded = /include_str!\("([^"]+)"\)/.exec(read(test));
    if (embedded === null) {
      failures.push(`${test} no longer embeds a corpus with include_str!`);
      continue;
    }
    const declaration = new RegExp(`const ${variable} = ([^;]*);`).exec(source);
    const joined = declaration === null ? "" : declaration[1];
    const segments = [...joined.matchAll(/"([^"]+)"/g)].map((match) => match[1]);
    const vendored = path.posix.join("apps/desktop/src-tauri", ...segments);
    const wanted = path.posix.join(path.posix.dirname(test), embedded[1]);
    if (!/path\.join\(\s*cargoRoot\s*,/.test(joined) || vendored !== wanted) {
      failures.push(
        `${script} does not vendor the corpus ${test} embeds (${embedded[1]}); two ` +
          `corpora means the hosted parity test and the native one are testing different things`,
      );
    }
  }

  for (const [file, source] of [
    [CHECKS_SCRIPT, checksScript],
    [SCORER_SCRIPT, scorerScript],
  ]) {
    if (!source.includes("vendorSet(")) {
      failures.push(
        `${file} does not vendor through \`vendorSet\`; the artifact, the corpus, and the record ` +
          `have to be written by one call or two of the three can be updated separately`,
      );
    }
    if (/\b(writeFileSync|copyFileSync)\s*\(/.test(source)) {
      failures.push(
        `${file} writes a vendored file directly; every byte that reaches a worker goes through ` +
          `\`vendorSet\` in ${VENDOR_LIB} so the set cannot be written piecemeal`,
      );
    }
  }

  const browserPayloadSources = ["axe.min.js", "cwv_observer.js", "cwv_read.js"];
  if (
    !browserPayloadSources.every((name) => checksScript.includes(`"${name}"`)) ||
    !checksScript.includes('"emit_browser_payload"') ||
    !checksScript.includes('{ name: "browser-assets.json", bytes: browserAssets }')
  ) {
    failures.push(
      `${CHECKS_SCRIPT} does not vendor the shared browser instrumentation payloads with the ` +
        `checks artifact; Browser Run and the desktop must inject the same bytes`,
    );
  }
  if (
    !checksScript.includes("axe_core_version: browserPayload.axe_core_version") ||
    !checksScript.includes("axe_run_script: browserPayload.axe_run_script")
  ) {
    failures.push(
      `${CHECKS_SCRIPT} must read the axe version from the shared browser payload; ` +
        `a second hardcoded version can drift from the script bytes it labels`,
    );
  }

  for (const field of REQUIRED_PROVENANCE) {
    if (!new RegExp(`\\b${field}:`).test(checksScript)) {
      failures.push(
        `${CHECKS_SCRIPT}: the vendored record no longer carries \`${field}\`; the record is the ` +
          `only thing between a reviewer and a wasm blob of unknown origin`,
      );
    }
  }

  const registered = REGISTRATION_SOURCES.map((file) => read(file)).join("\n");
  const tables = [
    runnerDispatches(runners, "pub const RUNNERS"),
    runnerDispatches(runnersSeo, "pub const SEO_RUNNERS"),
  ];
  const dispatches = tables.includes(null)
    ? null
    : {
        types: tables.flatMap((table) => table.types),
        invocations: tables.reduce((total, table) => total + table.invocations, 0),
      };
  if (dispatches !== null) {
    if (dispatches.types.length !== dispatches.invocations) {
      failures.push(
        `${RUNNERS} and ${RUNNERS_SEO}: the runner-extraction pattern reads ${dispatches.types.length} of the ` +
          `${dispatches.invocations} check invocations in \`RUNNERS\` and \`SEO_RUNNERS\`, so the rows it cannot read ` +
          `are exempt from the desktop-registration parity check; teach the pattern the new ` +
          `formatting rather than leaving those runners unchecked`,
      );
    }
    const unregistered = [
      ...new Set(dispatches.types.filter((type) => !registered.includes(`Box::new(${type})`))),
    ].filter((type) => !new RegExp(`Box::new\\([\\w:]*::${type}\\)`).test(registered));
    if (unregistered.length > 0) {
      failures.push(
        `${RUNNERS} and ${RUNNERS_SEO}: these checks run in the hosted artifact but are not registered in any desktop ` +
          `scan (${unregistered.sort().join(", ")}); a hosted-only check produces findings no ` +
          `desktop scan can reproduce, which is a parity break the manifest cannot express`,
      );
    }
  }

  const vendoredNames = [...checksScript.matchAll(/name:\s*"([^"]+)"/g)].map((match) => match[1]);
  const executable = vendoredNames.filter((name) => /\.(ts|tsx|js|mjs|cjs)$/.test(name));
  if (executable.length > 0) {
    failures.push(
      `${CHECKS_SCRIPT} vendors worker source into the scan worker (${executable.join(", ")}); the ` +
        `hosted lane runs compiled engine code, and shipping TypeScript through the artifact path ` +
        `is the reimplementation the parity contract exists to forbid`,
    );
  }

  return failures;
}
