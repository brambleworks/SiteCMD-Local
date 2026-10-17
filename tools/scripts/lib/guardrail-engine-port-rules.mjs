import { attributeBlock } from "./guardrail-engine-lane-parsing.mjs";

// The logic the hosted side runs lives in the portable engine, once. A second
// copy in the runtime is how the CLI and Connect would start to disagree about
// a finding's grade, so the runtime keeps adapters and nothing else.

const RUNTIME_POLICY = "apps/desktop/src-tauri/src/core/severity_policy.rs";
const ENGINE_POLICY = "apps/desktop/src-tauri/crates/engine/src/severity_policy/mod.rs";
const RUNTIME_DETECTOR = "apps/desktop/src-tauri/src/core/detector.rs";
const WASM_LIB = "apps/desktop/src-tauri/crates/engine-wasm/src/lib.rs";
const SCORER_SCRIPT = "tools/scripts/build-scorer-wasm.mjs";
const CHECKS_SCRIPT = "tools/scripts/build-checks-wasm.mjs";
const PORTED_SCRIPT = "tools/scripts/vendor-ported-fixtures.mjs";
const PARITY_DIR = "apps/desktop/src-tauri/tests/fixtures/parity";

function artifactFailures(read) {
  const failures = [];
  const wasm = read(WASM_LIB);
  const at = /^pub unsafe extern "C" fn severity_apply\(/m.exec(wasm)?.index ?? -1;
  if (at === -1) {
    failures.push(
      `${WASM_LIB} no longer exports \`severity_apply\`; Connect resolves it by name from its vendored artifact.`,
    );
  } else if (attributeBlock(wasm, at).includes('#[cfg(feature = "checks")]')) {
    failures.push(
      `${WASM_LIB}: \`severity_apply\` is behind the checks feature, so the default build Connect vendors would lose it.`,
    );
  }
  const scorer = read(SCORER_SCRIPT);
  if (
    !/^\s*\{ name: "severity-golden\.json", bytes: severityCorpus \},?$/m.test(scorer) ||
    !/^\s*severity_corpus_sha256: sha256\(severityCorpus\),?$/m.test(scorer)
  ) {
    failures.push(`${SCORER_SCRIPT} must vendor the severity corpus and record its digest.`);
  }
  const checks = read(CHECKS_SCRIPT);
  for (const kind of ["stack", "session"]) {
    if (
      !new RegExp(`^\\s*\\{ name: "${kind}-golden\\.json", bytes: ${kind}Corpus \\},?$`, "m").test(
        checks,
      ) ||
      !new RegExp(`^\\s*${kind}_corpus_sha256: sha256\\(${kind}Corpus\\),?$`, "m").test(checks)
    ) {
      failures.push(`${CHECKS_SCRIPT} must vendor the ${kind} corpus and record its digest.`);
    }
  }
  for (const [file, source] of [
    [SCORER_SCRIPT, scorer],
    [CHECKS_SCRIPT, checks],
    [PORTED_SCRIPT, read(PORTED_SCRIPT)],
  ]) {
    if (!/^const outDir = outDirFrom\(args, \["SiteCMD-Connect",/m.test(source)) {
      failures.push(
        `${file} must default to the SiteCMD-Connect checkout, where Connect and the runner live.`,
      );
    }
  }
  return failures;
}

function stackFailures(read) {
  const runtime = read(RUNTIME_DETECTOR);
  if (!/^pub use sitecmd_engine::stack::/m.test(runtime) || /\bfn detect_/.test(runtime)) {
    return [
      `${RUNTIME_DETECTOR} must re-export sitecmd_engine::stack and detect nothing itself; the hosted runner reports the engine's detection.`,
    ];
  }
  return [];
}

function severityPolicyFailures(read) {
  const failures = [];
  const runtime = read(RUNTIME_POLICY);
  if (!/^use sitecmd_engine::severity_policy/m.test(runtime)) {
    failures.push(`${RUNTIME_POLICY} must delegate to sitecmd_engine::severity_policy.`);
  }
  const severityNames = [
    "Severity",
    ...[...runtime.matchAll(/\bSeverity\s+as\s+(\w+)/g)].map((match) => match[1]),
  ];
  if (new RegExp(`\\b(?:${severityNames.join("|")})\\s*::`).test(runtime)) {
    failures.push(
      `${RUNTIME_POLICY} grades a severity itself; the policy table lives in ${ENGINE_POLICY}, which the hosted artifacts run too.`,
    );
  }
  if (!read(ENGINE_POLICY).includes("pub fn apply(")) {
    failures.push(`${ENGINE_POLICY} must keep \`apply\`, the one entry the WASM export calls.`);
  }
  return failures;
}

function portedFixtureFailures(read, listFiles) {
  const failures = [];
  const script = read(PORTED_SCRIPT);
  const entries = /^const PORTED = \[([\s\S]*?)^\];/m.exec(script)?.[1] ?? "";
  const sources = new Set(
    [...entries.matchAll(/^\s*(?:\{ )?source: "([^"]+)",/gm)].map((match) => match[1]),
  );
  const corpora = new Set(
    listFiles(PARITY_DIR, (file) => file.endsWith(".json")).map((file) =>
      file.slice(PARITY_DIR.length + 1),
    ),
  );
  for (const corpus of corpora) {
    if (!sources.has(corpus)) {
      failures.push(
        `${PORTED_SCRIPT} does not vendor ${corpus}; a corpus Connect does not replay pins nothing.`,
      );
    }
  }
  for (const source of sources) {
    if (!corpora.has(source)) {
      failures.push(`${PORTED_SCRIPT} vendors ${source} but no corpus file exists.`);
    }
  }
  if (!script.includes("vendorSet(") || /\b(writeFileSync|copyFileSync)\s*\(/.test(script)) {
    failures.push(`${PORTED_SCRIPT} must write the set through one vendorSet call.`);
  }
  return failures;
}

function vendoringRecordFailures(read) {
  const failures = [];
  for (const [file, scope] of [
    [SCORER_SCRIPT, ["apps/desktop/src-tauri", "tools/scripts"]],
    [CHECKS_SCRIPT, ["apps/desktop/src-tauri", "tools/scripts"]],
    [PORTED_SCRIPT, ["apps/desktop/src-tauri/src/core", PARITY_DIR]],
  ]) {
    const source = read(file);
    const paths = scope.map((file) => `"${file}"`).join("\\s*,\\s*");
    const call = new RegExp(
      `^const dirtySuffix = engineTreeSuffix\\(allowDirty,\\s*\\[\\s*${paths}\\s*,?\\s*\\]\\);`,
      "m",
    );
    if (!call.test(source)) {
      failures.push(`${file} must check its dirty scope with engineTreeSuffix(allowDirty, ...).`);
    }
    if (
      !/^\s*engine_commit: run\("git", \["rev-parse", "HEAD"\][^)]*\) \+ dirtySuffix,/m.test(source)
    ) {
      failures.push(`${file} must carry + dirtySuffix in engine_commit.`);
    }
  }
  return failures;
}

export function enginePortFailures(read, listFiles) {
  return [
    ...severityPolicyFailures(read),
    ...stackFailures(read),
    ...artifactFailures(read),
    ...portedFixtureFailures(read, listFiles),
    ...vendoringRecordFailures(read),
  ];
}
