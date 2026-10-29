import { engineArtifactFailures } from "./guardrail-engine-artifact-rules.mjs";

const WASM_LIB = "apps/desktop/src-tauri/crates/engine-wasm/src/lib.rs";
const WASM_MANIFEST = "apps/desktop/src-tauri/crates/engine-wasm/Cargo.toml";
const RUNNERS = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners.rs";
const RUNNERS_SEO = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_seo.rs";
const PROBE_CHECKS = "apps/desktop/src-tauri/crates/engine/src/evaluation/probe_checks.rs";
const PROBE_SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";
const ROUTE_SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/route_session.rs";
const SCHEMA = "apps/desktop/src-tauri/crates/engine/src/evaluation/mod.rs";
const GOLDEN_TEST = "apps/desktop/src-tauri/crates/engine/tests/golden_checks.rs";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const CHECKS_SCRIPT = "tools/scripts/build-checks-wasm.mjs";
const SCORER_SCRIPT = "tools/scripts/build-scorer-wasm.mjs";

const gated = (symbol) =>
  [
    '#[cfg(feature = "checks")]',
    "#[no_mangle]",
    `pub unsafe extern "C" fn ${symbol}(ptr: *mut u8, len: u32) -> *const u8 {}`,
  ].join("\n");

const WASM_LIB_BASE = [
  'pub extern "C" fn scorer_alloc(len: u32) -> *mut u8 {}',
  'pub unsafe extern "C" fn scorer_free(ptr: *mut u8, len: u32) {}',
  'pub unsafe extern "C" fn scorer_score(ptr: *mut u8, len: u32) -> *const u8 {}',
  'pub unsafe extern "C" fn severity_apply(ptr: *mut u8, len: u32) -> *const u8 {}',
  gated("engine_route_open"),
  gated("engine_route_plan"),
  gated("engine_route_evaluate"),
  gated("engine_route_session_page"),
  gated("engine_route_discover"),
  gated("engine_route_sitemap_routes"),
  gated("engine_session_evaluate"),
].join("\n\n");

const WASM_MANIFEST_BASE = ["[features]", "default = []", "checks = []", ""].join("\n");

const ROUTE_SCHEMA_BASE = [
  "pub struct RouteOpenRequest {",
  "}",
  "pub struct RouteCall {",
  "}",
  "pub struct RouteEvaluationRequest {",
  "}",
  "pub struct RouteSessionPageRequest {",
  "}",
  "pub struct RouteDiscoverRequest {",
  "}",
  "pub struct RouteSitemapRoutesRequest {",
  "}",
].join("\n");

const SCHEMA_BASE = [
  "pub struct EvaluationRequest {",
  "    pub page: PageArtifact,",
  "}",
  "pub struct EvaluationResponse {",
  "    pub planned: Vec<PlannedCheck>,",
  "}",
  "pub enum NotEvaluatedReason {",
  "    MissingFact { fact: RuntimeFact },",
  "}",
].join("\n");

const RUNNERS_BASE = [
  "pub const RUNNERS: &[Runner] = &[",
  "    Runner {",
  '        covers: &["security.mixed_content"],',
  "        run: |inputs| MixedContentCheck.run(inputs.page),",
  "    },",
  "    Runner {",
  '        covers: &["security.headers.cross_origin"],',
  "        run: |inputs| {",
  "            crate::checks::security::cross_origin::CrossOriginIsolationCheck.run(inputs.page)",
  "        },",
  "    },",
  "    Runner {",
  '        covers: &["performance.page_weight"],',
  "        run: |inputs| vec![html_size_result(inputs.page.body.len())],",
  "    },",
  "];",
].join("\n");

const RUNNERS_SEO_BASE = [
  "pub const EXCLUDED_ARTIFACT_CHECKS: &[(&str, &str)] = &[",
  '    ("seo.headings.h1", "HeadingCheck is unregistered on the desktop"),',
  "];",
  "pub const SEO_RUNNERS: &[Runner] = &[",
  "    Runner {",
  '        covers: &["seo.viewport"],',
  "        run: |inputs| meta::ViewportCheck.run(inputs.page),",
  "    },",
  "];",
].join("\n");

const PROBE_CHECKS_BASE = [
  "pub const PROBE_CHECKS: &[ProbeCheck] = &[",
  "    ProbeCheck {",
  '        covers: &["config.favicon"],',
  "        plan: |ctx| favicon_plan(ctx),",
  "        grade: |ctx| favicon_grade(ctx),",
  "    },",
  "];",
].join("\n");

const PROBE_SCHEMA_BASE = [
  "pub struct PlannedProbe {}",
  "pub struct ExecutedProbe {}",
  "pub struct ProbePlan {}",
  "pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[",
  '    ("seo.robots_txt", "the robots.txt fetch is still planned by the desktop shell"),',
  "];",
  "pub fn probe_plan() {}",
].join("\n");

const FETCH = ["page_artifact", "fetch"];
const MANIFEST_BASE = JSON.stringify({
  schema_version: 1,
  manifest_digest: "ad51493a86e8be14",
  entries: [
    { check: "security.mixed_content", hosted: "artifact", requires: ["page_artifact"] },
    { check: "security.headers.cross_origin", hosted: "artifact", requires: ["page_artifact"] },
    { check: "performance.page_weight", hosted: "artifact", requires: ["page_artifact"] },
    { check: "seo.headings.h1", hosted: "artifact", requires: ["page_artifact"] },
    { check: "seo.viewport", hosted: "artifact", requires: ["page_artifact"] },
    {
      check: "seo.orphan_pages",
      hosted: "artifact",
      scope: "session",
      requires: ["page_artifact"],
    },
    { check: "seo.title", hosted: "unsupported", requires: [] },
    { check: "security.dns.spf", hosted: "probe_adapter", requires: ["resolver"] },
    { check: "config.favicon", hosted: "probe_adapter", requires: FETCH },
    { check: "seo.robots_txt", hosted: "probe_adapter", requires: FETCH },
  ],
});

const GOLDEN_TEST_BASE = 'const CORPUS: &str = include_str!("../fixtures/checks/golden.json");';

const REGISTRATION = "apps/desktop/src-tauri/src/checks/security/mod.rs";
const REGISTRATION_BASE = [
  "pub fn sync_checks() -> Vec<Box<dyn Check>> {",
  "    vec![",
  "        Box::new(mixed_content::MixedContentCheck),",
  "        Box::new(cross_origin::CrossOriginIsolationCheck),",
  "        Box::new(meta::ViewportCheck),",
  "    ]",
  "}",
].join("\n");

const CHECKS_SCRIPT_BASE = [
  'const corpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "checks", "golden.json");',
  'const stackCorpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "stack", "golden.json");',
  'const sessionCorpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "session", "golden.json");',
  "const dirtySuffix = engineTreeSuffix(allowDirty);",
  "const provenance = {",
  '  crate: "sitecmd-engine-wasm",',
  '  features: ["checks"],',
  "  engine_commit: head + dirtySuffix,",
  "  rustc: rustcVersion,",
  "  target: WASM_TARGET,",
  "  profile: WASM_PROFILE,",
  "  artifact_sha256: sha256(artifact),",
  "  corpus_sha256: sha256(corpus),",
  "  session_corpus_sha256: sha256(sessionCorpus),",
  "  browser_assets_sha256: sha256(browserAssets),",
  "  manifest_digest: manifest.manifest_digest,",
  "};",
  "vendorSet({",
  "  outDir,",
  "  files: [",
  '    { name: "checks.wasm", bytes: artifact },',
  '    { name: "golden.json", bytes: corpus },',
  '    { name: "session-golden.json", bytes: sessionCorpus },',
  '    { name: "browser-assets.json", bytes: browserAssets },',
  "  ],",
  "  record: provenance,",
  '  recordName: "checks-artifact.json",',
  "});",
  'const axeCore = readFileSync(path.join(browserPath, "axe.min.js"), "utf8");',
  'const cwvObserver = readFileSync(path.join(browserPath, "cwv_observer.js"), "utf8");',
  'const cwvRead = readFileSync(path.join(browserPath, "cwv_read.js"), "utf8");',
  'const browserPayload = JSON.parse(run("cargo", ["run", "--example", "emit_browser_payload"]));',
  "axe_core_version: browserPayload.axe_core_version,",
  "axe_run_script: browserPayload.axe_run_script,",
].join("\n");

const SCORER_SCRIPT_BASE = [
  'const corpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "score", "golden.json");',
  'const severityCorpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "severity", "golden.json");',
  "vendorSet({",
  "  outDir,",
  '  files: [{ name: "scorer.wasm", bytes: artifact }],',
  "  record: provenance,",
  '  recordName: "scorer-artifact.json",',
  "});",
].join("\n");

const SESSION_BASE = 'pub const SESSION_CHECK_IDS: &[&str] = &["seo.orphan_pages"];';

function run(overrides = {}) {
  const fixture = {
    [WASM_LIB]: WASM_LIB_BASE,
    [WASM_MANIFEST]: WASM_MANIFEST_BASE,
    [RUNNERS]: RUNNERS_BASE,
    [RUNNERS_SEO]: RUNNERS_SEO_BASE,
    [PROBE_CHECKS]: PROBE_CHECKS_BASE,
    [PROBE_SCHEMA]: PROBE_SCHEMA_BASE,
    [SCHEMA]: SCHEMA_BASE,
    [ROUTE_SCHEMA]: ROUTE_SCHEMA_BASE,
    [SESSION]: SESSION_BASE,
    ["apps/desktop/src-tauri/crates/engine/tests/golden_session.rs"]:
      'const CORPUS: &str = include_str!("../fixtures/session/golden.json");',
    ["apps/desktop/src-tauri/crates/engine-wasm/tests/session_abi.rs"]:
      'const CORPUS: &str = include_str!("../../engine/fixtures/session/golden.json");',
    [GOLDEN_TEST]: GOLDEN_TEST_BASE,
    ["apps/desktop/src-tauri/crates/engine/tests/golden_score.rs"]:
      'const CORPUS: &str = include_str!("../fixtures/score/golden.json");',
    ["apps/desktop/src-tauri/crates/engine-wasm/tests/abi.rs"]:
      'const CORPUS: &str = include_str!("../../engine/fixtures/score/golden.json");',
    ["apps/desktop/src-tauri/crates/engine/tests/golden_severity.rs"]:
      'const CORPUS: &str = include_str!("../fixtures/severity/golden.json");',
    ["apps/desktop/src-tauri/crates/engine/tests/golden_stack.rs"]:
      'const CORPUS: &str = include_str!("../fixtures/stack/golden.json");',
    ["apps/desktop/src-tauri/crates/engine-wasm/tests/severity_abi.rs"]:
      'const CORPUS: &str = include_str!("../../engine/fixtures/severity/golden.json");',
    ["apps/desktop/src-tauri/crates/engine/tests/evaluation_policy_facts.rs"]:
      'const STACK_CORPUS: &str = include_str!("../fixtures/stack/golden.json");',
    [MANIFEST]: MANIFEST_BASE,
    [CHECKS_SCRIPT]: CHECKS_SCRIPT_BASE,
    [SCORER_SCRIPT]: SCORER_SCRIPT_BASE,
    [REGISTRATION]: REGISTRATION_BASE,
    ...overrides,
  };
  return engineArtifactFailures(
    (file) => fixture[file] ?? "",
    (dir, predicate) =>
      Object.keys(fixture).filter((file) => file.startsWith(`${dir}/`) && predicate(file)),
  );
}

export {
  WASM_LIB,
  WASM_MANIFEST,
  RUNNERS,
  RUNNERS_SEO,
  PROBE_CHECKS,
  PROBE_SCHEMA,
  SCHEMA,
  ROUTE_SCHEMA,
  SESSION,
  MANIFEST,
  CHECKS_SCRIPT,
  SCORER_SCRIPT,
  gated,
  WASM_LIB_BASE,
  WASM_MANIFEST_BASE,
  SCHEMA_BASE,
  ROUTE_SCHEMA_BASE,
  RUNNERS_BASE,
  RUNNERS_SEO_BASE,
  PROBE_CHECKS_BASE,
  PROBE_SCHEMA_BASE,
  REGISTRATION,
  REGISTRATION_BASE,
  CHECKS_SCRIPT_BASE,
  SCORER_SCRIPT_BASE,
  run,
};
