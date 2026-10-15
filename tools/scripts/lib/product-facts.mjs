import { runInNewContext } from "node:vm";

import { deriveHostedCheckCounts } from "./hosted-check-counts.mjs";
import { PRODUCT_SURFACE_STATUS } from "./product-surfaces.mjs";

const TELEMETRY_WRAPPER = "apps/desktop/src/lib/telemetry.ts";
const DEEP_LINKS = "apps/desktop/src-tauri/src/desktop_deep_links.rs";
const COMMERCIAL_MODEL = "apps/desktop/src/lib/commercial-model.json";
const POLISH_SIGNALS = "apps/desktop/src/generated/polish_signal_manifest.json";
const ANALYZER = "apps/desktop/src-tauri/src/webview/analyzer.rs";
const PRIVATE_NETWORK_RULES = "apps/desktop/src-tauri/src/webview/private_network_rules.rs";
const AGENT = "apps/desktop/src-tauri/crates/engine/src/agent.rs";
const PROBE = "apps/desktop/src-tauri/crates/engine/src/probe.rs";
const EXPOSED_FILES = "apps/desktop/src-tauri/crates/engine/src/checks/security/exposed_files.rs";
const CONSTANTS = "apps/desktop/src-tauri/src/constants.rs";
const ASSETS = "apps/desktop/src-tauri/crates/engine/src/checks/performance/assets/mod.rs";
const CSS_FETCH = "apps/desktop/src-tauri/src/checks/polish/css_fetch.rs";
const SITEMAP = "apps/desktop/src-tauri/crates/engine/src/checks/seo/sitemap.rs";
const SITEMAP_DOCUMENT = "apps/desktop/src-tauri/crates/engine/src/checks/seo/sitemap_document.rs";
const AXE_PAYLOAD = "apps/desktop/src-tauri/crates/engine/src/browser/payload.rs";
const AXE_BUNDLE = "apps/desktop/src-tauri/crates/engine/browser/axe.min.js";

const SUBRESOURCE_DISCLAIMER = "Tauri does not expose external subresource interception";
const WEBRTC_LOCKDOWN = "apps/desktop/src-tauri/src/webview/webrtc_lockdown.js";
const RESOLVED_PRIVATE_DISCLAIMER = "public hostname that resolves to a private address";

function extract(source, pattern, label, file) {
  const match = source.match(pattern);
  if (!match) {
    throw new Error(
      `product-facts: could not find ${label} in ${file}; update lib/product-facts.mjs`,
    );
  }
  return match[1];
}

const DEPENDENCY_ENGINE_ECOSYSTEMS = 8;

/** Returns production Rust source before its first inline test module. */
export function productionHalf(source) {
  for (const hit of source.matchAll(/#\[cfg\(test\)\]/g)) {
    let rest = source.slice(hit.index + hit[0].length);
    for (;;) {
      const attr = /^\s*#\[[^\]]*\]/.exec(rest);
      if (attr === null) break;
      rest = rest.slice(attr[0].length);
    }
    rest = rest.trimStart();
    if (rest.startsWith("pub")) {
      rest = rest.slice(3);
      if (rest.startsWith("(")) {
        const close = rest.indexOf(")");
        if (close === -1) continue;
        rest = rest.slice(close + 1);
      }
      if (!/^\s/.test(rest)) continue;
      rest = rest.trimStart();
    }
    if (!/^mod\s/.test(rest)) continue;
    rest = rest.slice(3).trimStart();
    const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest);
    if (name === null) continue;
    if (rest.slice(name[0].length).trimStart().startsWith("{")) {
      return source.slice(0, hit.index);
    }
  }
  return source;
}

/** The desktop's check tree and the engine crate's, which modules move into. */
export const WEB_CHECK_TREES = {
  desktop: "apps/desktop/src-tauri/src/checks",
  engine: "apps/desktop/src-tauri/crates/engine/src/checks",
};

/** Maps emitted web check ids to their source files. */
export function webCheckIdSources(read, listFiles, trees = Object.values(WEB_CHECK_TREES)) {
  const sources = new Map();
  for (const tree of trees) {
    for (const file of listFiles(tree, (f) => f.endsWith(".rs") && !f.endsWith("_tests.rs"))) {
      const source = productionHalf(read(file));
      const add = (id) => sources.set(id, [...(sources.get(id) ?? []), file]);
      for (const [, id] of source.matchAll(/fn id\(&self\) -> &str \{\s*"([^"]+)"/g)) add(id);
      for (const [, id] of source.matchAll(/check_id: "([^"]+)"/g)) add(id);
      for (const [, name, id] of source.matchAll(
        /const ([A-Z_]*CHECK_IDS?[A-Z_]*): &str = "([^"]+)"/g,
      )) {
        if (name.endsWith("_PREFIX")) continue;
        add(id);
      }
    }
  }
  return sources;
}

/** Namespace constants (`accessibility.axe.`) whose real ids are dynamic. */
export function webCheckIdPrefixes(read, listFiles, trees = Object.values(WEB_CHECK_TREES)) {
  const prefixes = new Map();
  for (const tree of trees) {
    for (const file of listFiles(tree, (f) => f.endsWith(".rs") && !f.endsWith("_tests.rs"))) {
      for (const [, , id] of productionHalf(read(file)).matchAll(
        /const ([A-Z_]*CHECK_ID_PREFIX): &str = "([^"]+)"/g,
      )) {
        prefixes.set(id, file);
      }
    }
  }
  return prefixes;
}

/** Counts the bundled axe rules selected by the engine's whole-document run. */
function deriveAxeRunRuleCount(read) {
  const source = productionHalf(read(AXE_PAYLOAD));
  const declaration = source.match(
    /^\s*pub const AXE_RUN_TAGS:\s*\[&str;\s*(\d+)\s*\]\s*=\s*(\[[\s\S]*?\])\s*;/m,
  );
  const invalidTags = () =>
    new Error(
      `product-facts: could not read AXE_RUN_TAGS in ${AXE_PAYLOAD}; expected a non-empty [&str; N] string array matching its declared length`,
    );
  if (!declaration) throw invalidTags();
  let tags;
  try {
    tags = JSON.parse(declaration[2].replace(/,\s*\]$/, "]"));
  } catch {
    throw invalidTags();
  }
  if (
    tags.length === 0 ||
    tags.length !== Number(declaration[1]) ||
    tags.some((tag) => typeof tag !== "string" || tag.length === 0)
  ) {
    throw invalidTags();
  }

  const run = source.match(/\baxe\.run\(\s*document\s*,\s*\{\{([\s\S]*?)\}\}\s*\)/);
  if (
    !/\blet\s+tags\s*=\s*AXE_RUN_TAGS\s*\.iter\(\)\s*\.map\(\|tag\|\s*format!\("'\{tag\}'"\)\)\s*\.collect::<Vec<_>>\(\)\s*\.join\(", "\)\s*;/.test(
      source,
    ) ||
    !/\brunOnly\s*:\s*\{\{\s*type:\s*'tag'\s*,\s*values:\s*\[\{tags\}\]\s*\}\}/.test(
      run?.[1] ?? "",
    ) ||
    /\brules\s*:|["']rules["']\s*:/.test(run?.[1] ?? "")
  ) {
    throw new Error(
      `product-facts: ${AXE_PAYLOAD} no longer calls axe.run(document) with runOnly tags from AXE_RUN_TAGS and no rules overrides; update lib/product-facts.mjs`,
    );
  }

  const sandbox = { module: { exports: {} }, setTimeout, clearTimeout };
  runInNewContext(read(AXE_BUNDLE), sandbox, { filename: AXE_BUNDLE });
  const axe = sandbox.module.exports;
  if (
    typeof axe?._audit?.normalizeOptions !== "function" ||
    typeof axe?.utils?.ruleShouldRun !== "function"
  ) {
    throw new Error(
      `product-facts: ${AXE_BUNDLE} no longer exposes axe's rule selector (_audit.normalizeOptions, utils.ruleShouldRun); update lib/product-facts.mjs`,
    );
  }
  const options = { runOnly: { type: "tag", values: tags } };
  axe._audit.normalizeOptions(options);
  // This is the selector the audit uses to enqueue rules; a tag the run names
  // selects a rule disabled by default.
  return axe._audit.rules.filter((rule) => axe.utils.ruleShouldRun(rule, { page: true }, options))
    .length;
}

/** Derives the public check total from the owning engine sources. */
export function deriveCheckCounts(read, _listFiles) {
  // The registries themselves generate this snapshot (`cargo test
  // checks::inventory` in apps/desktop/src-tauri), including runner shells'
  // sub-ids that a regex scrape of `id()`/`check_id` literals cannot see.
  const web = JSON.parse(read("apps/desktop/src-tauri/check-inventory.json")).web.length;

  const polishSource = read("apps/desktop/src-tauri/src/checks/polish/mod.rs");
  const start = polishSource.indexOf("pub fn run_all_signals");
  const polishBody = polishSource.slice(start, polishSource.indexOf("\n}", start));
  const polish = [...polishBody.matchAll(/^\s+[a-z_]+::[a-z_]+\(ctx\),/gm)].length;

  const registry = read("apps/desktop/src-tauri/crates/engine/src/code_rules.rs");
  const codeScan = [...registry.matchAll(/^\s*d\("[a-z0-9-]+"/gm)].length;
  const axe = deriveAxeRunRuleCount(read);

  return {
    web,
    polish,
    codeScan,
    axe,
    dependencyEcosystems: DEPENDENCY_ENGINE_ECOSYSTEMS,
    total: web + polish + codeScan + axe + DEPENDENCY_ENGINE_ECOSYSTEMS,
  };
}

/** Reads the analyzer protections promised by the public disclosure. */
function analyzerProtections(read) {
  const source = read(ANALYZER);
  const prose = source.replace(/^\s*\/\/+/gm, " ").replace(/\s+/g, " ");
  const rules = read(PRIVATE_NETWORK_RULES);
  const rulesProse = rules.replace(/^\s*\/\/+/gm, " ").replace(/\s+/g, " ");
  return {
    validatesScanTarget: source.includes("network_policy::validate_url("),
    revalidatesNavigations: source.includes("on_navigation"),
    usesRedirectPolicy: source.includes("UrlPolicy::Redirect"),
    isPrivateWindow: source.includes("incognito(true)"),
    deniesNewWindows: source.includes("NewWindowResponse::Deny"),
    refusesDownloads: source.includes("on_download(|_, _| false)"),
    disclaimsSubresourceInterception: prose.includes(SUBRESOURCE_DISCLAIMER),
    privateNetworkSubresourceRulePlatforms: analyzerRulePlatforms(rules),
    // Every other platform arm must refuse rather than scan with the LAN
    // reachable, and analyze_url must only navigate on an explicit true.
    failsClosedWithoutRules:
      source.includes("Ok(Ok(true)) => {}") && fallbackRulesArmFailsClosed(rules),
    // The lockdown runs in every frame, not only the top document.
    locksWebRtcInAllFrames:
      source.includes("initialization_script_for_all_frames(") &&
      source.includes("WEBRTC_LOCKDOWN_SCRIPT") &&
      ["RTCPeerConnection", "webkitRTCPeerConnection", "WebTransport"].every((name) =>
        read(WEBRTC_LOCKDOWN).includes(`"${name}"`),
      ),
    // The gap the rules cannot close stays written down at the source.
    disclaimsResolvedPrivateAddresses: rulesProse.includes(RESOLVED_PRIVATE_DISCLAIMER),
  };
}

/** The installer arm for platforms without a filter must signal false and never true. */
function fallbackRulesArmFailsClosed(rulesSource) {
  const marker =
    '#[cfg(not(any(target_os = "macos", windows)))]\npub(crate) fn install_private_network_rules';
  const start = rulesSource.indexOf(marker);
  if (start < 0) return false;
  const rest = rulesSource.slice(start);
  const arm = rest.slice(0, rest.indexOf("\n}\n"));
  return arm.includes("ready.signal(false)") && !arm.includes("ready.signal(true)");
}

/** Platforms with a real installer for the analyzer's private-network rules. */
function analyzerRulePlatforms(rulesSource) {
  const arms = [
    ["macos", /#\[cfg\(target_os = "macos"\)\]\s*pub\(crate\) fn install_private_network_rules/],
    ["windows", /#\[cfg\(windows\)\]\s*pub\(crate\) fn install_private_network_rules/],
    ["linux", /#\[cfg\(target_os = "linux"\)\]\s*pub\(crate\) fn install_private_network_rules/],
  ];
  return arms.filter(([, pattern]) => pattern.test(rulesSource)).map(([platform]) => platform);
}

/** Evaluates the simple numeric expressions used by Rust constants. */
function rustNumber(source, name, file) {
  const expression = extract(
    source,
    new RegExp(`const ${name}\\b[^=]*=\\s*([^;]+);`),
    name,
    file,
  ).trim();
  const seconds = expression.match(/from_secs\((\d+)\)/);
  const factors = (seconds ? seconds[1] : expression).split("*").map((part) => Number(part.trim()));
  if (factors.some((factor) => !Number.isFinite(factor))) {
    throw new Error(`product-facts: ${name} in ${file} is no longer a plain number: ${expression}`);
  }
  return factors.reduce((product, factor) => product * factor, 1);
}

/** Reads the sitemap declaration bound and conventional candidate paths. */
function sitemapWalk(read) {
  const declaredLimit = rustNumber(read(SITEMAP), "SITEMAP_DECLARATION_PROBE_LIMIT", SITEMAP);
  const block = extract(
    read(SITEMAP_DOCUMENT),
    /SITEMAP_CANDIDATE_PATHS: \[&str; \d+\] = \[([\s\S]*?)\];/,
    "SITEMAP_CANDIDATE_PATHS",
    SITEMAP_DOCUMENT,
  );
  const candidatePaths = [...block.matchAll(/"(\/[^"]+)"/g)].map(([, path]) => path);
  if (candidatePaths.length === 0) {
    throw new Error(`product-facts: no SITEMAP_CANDIDATE_PATHS found in ${SITEMAP_DOCUMENT}`);
  }
  return { declaredLimit, candidatePaths };
}

function scannerIdentity(read) {
  const agentSource = read(AGENT);
  const docsUrl = extract(
    agentSource,
    /SCANNER_DOCS_URL: &str = "([^"]+)"/,
    "SCANNER_DOCS_URL",
    AGENT,
  );
  const userAgentFormat = extract(
    agentSource,
    /format!\("([^"]+)"\)/,
    "the User-Agent format string",
    AGENT,
  ).replace("{SCANNER_DOCS_URL}", docsUrl);

  const methodBlock = extract(
    read(PROBE),
    /pub enum ProbeMethod \{([^}]*)\}/,
    "the ProbeMethod variants",
    PROBE,
  );
  const methods = [...methodBlock.matchAll(/^\s*(\w+),/gm)].map(([, variant]) =>
    variant.toUpperCase(),
  );
  if (methods.length === 0) {
    throw new Error(`product-facts: no ProbeMethod variants found in ${PROBE}`);
  }

  const pathBlock = extract(
    read(EXPOSED_FILES),
    /SENSITIVE_PATHS: &\[\(&str, &str, Severity\)\] = &\[([\s\S]*?)\n\];/,
    "SENSITIVE_PATHS",
    EXPOSED_FILES,
  );
  const sensitivePaths = [
    ...pathBlock.matchAll(/\(\s*"([^"]+)",\s*"([^"]+)",\s*Severity::(\w+)\s*,?\s*\)/g),
  ].map(([, path, description, severity]) => ({
    path,
    description,
    severity: severity.toLowerCase(),
  }));
  if (sensitivePaths.length === 0) {
    throw new Error(`product-facts: no SENSITIVE_PATHS entries found in ${EXPOSED_FILES}`);
  }

  const constants = read(CONSTANTS);
  return {
    docsUrl,
    userAgentFormat,
    methods,
    sensitivePaths,
    sitemapWalk: sitemapWalk(read),
    limits: {
      redirectHops: rustNumber(constants, "MAX_REDIRECT_HOPS", CONSTANTS),
      checkTimeoutSeconds: rustNumber(constants, "CHECK_TIMEOUT", CONSTANTS),
      pageBodyMaxBytes: rustNumber(constants, "MAX_BODY_SIZE", CONSTANTS),
      probeBodyMaxBytes: rustNumber(constants, "MAX_PROBE_BODY_SIZE", CONSTANTS),
      sitemapBodyMaxBytes: rustNumber(constants, "MAX_SITEMAP_SIZE", CONSTANTS),
      assetSampleLimit: rustNumber(read(ASSETS), "ASSET_SAMPLE_LIMIT", ASSETS),
      stylesheetMaxCount: rustNumber(read(CSS_FETCH), "MAX_CSS_FILES", CSS_FETCH),
    },
  };
}

export function productFacts(read, listFiles) {
  const checkCounts = deriveCheckCounts(read, listFiles);
  return {
    sentryIngestHost: extract(
      read(TELEMETRY_WRAPPER),
      /SENTRY_INGEST_HOST = "([^"]+)"/,
      "SENTRY_INGEST_HOST",
      TELEMETRY_WRAPPER,
    ),
    licenseActivateScheme: extract(
      read(DEEP_LINKS),
      /LICENSE_ACTIVATE_SCHEME: &str = "([^"]+)"/,
      "LICENSE_ACTIVATE_SCHEME",
      DEEP_LINKS,
    ),
    commercialModel: JSON.parse(read(COMMERCIAL_MODEL)),
    productSurfaceStatus: PRODUCT_SURFACE_STATUS,
    checkCounts,
    hostedCheckCounts: deriveHostedCheckCounts(read, checkCounts.axe),
    polishSignals: JSON.parse(read(POLISH_SIGNALS)).signals,
    telemetryEnvelopeTierIsPlaceholder: /tier:\s*"unknown"/.test(
      read(TELEMETRY_WRAPPER).slice(read(TELEMETRY_WRAPPER).indexOf("function buildEnvelope")),
    ),
    analyzerProtections: analyzerProtections(read),
    scannerIdentity: scannerIdentity(read),
  };
}

export const PRODUCT_FACTS_FILE = "product-facts.json";
