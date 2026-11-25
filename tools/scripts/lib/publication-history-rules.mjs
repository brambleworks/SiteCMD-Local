const PUBLIC_CLIENT_APPS = new Set(["desktop", "mcp-server"]);
const PRIVATE_STRATEGY_RECORD =
  /(?:^|\/)(?:publication-decision|paid-intelligence-rfc|commercial-terms-spec|connected-service-rfc)\.md$/;

const RUST_WORKSPACE = "apps/desktop/src-tauri";

export const ENGINE_PATHS = [
  `${RUST_WORKSPACE}/crates/engine/`,
  `${RUST_WORKSPACE}/crates/engine-wasm/`,
  `${RUST_WORKSPACE}/crates/engine-fuzz/`,
  `${RUST_WORKSPACE}/crates/code-scan/`,
  `${RUST_WORKSPACE}/crates/local-engine/`,
  `${RUST_WORKSPACE}/src/core/code_scan/`,
  `${RUST_WORKSPACE}/src/checks/`,
  `${RUST_WORKSPACE}/src/core/scanner`,
  `${RUST_WORKSPACE}/src/ai.rs`,
  `${RUST_WORKSPACE}/src/core/severity_policy`,
  `${RUST_WORKSPACE}/src/core/confidence_policy.rs`,
  `${RUST_WORKSPACE}/src/scoring/`,
  `${RUST_WORKSPACE}/src/core/fix_templates/fixers/`,
  `${RUST_WORKSPACE}/src/core/event_correlations`,
  `${RUST_WORKSPACE}/src/core/regression_blame`,
  `${RUST_WORKSPACE}/src/core/work_item_projection`,
  `${RUST_WORKSPACE}/src/core/fix_brief`,
  `${RUST_WORKSPACE}/tests/fixtures/code_scan/`,
  `${RUST_WORKSPACE}/tests/fixtures/parity/`,
  "crates/",
  "fixtures/",
  "open/",
  "tools/engine/",
  "docs/engine/",
  "product-facts.json",
  ".github/workflows/engine-",
  ".github/workflows/publish-capability-manifest.yml",
];

export const ENGINE_CRATES = [
  "sitecmd-engine",
  "sitecmd-engine-wasm",
  "sitecmd-engine-fuzz",
  "sitecmd-code-scan",
  "sitecmd-local-engine",
];

export const ENGINE_RUST_CRATES = ENGINE_CRATES.map((name) => name.replaceAll("-", "_"));

const WIRE_IDENTIFIERS = `${RUST_WORKSPACE}/tests/fixtures/parity/wire_identifiers.json`;
const LIBRARY_SUFFIX = /\.(?:rlib|rmeta|a|so|dylib|dll|lib)$/;

function isEngineArtifact(file) {
  const name = file.split("/").at(-1).replace(/^lib/, "");
  return (
    LIBRARY_SUFFIX.test(name) &&
    !/^sitecmd_engine_host[.-]/.test(name) &&
    ENGINE_RUST_CRATES.some((crate) => name.startsWith(crate))
  );
}

export function enginePathFailures(paths) {
  return paths.filter((file) => {
    if (file === WIRE_IDENTIFIERS) return false;
    const lower = file.toLowerCase();
    return (
      lower.endsWith(".wasm") ||
      isEngineArtifact(lower) ||
      ENGINE_PATHS.some((prefix) => {
        if (lower.startsWith(prefix)) return true;
        if (prefix.endsWith(".rs")) return lower.startsWith(prefix.slice(0, -3) + "/");
        if (prefix.endsWith(".yml")) return lower.startsWith(prefix.slice(0, -4) + ".yaml");
        if (!prefix.endsWith("/")) return false;
        const directory = prefix.slice(0, -1);
        return lower === directory || lower === directory + ".rs";
      })
    );
  });
}

/** Checks every path reachable from a proposed public ref. */
export function publicationHistoryPathFailures(paths) {
  const failures = [];
  const seen = new Set();
  const add = (failure) => {
    if (!seen.has(failure)) {
      seen.add(failure);
      failures.push(failure);
    }
  };

  for (const relativePath of paths) {
    if (PRIVATE_STRATEGY_RECORD.test(relativePath)) {
      add(`public history contains a private strategy record: ${relativePath}`);
    }

    const appMatch = relativePath.match(/^apps\/([^/]+)\//);
    if (appMatch && !PUBLIC_CLIENT_APPS.has(appMatch[1])) {
      add(`public history contains a private/non-client app tree: apps/${appMatch[1]}/`);
    }
  }

  return failures.sort();
}

export function candidateHistoryShapeFailures(commitCount, rootLine) {
  const failures = [];
  if (commitCount !== "1") {
    failures.push(`candidate main must contain exactly one commit (found ${commitCount})`);
  }
  if (rootLine.trim().split(/\s+/u).length !== 1) {
    failures.push("candidate main commit must have no parent");
  }
  return failures;
}
