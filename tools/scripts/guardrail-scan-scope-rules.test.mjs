import { describe, expect, it } from "vitest";
import { scanScopeFailures } from "./lib/guardrail-scan-scope-rules.mjs";

const ENGINE_ROUTE = "apps/desktop/src-tauri/crates/protocol/src/route.rs";
const SCHEDULER = "apps/desktop/src-tauri/src/background/scan_scheduler.rs";
const SCOPE_COMMANDS = "apps/desktop/src-tauri/src/commands/scan_scope.rs";
const OVERLAY_STATE = "apps/desktop/src/components/scan/useScanConfigOverlayState.ts";

const HEALTHY = {
  [ENGINE_ROUTE]: "pub const CANONICALIZER_VERSION: u8 = 1;",
  [SCHEDULER]: "let urls = crate::db::scan_scope_urls(db, &url);",
  [SCOPE_COMMANDS]: "let scope = build_scope(&entry, &routes, families, None)?;",
  [OVERLAY_STATE]: `
  const handleStart = useCallback(async () => {
    if (scanType === "code") {
      onStart({ urls: [], axeEnabled: false, scanType });
      return;
    }
    await setScanScope({ siteId, siteUrl, routes });
    onStart({ urls, axeEnabled, scanType });
  }, [siteUrl]);
`,
};

function failuresWith(overrides = {}) {
  const files = { ...HEALTHY, ...overrides };
  return scanScopeFailures((file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  });
}

describe("the two scan paths read one scope", () => {
  it("passes when every rule holds", () => {
    expect(failuresWith()).toEqual([]);
  });

  it("fails when the canonicalizer loses its version", () => {
    const found = failuresWith({ [ENGINE_ROUTE]: "pub fn canonical_path() {}" });
    expect(found.join("\n")).toContain("CANONICALIZER_VERSION");
  });
});
