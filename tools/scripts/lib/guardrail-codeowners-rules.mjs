const REQUIRED_PATTERNS = [
  "/.github/",
  "/renovate.json",
  "/pnpm-lock.yaml",
  "/pnpm-workspace.yaml",
  "/LICENSE",
  "/NOTICE",
  "/THIRD_PARTY_NOTICES",
  "/THIRD_PARTY_DEPENDENCIES.json",
  "/THIRD_PARTY_LICENSES.txt",
  "/SECURITY.md",
  "/install.sh",
  "/tools/scripts/",
  "/apps/desktop/src-tauri/Cargo.toml",
  "/apps/desktop/src-tauri/Cargo.lock",
  "/apps/desktop/src-tauri/build_config.rs",
  "/apps/desktop/src-tauri/crates/runtime/",
  "/apps/desktop/src-tauri/src/runtime.rs",
  "/apps/desktop/src-tauri/src/network_policy.rs",
  "/apps/desktop/src-tauri/crates/protocol/src/network_class.rs",
  "/apps/desktop/src-tauri/crates/protocol/src/database_env.rs",
  "/apps/desktop/src-tauri/src/updates/",
];

export function codeOwnerSafetyFailures(read) {
  const source = read(".github/CODEOWNERS");
  const ownedPatterns = new Set(
    source
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => line.split(/\s+/)[0]),
  );
  const missing = REQUIRED_PATTERNS.filter((pattern) => !ownedPatterns.has(pattern));
  return missing.length === 0
    ? []
    : [
        `CODEOWNERS must protect every release, dependency, network and privacy boundary: ${missing.join(", ")}`,
      ];
}
