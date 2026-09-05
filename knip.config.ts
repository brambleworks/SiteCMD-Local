import type { KnipConfig } from "knip";

// Single Knip configuration for workspace code inside each project glob.
// Assets outside those globs do not need redundant ignore entries.
const config: KnipConfig = {
  // Exclude local benchmark clones missed by nested gitignore handling.
  ignore: ["tools/benchmark/.work/**"],
  ignoreBinaries: [
    // Separately installed native desktop WebDriver.
    "tauri-driver",
    // POSIX utility used to construct benchmark filesystem fixtures.
    "mkfifo",
    // OS process lookup used by the development restart preflight.
    "pgrep",
    // Rustup-provided toolchain binary.
    "rustc",
    // Independently installed secret scanner.
    "gitleaks",
    // Toolchain binary used to locate the pinned actionlint installation.
    "go",
  ],
  workspaces: {
    ".": {
      entry: [
        "tools/scripts/tauri-attach-lib.mjs",
        // One-shot audit CLIs invoked outside package scripts.
        "tools/scripts/audit/file-sizes.mjs",
        "tools/scripts/audit/rust-function-lengths.mjs",
        // Manual hosted-runner WASM vendor entry points.
        "tools/scripts/build-scorer-wasm.mjs",
        "tools/scripts/build-checks-wasm.mjs",
        // Bare command paths invoked by verify-push.mjs.
        "tools/scripts/cli-smoke.mjs",
        "tools/scripts/audit/check-rust-toolchain.mjs",
      ],
      project: ["tools/scripts/**/*.{mjs,ts}"],
    },
    "apps/desktop": {
      // Playwright specs are entry points; fixtures are reached from them.
      entry: ["e2e/**/*.spec.ts"],
      // Generated IPC bindings intentionally export more than the frontend imports.
      project: ["src/**/*.{ts,tsx}", "e2e/**/*.ts", "!src/generated/**"],
      // Treat tests as entry points.
      vitest: {
        config: "vitest.config.ts",
        entry: ["src/**/*.{test,spec,behavior,render}.{ts,tsx}"],
      },
    },
    "apps/mcp-server": {
      // Source server entry; the bundle script is inferred from package.json.
      entry: ["src/index.ts", "test/**/*.test.mjs"],
      project: ["src/**/*.ts", "test/**/*.mjs"],
    },
  },
  // Block hard unused-code signals; report exports and types for manual triage.
  rules: {
    files: "error",
    dependencies: "error",
    devDependencies: "error",
    binaries: "error",
    unlisted: "error",
    duplicates: "error",
    exports: "warn",
    types: "warn",
    nsExports: "warn",
    nsTypes: "warn",
    enumMembers: "warn",
    namespaceMembers: "warn",
  },
};

export default config;
