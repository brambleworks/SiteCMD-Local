import { globSync } from "node:fs";
import type { KnipConfig } from "knip";

const extensions = await Promise.all(
  globSync("tools/*/tooling.config.mjs", { cwd: new URL(".", import.meta.url) }).map(
    (file) => import(new URL(file, import.meta.url).href),
  ),
);

// Single Knip configuration for workspace code inside each project glob.
// Assets outside those globs do not need redundant ignore entries.
const config: KnipConfig = {
  ignoreBinaries: [
    // Rustup-provided toolchain binary.
    "rustc",
    // Independently installed secret scanner.
    "gitleaks",
    // External verifier used to authenticate engine pin updates.
    "minisign",
    // Toolchain binary used to locate the pinned actionlint installation.
    "go",
  ],
  workspaces: {
    ".": {
      entry: [
        // One-shot audit CLIs invoked outside package scripts.
        "tools/scripts/audit/file-sizes.mjs",
        "tools/scripts/audit/rust-function-lengths.mjs",
        // The workflow extracts this entry point from a commit before running it.
        "tools/scripts/run-public-tree-check.mjs",
        ...extensions.flatMap((x) => x.knipEntry),
        // Shared queue verdict entry point reserved for future release wiring.
        "tools/scripts/ci-verdict.mjs",
      ],
      project: ["tools/scripts/**/*.{mjs,ts}", ...extensions.flatMap((x) => x.knipProject)],
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
