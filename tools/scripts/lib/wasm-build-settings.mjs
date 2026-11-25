import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);
export const cargoRoot = path.join(repoRoot, "apps", "desktop", "src-tauri");

/** Cargo profile shared by every vendored WASM artifact. */
export const WASM_PROFILE = "wasm-release";
export const WASM_TARGET = "wasm32-unknown-unknown";
/** Where the remap puts the Cargo home and the checkout inside the artifact. */
const CARGO_HOME_PLACEHOLDER = "/cargo";
const REPO_ROOT_PLACEHOLDER = "/sitecmd";
export const WASM_RUSTFLAGS = [
  "-C",
  "target-feature=+simd128",
  `--remap-path-prefix=<CARGO_HOME>=${CARGO_HOME_PLACEHOLDER}`,
  `--remap-path-prefix=<REPO_ROOT>=${REPO_ROOT_PLACEHOLDER}`,
];

/** Reject machine-local paths before any artifact is vendored. */
export function assertPortableArtifact(bytes, localPaths) {
  for (const raw of localPaths) {
    // A trailing separator would put a path character after every match.
    const localPath = raw.replace(/[\\/]+$/, "");
    const root = path.parse(localPath).root;
    if (
      !localPath ||
      localPath === root ||
      localPath === CARGO_HOME_PLACEHOLDER ||
      localPath === REPO_ROOT_PLACEHOLDER
    )
      continue;
    const needle = Buffer.from(localPath);
    const singleSegment = path.dirname(localPath) === root;
    for (let at = bytes.indexOf(needle); at !== -1; at = bytes.indexOf(needle, at + 1)) {
      const next = String.fromCharCode(bytes[at + needle.length]);
      if (!/[A-Za-z0-9._-]/.test(next) && (!singleSegment || bytes[at - 1] === 0)) {
        throw new Error(`WASM artifact contains local path: ${localPath}`);
      }
    }
  }
}

export function run(command, commandArgs, options = {}) {
  return execFileSync(command, commandArgs, { encoding: "utf8", ...options }).trim();
}
