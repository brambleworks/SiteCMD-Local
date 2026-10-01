import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
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

export function run(command, commandArgs, options = {}) {
  return execFileSync(command, commandArgs, { encoding: "utf8", ...options }).trim();
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Refuse dirty engine trees unless provenance is explicitly marked dirty. */
export function engineTreeSuffix(allowDirty, paths = ["apps/desktop/src-tauri/crates"]) {
  const dirty = run("git", ["status", "--porcelain", "--", ...paths], { cwd: repoRoot });
  if (dirty && !allowDirty) {
    console.error(
      `${paths.join(", ")} has uncommitted changes; commit first or pass --allow-dirty:`,
    );
    console.error(dirty);
    process.exit(1);
  }
  return dirty ? "-dirty" : "";
}

/** Build the WASM artifact with the requested feature set. */
export function buildWasmArtifact({ features = [] } = {}) {
  const label = features.length > 0 ? ` (features: ${features.join(",")})` : "";
  console.log(`building sitecmd-engine-wasm${label}...`);
  execFileSync(
    "cargo",
    [
      "build",
      "-p",
      "sitecmd-engine-wasm",
      "--target",
      WASM_TARGET,
      "--profile",
      WASM_PROFILE,
      ...(features.length > 0 ? ["--features", features.join(",")] : []),
    ],
    { cwd: cargoRoot, stdio: "inherit" },
  );
  return path.join(cargoRoot, "target", WASM_TARGET, WASM_PROFILE, "sitecmd_engine_wasm.wasm");
}

/** Write content files and then their provenance record as one vendored set. */
export function vendorSet({ outDir, files, record, recordName }) {
  mkdirSync(outDir, { recursive: true });
  for (const file of files) {
    writeFileSync(path.join(outDir, file.name), file.bytes);
  }
  writeFileSync(path.join(outDir, recordName), `${JSON.stringify(record, null, 2)}\n`);

  console.log(`vendored to ${outDir}`);
  for (const file of files) {
    console.log(
      `  ${file.name}  ${(file.bytes.length / 1024).toFixed(1)} KB  sha256 ${sha256(file.bytes)}`,
    );
  }
  console.log(`  engine commit ${record.engine_commit}`);
}

/** The `--out <dir>` override every vendor script accepts, resolved. */
export function outDirFrom(args, fallbackParts) {
  const flag = args.indexOf("--out");
  if (flag >= 0 && args[flag + 1]) return path.resolve(args[flag + 1]);
  return path.resolve(repoRoot, "..", ...fallbackParts);
}
