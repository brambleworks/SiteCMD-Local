import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
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
/** Where the remap puts the Cargo home and the checkout inside the artifact. */
const CARGO_HOME_PLACEHOLDER = "/cargo";
const REPO_ROOT_PLACEHOLDER = "/sitecmd";
export const WASM_RUSTFLAGS = [
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
  const cargoHome = path.resolve(
    cargoRoot,
    process.env.CARGO_HOME || path.join(homedir(), ".cargo"),
  );
  const relativeHome = path.relative(repoRoot, cargoHome);
  if (
    !relativeHome ||
    (relativeHome !== ".." &&
      !relativeHome.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relativeHome))
  ) {
    throw new Error(`Cargo home must be outside the checkout: ${cargoHome}`);
  }
  const rustflags = WASM_RUSTFLAGS.map((flag) =>
    flag.replace("<CARGO_HOME>", () => cargoHome).replace("<REPO_ROOT>", () => repoRoot),
  ).join("\x1f");
  const label = features.length > 0 ? ` (features: ${features.join(",")})` : "";
  console.log(`building sitecmd-engine-wasm${label}...`);
  execFileSync(
    "cargo",
    [
      "build",
      "--locked",
      "-p",
      "sitecmd-engine-wasm",
      "--target",
      WASM_TARGET,
      "--profile",
      WASM_PROFILE,
      ...(features.length > 0 ? ["--features", features.join(",")] : []),
    ],
    {
      cwd: cargoRoot,
      stdio: "inherit",
      env: { ...process.env, CARGO_ENCODED_RUSTFLAGS: rustflags },
    },
  );
  const artifactPath = path.join(
    cargoRoot,
    "target",
    WASM_TARGET,
    WASM_PROFILE,
    "sitecmd_engine_wasm.wasm",
  );
  assertPortableArtifact(readFileSync(artifactPath), [cargoHome, repoRoot, homedir()]);
  return artifactPath;
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
