import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import process from "node:process";
import {
  assertPortableArtifact,
  cargoRoot,
  repoRoot,
  run,
  WASM_PROFILE,
  WASM_RUSTFLAGS,
  WASM_TARGET,
} from "./wasm-build-settings.mjs";

function assertPinnedRustc(rustc, options) {
  const toolchain = readFileSync(path.join(cargoRoot, "rust-toolchain.toml"), "utf8");
  const pinned = /^channel[ \t]*=[ \t]*"(\d+\.\d+\.\d+)"/m.exec(toolchain)?.[1];
  if (!pinned) throw new Error("rust-toolchain.toml must pin a Rust version for WASM builds.");

  let output;
  try {
    output = run(rustc, ["-V"], options);
  } catch (cause) {
    throw new Error(`Could not run rustc -V for WASM build. Expected Rust ${pinned}.`, { cause });
  }
  const [name, version] = output.split(/\s+/);
  if (name !== "rustc" || version !== pinned) {
    throw new Error(
      `WASM build requires Rust ${pinned} from rust-toolchain.toml. rustc -V reported "${output}".`,
    );
  }
}

/** Build the WASM artifact with the requested feature set. */
export function buildWasmArtifact({ features = [], packageName }) {
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
  const rustc = process.env.RUSTC || process.env.CARGO_BUILD_RUSTC || "rustc";
  const options = {
    cwd: cargoRoot,
    env: { ...process.env, RUSTC: rustc, CARGO_ENCODED_RUSTFLAGS: rustflags },
  };
  assertPinnedRustc(rustc, options);

  const label = features.length > 0 ? ` (features: ${features.join(",")})` : "";
  console.log(`building ${packageName}${label}...`);
  execFileSync(
    "cargo",
    [
      "build",
      "--locked",
      "-p",
      packageName,
      "--target",
      WASM_TARGET,
      "--profile",
      WASM_PROFILE,
      ...(features.length > 0 ? ["--features", features.join(",")] : []),
    ],
    { ...options, stdio: "inherit" },
  );
  const targetDir = path.resolve(
    cargoRoot,
    process.env.CARGO_TARGET_DIR || process.env.CARGO_BUILD_TARGET_DIR || "target",
  );
  const artifactPath = path.join(
    targetDir,
    WASM_TARGET,
    WASM_PROFILE,
    `${packageName.replaceAll("-", "_")}.wasm`,
  );
  assertPortableArtifact(readFileSync(artifactPath), [cargoHome, repoRoot, homedir()]);
  return artifactPath;
}
