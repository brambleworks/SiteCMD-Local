import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  engineHostFailures,
  openCrateDependencyFailures,
  parseNormalWasmtimeFeatures,
} from "../lib/guardrail-engine-host-rules.mjs";

const cargoRoot = fileURLToPath(new URL("../../../apps/desktop/src-tauri/", import.meta.url));
const fixture = fileURLToPath(new URL("../testdata/deny-wasi/Cargo.toml", import.meta.url));
const options = { cwd: cargoRoot, encoding: "utf8" };

try {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--format-version", "1", "--all-features", "--locked"], {
      ...options,
      maxBuffer: 32 * 1024 * 1024,
    }),
  );
  // Cargo metadata combines normal, build, and dev features in each resolved node.
  const tree = execFileSync(
    "cargo",
    [
      "tree",
      "--locked",
      "--workspace",
      "--target",
      "all",
      "-e",
      "normal",
      "-i",
      "wasmtime",
      "--prefix",
      "none",
      "--format",
      "{p}\t{f}\t",
    ],
    options,
  );
  const normalFeatures = parseNormalWasmtimeFeatures(tree);
  if (normalFeatures.length === 0)
    throw new Error("Cargo did not resolve normal Wasmtime features.");
  const failures = [
    ...openCrateDependencyFailures(metadata),
    ...engineHostFailures(metadata, normalFeatures),
  ];
  if (failures.length > 0) throw new Error(failures.join("\n"));

  const checks = process.argv.includes("--no-advisories")
    ? ["licenses", "sources"]
    : ["advisories", "licenses", "sources"];
  execFileSync("cargo", ["deny", "check", ...checks], {
    ...options,
    stdio: "inherit",
  });
  execFileSync("cargo", ["deny", "--workspace", "check", "bans"], {
    ...options,
    stdio: "inherit",
  });

  // A dependency that grants filesystem or socket access must be rejected.
  const deny = spawnSync(
    "cargo",
    ["deny", "--manifest-path", fixture, "check", "bans", "--config", "deny.toml"],
    options,
  );
  if (deny.error) throw deny.error;
  const banned = ["wasi-common", "wasmtime-wasi"];
  if (
    deny.status !== 2 ||
    !banned.every((name) =>
      deny.stderr.includes(`error[banned]: crate '${name} = 0.0.0' is explicitly banned`),
    )
  ) {
    throw new Error(`The WASI bans fixture did not reject both crates:\n${deny.stderr}`);
  }
  console.log("Rust dependency policy passed. Both WASI fixture crates were rejected.");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
