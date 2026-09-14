import { VERSION_FILES } from "./version-files.mjs";

const RUST_MSRV = "1.89.0";
const RUST_MANIFESTS = [
  "apps/desktop/src-tauri/Cargo.toml",
  "apps/desktop/src-tauri/crates/cli/Cargo.toml",
  "apps/desktop/src-tauri/crates/runtime/Cargo.toml",
  "apps/desktop/src-tauri/crates/engine-fuzz/Cargo.toml",
  "apps/desktop/src-tauri/crates/engine/Cargo.toml",
  "apps/desktop/src-tauri/crates/engine-wasm/Cargo.toml",
];

export function versionSyncFailures(read) {
  const failures = [];
  const found = VERSION_FILES.map(({ file, read: extract }) => [file, extract(read(file))]);
  const versions = new Set(found.map(([, version]) => version));
  if (versions.size !== 1 || versions.has(undefined)) {
    failures.push(
      `SiteCMD version is out of sync across release files: ${found
        .map(([file, version]) => `${file}=${version ?? "MISSING"}`)
        .join("; ")}. Run \`pnpm release <version>\` to bump them together.`,
    );
  }

  const rustVersions = RUST_MANIFESTS.map((file) => [
    file,
    read(file).match(/^rust-version\s*=\s*"([^"]+)"/m)?.[1],
  ]);
  if (rustVersions.some(([, version]) => version !== RUST_MSRV)) {
    failures.push(
      `Rust MSRV is out of sync with the tested ${RUST_MSRV} floor: ${rustVersions
        .map(([file, version]) => `${file}=${version ?? "MISSING"}`)
        .join("; ")}.`,
    );
  }

  const nodeVersion = read(".nvmrc").trim().replace(/^v/, "");
  const rootPackage = JSON.parse(read("package.json"));
  const nodeMajor = Number.parseInt(nodeVersion.split(".")[0] ?? "", 10);
  const expectedNodeRange = `>=${nodeVersion} <${nodeMajor + 1}`;
  if (rootPackage.engines?.node !== expectedNodeRange) {
    failures.push(
      `The root Node engine must use .nvmrc as its minimum and stay within that major: expected ${expectedNodeRange}; found ${rootPackage.engines?.node ?? "MISSING"}.`,
    );
  }
  const runtime = rootPackage.devEngines?.runtime;
  if (
    runtime?.name !== "node" ||
    runtime?.version !== expectedNodeRange ||
    runtime?.onFail !== "error"
  ) {
    failures.push(
      "The root devEngines.runtime must enforce the same Node range as engines.node with onFail set to error.",
    );
  }
  if (!/^engineStrict:\s*true\s*$/m.test(read("pnpm-workspace.yaml"))) {
    failures.push(
      "pnpm-workspace.yaml must keep engineStrict enabled so incompatible dependency engines fail installation.",
    );
  }

  return failures;
}
