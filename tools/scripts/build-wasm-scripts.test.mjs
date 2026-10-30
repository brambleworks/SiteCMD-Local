import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { buildWasmArtifact, cargoRoot, sha256, vendorSet } from "./lib/wasm-vendor.mjs";

vi.mock("node:fs", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    readFileSync: (file, ...args) =>
      file === "/test-artifact.wasm" ? Buffer.from("\0asm") : original.readFileSync(file, ...args),
  };
});

vi.mock("./lib/wasm-vendor.mjs", async (importOriginal) => ({
  ...(await importOriginal()),
  buildWasmArtifact: vi.fn(() => "/test-artifact.wasm"),
  engineTreeSuffix: vi.fn(() => "-dirty"),
  vendorSet: vi.fn(),
  run: vi.fn((command) =>
    command === "cargo"
      ? JSON.stringify({ axe_core_version: "test", axe_run_script: "test" })
      : "test-revision",
  ),
}));

describe("WASM vendor records", () => {
  it.each(["checks", "scorer"])("records portable build inputs for %s", async (kind) => {
    vi.mocked(vendorSet).mockClear();
    vi.mocked(buildWasmArtifact).mockClear();
    await import(`./build-${kind}-wasm.mjs`);
    expect(buildWasmArtifact).toHaveBeenCalledWith(
      ...(kind === "checks" ? [{ features: ["checks"] }] : []),
    );
    expect(vendorSet).toHaveBeenCalledOnce();
    const { files, record, recordName } = vi.mocked(vendorSet).mock.calls[0][0];
    expect(recordName).toBe(`${kind}-artifact.json`);
    expect(record).toMatchObject({
      engine_commit: "test-revision-dirty",
      target: "wasm32-unknown-unknown",
      profile: "wasm-release",
      rustflags: [
        "--remap-path-prefix=<CARGO_HOME>=/cargo",
        "--remap-path-prefix=<REPO_ROOT>=/sitecmd",
      ],
      artifact_sha256: sha256(Buffer.from("\0asm")),
    });
    expect(files.find((file) => file.name === `${kind}.wasm`).bytes).toEqual(Buffer.from("\0asm"));
    if (kind === "checks") {
      const manifest = readFileSync(
        path.join(cargoRoot, "crates", "engine", "manifest", "capability_manifest.json"),
      );
      expect(files.find((file) => file.name === "capability_manifest.json").bytes).toEqual(
        manifest,
      );
      expect(record.capability_manifest_sha256).toBe(sha256(manifest));
      expect(record.manifest_digest).toBe(JSON.parse(manifest.toString()).manifest_digest);
    }
  });
});
