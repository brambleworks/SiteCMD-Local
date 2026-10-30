import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import process from "node:process";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildWasmArtifact,
  assertPortableArtifact,
  cargoRoot,
  engineTreeSuffix,
  repoRoot,
  WASM_PROFILE,
  WASM_TARGET,
} from "./lib/wasm-vendor.mjs";

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal()),
  execFileSync: vi.fn(),
}));
vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal()),
  readFileSync: vi.fn(),
}));
vi.mock("node:os", async (importOriginal) => ({
  ...(await importOriginal()),
  homedir: () => "/Users/dev",
}));

let error;
let exit;

beforeEach(() => {
  vi.mocked(execFileSync).mockReturnValue("");
  vi.mocked(readFileSync).mockReturnValue(
    Buffer.from(
      "\0asm\0/cargo/registry/src/x.rs\0crates/engine/src/lib.rs\0builder/build/output\0browser/application\0/\x01\0/sitecmd/x.rs",
    ),
  );
  error = vi.spyOn(console, "error").mockImplementation(() => {});
  exit = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("exit");
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe("buildWasmArtifact", () => {
  it.each([{ features: [] }, { features: ["checks"] }])(
    "builds with recorded flags for $features",
    ({ features }) => {
      vi.stubEnv("CARGO_HOME", "/tmp/Cargo Home/.cargo");
      vi.stubEnv("RUSTFLAGS", "--cfg stale");
      vi.stubEnv("CARGO_ENCODED_RUSTFLAGS", "--cfg also_stale");
      expect(buildWasmArtifact({ features })).toBe(
        path.join(cargoRoot, "target", WASM_TARGET, WASM_PROFILE, "sitecmd_engine_wasm.wasm"),
      );
      expect(execFileSync).toHaveBeenCalledWith(
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
          ...(features.length ? ["--features", features.join(",")] : []),
        ],
        {
          cwd: cargoRoot,
          stdio: "inherit",
          env: {
            ...process.env,
            CARGO_ENCODED_RUSTFLAGS: `--remap-path-prefix=/tmp/Cargo Home/.cargo=/cargo\x1f--remap-path-prefix=${repoRoot}=/sitecmd`,
          },
        },
      );
    },
  );

  it.each([undefined, ""])("defaults Cargo home when CARGO_HOME is %j", (value) => {
    vi.stubEnv("CARGO_HOME", value);
    buildWasmArtifact();
    expect(vi.mocked(execFileSync).mock.calls[0][2].env.CARGO_ENCODED_RUSTFLAGS).toContain(
      `--remap-path-prefix=${path.join(homedir(), ".cargo")}=/cargo`,
    );
  });

  it("preserves literal dollar replacement tokens in Cargo home", () => {
    vi.stubEnv("CARGO_HOME", "/tmp/a$$b$&/.cargo");
    buildWasmArtifact();
    expect(vi.mocked(execFileSync).mock.calls[0][2].env.CARGO_ENCODED_RUSTFLAGS).toBe(
      `--remap-path-prefix=/tmp/a$$b$&/.cargo=/cargo\x1f--remap-path-prefix=${repoRoot}=/sitecmd`,
    );
  });

  it.each([repoRoot, path.join(repoRoot, ".cargo")])(
    "refuses overlapping Cargo home %s",
    (cargoHome) => {
      vi.stubEnv("CARGO_HOME", cargoHome);
      expect(() => buildWasmArtifact()).toThrow(
        `Cargo home must be outside the checkout: ${cargoHome}`,
      );
      expect(execFileSync).not.toHaveBeenCalled();
    },
  );

  it("accepts CARGO_HOME equal to its portable placeholder", () => {
    vi.stubEnv("CARGO_HOME", "/cargo");
    expect(() => buildWasmArtifact()).not.toThrow();
  });

  it.each(["/custom/cargo", repoRoot, homedir()])(
    "refuses a built artifact containing %s",
    (localPath) => {
      vi.stubEnv("CARGO_HOME", "/custom/cargo");
      vi.mocked(readFileSync).mockReturnValue(Buffer.from(`\0asm${localPath}/src/lib.rs`));
      expect(() => buildWasmArtifact()).toThrow(`WASM artifact contains local path: ${localPath}`);
    },
  );
});

describe("artifact path boundaries", () => {
  it("refuses a home path written with a trailing separator", () => {
    expect(() =>
      assertPortableArtifact(Buffer.from("\0asm\0/Users/dev/.cargo/registry/x.rs"), [
        "/Users/dev/",
      ]),
    ).toThrow("WASM artifact contains local path: /Users/dev");
  });

  it.each(["", "/", "/src", "/app", "/build", "/cargo", "/sitecmd"])(
    "accepts clean bytes for %j",
    (localPath) => {
      expect(() => assertPortableArtifact(readFileSync("unused"), [localPath])).not.toThrow();
    },
  );

  it.each(["a", "Z", "0", ".", "_", "-"])("ignores a path prefix followed by %s", (suffix) => {
    expect(() =>
      assertPortableArtifact(Buffer.from(`\0/custom/cargo${suffix}/x.rs`), ["/custom/cargo"]),
    ).not.toThrow();
  });

  it.each(["/src", "/build"])("refuses a NUL-prefixed short path %s", (localPath) => {
    expect(() =>
      assertPortableArtifact(Buffer.from(`\0asm\0${localPath}/x.rs`), [localPath]),
    ).toThrow(`WASM artifact contains local path: ${localPath}`);
  });
});

describe("artifact path guard process failure", () => {
  it.each(["/custom/cargo", repoRoot, homedir()])("exits non-zero and names %s", (localPath) => {
    const moduleUrl = new URL("./lib/wasm-vendor.mjs", import.meta.url).href;
    const result = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { assertPortableArtifact } from ${JSON.stringify(moduleUrl)};
       assertPortableArtifact(Buffer.from(${JSON.stringify(`\0asm${localPath}/lib.rs`)}),
         [${JSON.stringify(localPath)}]);`,
      ],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`WASM artifact contains local path: ${localPath}`);
  });
});

describe("engineTreeSuffix", () => {
  it("uses the engine crates as its default status scope", () => {
    expect(engineTreeSuffix(false)).toBe("");
    expect(execFileSync).toHaveBeenCalledWith(
      "git",
      ["status", "--porcelain", "--", "apps/desktop/src-tauri/crates"],
      { encoding: "utf8", cwd: repoRoot },
    );
  });

  it("uses exactly the caller's status scope", () => {
    expect(engineTreeSuffix(false, ["tools/scripts", "apps/desktop/src-tauri/src/core"])).toBe("");
    expect(execFileSync).toHaveBeenCalledWith(
      "git",
      ["status", "--porcelain", "--", "tools/scripts", "apps/desktop/src-tauri/src/core"],
      { encoding: "utf8", cwd: repoRoot },
    );
  });

  it("marks explicitly allowed uncommitted changes in provenance", () => {
    vi.mocked(execFileSync).mockReturnValue(" M tools/scripts/build-scorer-wasm.mjs\n");
    expect(engineTreeSuffix(true, ["tools/scripts"])).toBe("-dirty");
    expect(error).not.toHaveBeenCalled();
    expect(exit).not.toHaveBeenCalled();
  });

  it("names the default dirty scope and changed file in its refusal", () => {
    const dirty = "M apps/desktop/src-tauri/crates/engine/src/lib.rs";
    vi.mocked(execFileSync).mockReturnValue(` ${dirty}\n`);
    expect(() => engineTreeSuffix(false)).toThrow("exit");
    expect(error).toHaveBeenCalledWith(
      "apps/desktop/src-tauri/crates has uncommitted changes; commit first or pass --allow-dirty:",
    );
    expect(error).toHaveBeenCalledWith(dirty);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("names each custom dirty scope and changed file in its refusal", () => {
    const dirty = "M tools/scripts/build-scorer-wasm.mjs";
    vi.mocked(execFileSync).mockReturnValue(` ${dirty}\n`);
    expect(() =>
      engineTreeSuffix(false, ["tools/scripts", "apps/desktop/src-tauri/src/core"]),
    ).toThrow("exit");
    expect(error).toHaveBeenCalledWith(
      "tools/scripts, apps/desktop/src-tauri/src/core has uncommitted changes; commit first or pass --allow-dirty:",
    );
    expect(error).toHaveBeenCalledWith(dirty);
    expect(exit).toHaveBeenCalledWith(1);
  });
});
