import { execFileSync } from "node:child_process";
import process from "node:process";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { engineTreeSuffix, repoRoot } from "./lib/wasm-vendor.mjs";

vi.mock("node:child_process", () => ({ execFileSync: vi.fn() }));

let error;
let exit;

beforeEach(() => {
  vi.mocked(execFileSync).mockReturnValue("");
  error = vi.spyOn(console, "error").mockImplementation(() => {});
  exit = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("exit");
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
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
