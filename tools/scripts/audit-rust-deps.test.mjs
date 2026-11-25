import { spawnSync } from "node:child_process";
import { afterEach, expect, it, vi } from "vitest";

vi.mock("node:child_process", () => ({ spawnSync: vi.fn() }));

afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.resetModules();
});

it("refuses the Chrono acceptance when Chrono is active", async () => {
  // A lockfile acceptance can conceal an active Chrono dependency.
  vi.mocked(spawnSync).mockReturnValue({ status: 0, stdout: "sitecmd v2.0.0\nchrono v0.4.45\n" });
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  const exit = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("exit");
  });

  await expect(import("./audit-rust-deps.mjs")).rejects.toThrow("exit");
  expect(exit).toHaveBeenCalledWith(1);
  expect(error).toHaveBeenCalledWith(
    "RUSTSEC-2026-0543: chrono is active in the Rust workspace dependency graph.",
  );
  expect(spawnSync).toHaveBeenCalledExactlyOnceWith(
    "cargo",
    expect.arrayContaining([
      "tree",
      "--locked",
      "--workspace",
      "--all-features",
      "--target",
      "all",
      "--edges",
      "normal,build,dev",
    ]),
    expect.any(Object),
  );
});

it("fails when Cargo cannot resolve the workspace graph", async () => {
  // Cargo can return a partial graph without Chrono before failing.
  vi.mocked(spawnSync).mockReturnValue({ status: 1, stdout: "sitecmd v2.0.0\n" });
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  const exit = vi.spyOn(process, "exit").mockImplementation(() => {
    throw new Error("exit");
  });

  await expect(import("./audit-rust-deps.mjs")).rejects.toThrow("exit");
  expect(exit).toHaveBeenCalledWith(1);
  expect(error).toHaveBeenCalledWith(
    "Cannot verify the Rust workspace dependency graph for RUSTSEC-2026-0543.",
  );
});
