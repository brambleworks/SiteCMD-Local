import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { invocationFor, isEntryPoint, run } from "./sitecmd.mjs";

describe("checkout CLI", () => {
  it.each([
    { args: [] },
    { args: ["--help"] },
    { args: ["--version"] },
    { args: ["help"] },
    { args: ["scan", "--url", "https://example.com"] },
    { args: ["audit", ".", "--format", "json"] },
    { args: ["init"] },
    { args: ["fix"] },
    { args: ["watch"] },
    { args: ["check"] },
    { args: ["connected", "--dry-run"] },
    { args: ["deploy"] },
    { args: ["gate"] },
    { args: ["future-command"] },
  ])("forwards $args to the shipped CLI", ({ args }) => {
    const invocation = invocationFor(args);
    expect(invocation.command).toBe("cargo");
    expect(invocation.args.slice(invocation.args.indexOf("--") + 1)).toEqual(args);
    expect(invocation.args).toContain("--locked");
    expect(invocation.args[0]).toBe("run");
    expect(invocation.env.RUSTUP_TOOLCHAIN).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("strips only pnpm's leading separator and preserves argument contents", () => {
    const args = ["audit", "path with spaces", "--output", "$(touch nope);report.json", "--"];
    expect(invocationFor(["--", ...args])).toEqual(invocationFor(args));
  });

  it.each([0, 1, 2])("preserves child exit status %i", async (status) => {
    const child = new EventEmitter();
    const launch = vi.fn(() => child);
    const result = run(["audit", "."], launch);
    child.emit("exit", status, null);
    await expect(result).resolves.toBe(status);
    const options = launch.mock.calls[0][2];
    expect(options.stdio).toBe("inherit");
    expect(options.cwd).toBeUndefined();
    expect(options.env.RUSTUP_TOOLCHAIN).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("reports launch failures and removes signal listeners", async () => {
    const before = process.listenerCount("SIGINT");
    const child = new EventEmitter();
    const result = run(["--version"], () => child);
    child.emit("error", new Error("cargo is unavailable"));
    await expect(result).rejects.toThrow("cargo is unavailable");
    expect(process.listenerCount("SIGINT")).toBe(before);
  });
});

it("runs when started through a linked bin", () => {
  // Bug: the entry check compared path.resolve(argv[1]) with this file, so a
  // globally linked `sitecmd` exited 0 having run nothing.
  const script = fileURLToPath(new URL("./sitecmd.mjs", import.meta.url));
  const directory = mkdtempSync(path.join(tmpdir(), "sitecmd-bin-"));
  try {
    const link = path.join(directory, "sitecmd");
    symlinkSync(script, link);
    expect(path.resolve(link)).not.toBe(script);
    expect(isEntryPoint(link)).toBe(true);
    expect(isEntryPoint(script)).toBe(true);
    expect(isEntryPoint(path.join(directory, "missing"))).toBe(false);
    expect(isEntryPoint(undefined)).toBe(false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
