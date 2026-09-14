import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { invocationFor, run } from "./sitecmd.mjs";

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

  it("opens desktop navigation only under the open subcommand", () => {
    const invocation = invocationFor(["open", "scan", "--project", "12"], "darwin");
    expect(invocation).toEqual({
      command: "open",
      args: ["sitecmd://open?page=scans&projectId=12"],
    });
    expect(invocationFor(["scan"]).command).toBe("cargo");
  });

  it.each([{ args: ["--project", "NaN"] }, { args: ["--unknown", "value"] }, { args: ["--url"] }])(
    "rejects invalid desktop options $args",
    ({ args }) => {
      expect(() => invocationFor(["open", "dashboard", ...args])).toThrow();
    },
  );

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
