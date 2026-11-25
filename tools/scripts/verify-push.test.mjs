import { execFileSync, spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";

import { beforeAll, describe, expect, it, vi } from "vitest";

import { workerCount } from "./lib/test-workers.mjs";
import { isolatedGitEnvironment, resolveRepositoryRoot } from "./verify-push-lib.mjs";

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal()),
  spawn: vi.fn(),
}));

const msrvWorkflow = readFileSync(
  new URL("../../.github/workflows/ci.yml", import.meta.url),
  "utf8",
);
const msrv = /rustup toolchain install (\d+\.\d+\.\d+)/.exec(msrvWorkflow)?.[1];
const tierFourCommands = [
  "cargo nextest run --no-fail-fast --workspace",
  "cargo clippy --workspace --all-targets -- -D warnings",
  "cargo clippy --manifest-path crates/cli/Cargo.toml --all-targets -- -D warnings",
  `cargo +${msrv} check --locked --workspace --all-targets`,
  `cargo +${msrv} check --locked --manifest-path crates/cli/Cargo.toml --all-targets`,
];

async function runWithFakeChecks(cargoJobs) {
  const checks = new Map();
  const events = [];
  const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
  vi.stubEnv("VITEST_MAX_WORKERS", "4");
  vi.stubEnv("CARGO_BUILD_JOBS", cargoJobs);
  vi.mocked(spawn).mockImplementation((_shell, [_flag, command], { env }) => {
    const child = new EventEmitter();
    checks.set(command, {
      jobs: env.CARGO_BUILD_JOBS,
      output: env.SITECMD_VERIFY_ENGINE_OUT,
      wasm: env.SITECMD_ENGINE_WASM,
      unpinned: env.SITECMD_ENGINE_UNPINNED,
    });
    events.push([command, "start"]);
    setImmediate(() => {
      events.push([command, "finish"]);
      child.emit("close", 0);
    });
    return child;
  });

  try {
    vi.resetModules();
    await import("./verify-push.mjs");
    await vi.waitFor(() => {
      expect(stderr).toHaveBeenCalledWith(
        expect.stringContaining("verify-push: all checks passed"),
      );
    });
    return { checks, events };
  } finally {
    stderr.mockRestore();
    vi.mocked(spawn).mockReset();
    vi.unstubAllEnvs();
  }
}

describe("push-hook Git environment", () => {
  it("keeps a dependency repository reset from changing the checkout being verified", () => {
    const scratch = mkdtempSync(join(tmpdir(), "sitecmd-push-git-"));
    const checkout = join(scratch, "checkout");
    const dependency = join(scratch, "dependency");
    const environment = {
      ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_"))),
      GIT_CONFIG_GLOBAL: devNull,
      GIT_CONFIG_SYSTEM: devNull,
      GIT_AUTHOR_NAME: "Fixture",
      GIT_AUTHOR_EMAIL: "fixture@example.invalid",
      GIT_COMMITTER_NAME: "Fixture",
      GIT_COMMITTER_EMAIL: "fixture@example.invalid",
      CI: "1",
    };
    const git = (cwd, args, env = environment) =>
      execFileSync("git", args, {
        cwd,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    try {
      mkdirSync(checkout);
      git(checkout, ["init", "-q", "-b", "main"]);
      git(checkout, ["commit", "--allow-empty", "-qm", "Initial"]);
      const base = git(checkout, ["rev-parse", "HEAD"]);
      git(checkout, ["commit", "--allow-empty", "-qm", "Next"]);
      const head = git(checkout, ["rev-parse", "HEAD"]);
      git(scratch, ["clone", "-q", checkout, dependency]);
      const hookEnvironment = {
        ...environment,
        GIT_DIR: join(checkout, ".git"),
        GIT_INDEX_FILE: join(checkout, ".git", "index"),
        GIT_PREFIX: "",
      };
      const isolated = isolatedGitEnvironment(checkout, hookEnvironment);
      git(dependency, ["reset", "--hard", base], isolated);
      expect(git(checkout, ["rev-parse", "HEAD"])).toBe(head);
      expect(git(dependency, ["rev-parse", "HEAD"])).toBe(base);
      expect(isolated.CI).toBe("1");
      expect(isolated).not.toHaveProperty("GIT_INDEX_FILE");
      expect(hookEnvironment.GIT_DIR).toBe(join(checkout, ".git"));
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe("repository root resolution", () => {
  it("decodes spaces in checkout paths", () => {
    expect(
      resolveRepositoryRoot(
        "file:///Users/dev/My%20Projects/SiteCMD/tools/scripts/verify-push.mjs",
      ),
    ).toBe("/Users/dev/My Projects/SiteCMD");
  });
});

describe("local verification resource isolation", () => {
  let result;

  beforeAll(async () => {
    result = await runWithFakeChecks(undefined);
  });

  it("starts each Tier 4 Cargo child after the previous one finishes", () => {
    const rustEvents = result.events.filter(([command]) => tierFourCommands.includes(command));
    expect(rustEvents).toEqual(
      tierFourCommands.flatMap((command) => [
        [command, "start"],
        [command, "finish"],
      ]),
    );
  });

  it("gives each Tier 4 Cargo child the full worker budget", () => {
    const workers = workerCount({ env: { VITEST_MAX_WORKERS: "4" } });
    expect(tierFourCommands.map((command) => result.checks.get(command)?.jobs)).toEqual(
      tierFourCommands.map(() => String(workers)),
    );
    for (const [command, check] of result.checks) {
      if (command.startsWith("cargo ")) expect(check.jobs, command).toBe(String(workers));
    }
  });

  it.each(["7", ""])("keeps the caller's Cargo job setting (%j)", async (jobs) => {
    const { checks } = await runWithFakeChecks(jobs);
    expect(tierFourCommands.map((command) => checks.get(command)?.jobs)).toEqual(
      tierFourCommands.map(() => jobs),
    );
  });

  it("keeps non-Cargo steps in another tier concurrent", () => {
    const lint = "pnpm run lint";
    const prettier = "pnpm exec prettier --check .";
    expect(result.events.filter(([command]) => command === lint || command === prettier)).toEqual([
      [lint, "start"],
      [prettier, "start"],
      [lint, "finish"],
      [prettier, "finish"],
    ]);
  });

  it("runs doctests after nextest, since both build the same test-profile libraries", () => {
    const nextest = tierFourCommands[0];
    const doctests = "cargo test --doc --workspace";
    expect(
      result.events.filter(([command]) => command === nextest || command === doctests),
    ).toEqual([
      [nextest, "start"],
      [nextest, "finish"],
      [doctests, "start"],
      [doctests, "finish"],
    ]);
  });

  it("provides a freshly built module before checks compile the engine host", () => {
    const standin = result.events[0][0];
    expect(standin).toContain('build-standin.mjs --out "$SITECMD_VERIFY_ENGINE_OUT"');
    expect(result.events.slice(0, 2)).toEqual([
      [standin, "start"],
      [standin, "finish"],
    ]);
    const { output } = result.checks.get(standin);
    expect(output).toBeTruthy();
    for (const [command, check] of result.checks) {
      expect(check.wasm, command).toBe(join(output, "sitecmd_engine_standin.wasm"));
      expect(check.unpinned, command).toBe("1");
    }
  });

  it("runs private guardrail tests only in the engine checkout", () => {
    const scripts = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    ).scripts;
    const testScript = "private:guardrails:test";
    const privateCheck =
      /tools\/engine\/|private:guardrails|\bsitecmd-(?:engine-wasm|local-engine|code-scan)\b/;
    const scriptNames = [...result.checks.keys()]
      .filter((command) => privateCheck.test(command))
      .map((command) => command.split(" ").at(-1));
    expect(scriptNames).toEqual(Object.hasOwn(scripts, testScript) ? [testScript] : []);
  });

  it("mirrors dependency policy and the declared Rust MSRV", () => {
    expect(msrv).toBeTruthy();
    expect(result.checks.has("pnpm run audit:deps:rust-policy")).toBe(true);
    expect(result.checks.has(`cargo +${msrv} check --locked --workspace --all-targets`)).toBe(true);
    expect(
      result.checks.has(
        `cargo +${msrv} check --locked --manifest-path crates/cli/Cargo.toml --all-targets`,
      ),
    ).toBe(true);
  });
});
