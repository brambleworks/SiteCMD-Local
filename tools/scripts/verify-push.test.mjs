import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  classifyBindError,
  isolatedGitEnvironment,
  missingBrowserPaths,
  parseBrowserInstallLocations,
  resolveRepositoryRoot,
} from "./verify-push-lib.mjs";

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

describe("push-gate port preflight", () => {
  it("distinguishes an occupied port from other bind failures", () => {
    expect(classifyBindError({ code: "EADDRINUSE" })).toBe("occupied");
    expect(classifyBindError({ code: "EACCES" })).toBe("denied");
    expect(classifyBindError({ code: "EPERM" })).toBe("denied");
    expect(classifyBindError(new Error("network unavailable"))).toBe("unavailable");
  });

  it("does not report an unusable address as a permission failure", () => {
    expect(classifyBindError({ code: "EADDRNOTAVAIL" })).toBe("unavailable");
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

const DRY_RUN_OUTPUT = `Chrome for Testing 149.0.7827.55 (playwright chromium v1228)
  Install location:    /cache/ms-playwright/chromium-1228
  Download url:        https://cdn.playwright.dev/builds/cft/149.0.7827.55/mac-arm64/chrome-mac-arm64.zip

FFmpeg (playwright ffmpeg v1011)
  Install location:    /cache/ms-playwright/ffmpeg-1011
  Download url:        https://cdn.playwright.dev/builds/ffmpeg/1011/ffmpeg-mac-arm64.zip
  Download fallback 1: https://playwright.download.prss.microsoft.com/builds/ffmpeg/1011/ffmpeg-mac-arm64.zip

Chrome Headless Shell 149.0.7827.55 (playwright chromium-headless-shell v1228)
  Install location:    /cache/ms-playwright/chromium_headless_shell-1228
  Download url:        https://cdn.playwright.dev/builds/cft/149.0.7827.55/mac-arm64/chrome-headless-shell-mac-arm64.zip
`;

describe("playwright browser preflight", () => {
  it("reads every required install location, ignoring download URLs", () => {
    expect(parseBrowserInstallLocations(DRY_RUN_OUTPUT)).toEqual([
      "/cache/ms-playwright/chromium-1228",
      "/cache/ms-playwright/ffmpeg-1011",
      "/cache/ms-playwright/chromium_headless_shell-1228",
    ]);
  });

  it("passes when every browser is on disk", () => {
    expect(missingBrowserPaths(DRY_RUN_OUTPUT, () => true)).toEqual([]);
  });

  it("names only the browsers that are absent", () => {
    const present = new Set([
      "/cache/ms-playwright/chromium-1228",
      "/cache/ms-playwright/ffmpeg-1011",
    ]);
    expect(missingBrowserPaths(DRY_RUN_OUTPUT, (path) => present.has(path))).toEqual([
      "/cache/ms-playwright/chromium_headless_shell-1228",
    ]);
  });

  it("reports unparseable output instead of claiming everything is installed", () => {
    expect(missingBrowserPaths("Downloading Chromium...\ndone\n", () => false)).toBeNull();
    expect(missingBrowserPaths("", () => false)).toBeNull();
  });
});

describe("push-gate resource isolation", () => {
  it("does not run desktop UI tests beside the heavy Rust suite", () => {
    const source = readFileSync(
      fileURLToPath(new URL("./verify-push.mjs", import.meta.url)),
      "utf8",
    );
    const desktopTest = source.indexOf('name: "desktop-vitest"');
    expect(desktopTest).toBeGreaterThan(-1);
    const tierStart = source.lastIndexOf("  [", desktopTest);
    const tierEnd = source.indexOf("\n  ],", desktopTest);
    expect(tierStart).toBeGreaterThan(-1);
    expect(tierEnd).toBeGreaterThan(desktopTest);
    const desktopTier = source.slice(tierStart, tierEnd);
    expect(desktopTier).not.toContain('name: "rust-nextest"');
    expect(desktopTier).not.toContain('name: "rust-clippy"');
  });

  it("runs doctests after nextest, since both build the same test-profile libraries", () => {
    const source = readFileSync(
      fileURLToPath(new URL("./verify-push.mjs", import.meta.url)),
      "utf8",
    );
    const doctest = source.indexOf('name: "rust-doctest"');
    expect(doctest).toBeGreaterThan(-1);
    const tierStart = source.lastIndexOf("  [", doctest);
    const tierEnd = source.indexOf("\n  ],", doctest);
    expect(tierStart).toBeGreaterThan(-1);
    expect(tierEnd).toBeGreaterThan(doctest);
    expect(source.slice(tierStart, tierEnd)).not.toContain('name: "rust-nextest"');
    expect(source.indexOf('name: "rust-nextest"')).toBeLessThan(tierStart);
  });

  it("mirrors dependency policy and the declared Rust MSRV", () => {
    const source = readFileSync(
      fileURLToPath(new URL("./verify-push.mjs", import.meta.url)),
      "utf8",
    );
    const msrvWorkflow = readFileSync(
      fileURLToPath(new URL("../../.github/workflows/rust-msrv.yml", import.meta.url)),
      "utf8",
    );
    const msrv = /toolchain:\s*(\d+\.\d+\.\d+)/.exec(msrvWorkflow)?.[1];
    expect(msrv).toBeTruthy();
    expect(source).toContain('name: "audit:licenses:js"');
    expect(source).toContain('name: "cargo-deny"');
    expect(source).toContain(`cargo +${msrv} check --locked --workspace --all-targets`);
    expect(source).toContain(
      `cargo +${msrv} check --locked --manifest-path crates/cli/Cargo.toml --all-targets`,
    );
  });
});
