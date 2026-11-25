#!/usr/bin/env node

import { spawn } from "node:child_process";
import {
  appendFileSync,
  closeSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { workerCount } from "./lib/test-workers.mjs";
import { toolingEntries } from "./lib/tooling-entries.mjs";
import { isolatedGitEnvironment, resolveRepositoryRoot } from "./verify-push-lib.mjs";

const ROOT = resolveRepositoryRoot(import.meta.url);
const CHECK_ENV = isolatedGitEnvironment(ROOT, process.env);

const NO_BAIL = process.argv.slice(2).some((arg) => arg === "--no-bail" || arg === "--all");
const SHARED_CARGO_TARGET_TIER = 4;

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

/**
 * @typedef {Object} Check
 * @property {string} name Short progress label.
 * @property {string} cmd Shell command run through `/bin/bash -lc`.
 * @property {string} [cwd] Repository-relative working directory.
 * @property {boolean} [optional] Report failure without failing the run.
 */

/** @type {Array<Check[]>} */
const TIERS = [
  [
    {
      name: "standin-build",
      cmd: 'fnm exec --using=26.13.1 node tools/scripts/build-standin.mjs --out "$SITECMD_VERIFY_ENGINE_OUT"',
    },
  ],
  [
    { name: "lint", cmd: "pnpm run lint" },
    { name: "prettier", cmd: "pnpm exec prettier --check ." },
    { name: "legal-artifacts", cmd: "pnpm run legal:check" },
    { name: "installer", cmd: "pnpm run installer:check" },
    { name: "workflows", cmd: "pnpm run workflows:check" },
    { name: "guardrails:repo", cmd: "pnpm run guardrails:repo" },
    { name: "knip:budget", cmd: "pnpm run knip:exports-budget" },
    // The export budget does not detect unused files, dependencies, or binaries.
    { name: "knip:files", cmd: "pnpm run knip:files" },
    { name: "cargo-fmt", cmd: "cargo fmt --check", cwd: "apps/desktop/src-tauri" },
    { name: "rust-toolchain", cmd: "node tools/scripts/audit/check-rust-toolchain.mjs" },
    { name: "rust-patterns", cmd: "bash tools/scripts/audit/forbid-adhoc-rust-patterns.sh" },
    {
      name: "gitleaks",
      cmd: 'gitleaks git --redact --no-banner --log-opts="origin/main..HEAD"',
    },
    { name: "agents-md", cmd: "node tools/scripts/audit/check-agents-md.mjs" },
    { name: "regex-audit", cmd: "pnpm run audit:regex" },
    {
      name: "audit:deps:rust",
      cmd: "SITECMD_RUST_AUDIT_FETCH=1 pnpm run audit:deps:rust",
    },
    { name: "audit:deps:js", cmd: "pnpm run audit:deps:js" },
    { name: "audit:deps:signer", cmd: "pnpm run audit:deps:signer" },
    { name: "cargo-deny", cmd: "pnpm run audit:deps:rust-policy" },
    {
      name: "cli-build",
      cmd: "cargo build --manifest-path crates/cli/Cargo.toml",
      cwd: "apps/desktop/src-tauri",
    },
  ],
  // Keep JavaScript suites separate from CPU-heavy Rust tests.
  [
    {
      name: "guardrails-tests",
      cmd: "pnpm run guardrails:repo:test",
    },
    ...(await toolingEntries(ROOT, "localGuardrailChecks")),
    {
      name: "cli-smoke",
      cmd: "node tools/scripts/cli-smoke.mjs --standin",
    },
  ],
  [
    {
      name: "rust-nextest",
      cmd: "cargo nextest run --no-fail-fast --workspace",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "rust-clippy",
      cmd: "cargo clippy --workspace --all-targets -- -D warnings",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "cli-headless-clippy",
      // Check the CLI's no-default-features graph independently of workspace unification.
      cmd: "cargo clippy --manifest-path crates/cli/Cargo.toml --all-targets -- -D warnings",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "rust-msrv-workspace",
      cmd: "cargo +1.95.0 check --locked --workspace --all-targets",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "rust-msrv-cli",
      cmd: "cargo +1.95.0 check --locked --manifest-path crates/cli/Cargo.toml --all-targets",
      cwd: "apps/desktop/src-tauri",
    },
  ],
  [
    // nextest excludes doctests. Both build the workspace's libraries in the test
    // profile, so the doctests run after nextest rather than beside it, where one
    // could read a library the other is still writing.
    { name: "rust-doctest", cmd: "cargo test --doc --workspace", cwd: "apps/desktop/src-tauri" },
  ],
];

const tempDir = mkdtempSync(join(tmpdir(), "sitecmd-verify-"));
const engineOutput = join(tempDir, "standin");
const allChecks = TIERS.flat();
/** @type {Map<string, {status: "pending"|"running"|"pass"|"fail", durationMs: number, logFile: string}>} */
const state = new Map();
for (const check of allChecks) {
  state.set(check.name, {
    status: "pending",
    durationMs: 0,
    logFile: join(tempDir, `${check.name}.log`),
  });
}

function runCheck(check) {
  return new Promise((resolve) => {
    const entry = state.get(check.name);
    entry.status = "running";
    const start = Date.now();
    const logFd = openSync(entry.logFile, "w");
    const child = spawn("bash", ["-lc", check.cmd], {
      cwd: check.cwd ? join(ROOT, check.cwd) : ROOT,
      stdio: ["ignore", logFd, logFd],
      env: {
        ...CHECK_ENV,
        CI: "1",
        CARGO_BUILD_JOBS: CHECK_ENV.CARGO_BUILD_JOBS ?? String(workerCount({ env: CHECK_ENV })),
        SITECMD_VERIFY_ENGINE_OUT: engineOutput,
        SITECMD_ENGINE_WASM: join(engineOutput, "sitecmd_engine_standin.wasm"),
        SITECMD_ENGINE_UNPINNED: "1",
      },
    });
    child.on("close", (code) => {
      closeSync(logFd);
      entry.durationMs = Date.now() - start;
      entry.status = code === 0 ? "pass" : "fail";
      resolve();
    });
    child.on("error", (err) => {
      try {
        closeSync(logFd);
      } catch {
        // Already closed.
      }
      entry.durationMs = Date.now() - start;
      entry.status = "fail";
      appendFileSync(entry.logFile, `\nverify-push: spawn error: ${err.message}\n`);
      resolve();
    });
  });
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds - minutes * 60);
  return `${minutes}m${remainder.toString().padStart(2, "0")}s`;
}

function progressLine(check) {
  const entry = state.get(check.name);
  const marker =
    entry.status === "pass"
      ? `${GREEN}✓${RESET}`
      : entry.status === "fail"
        ? `${RED}✗${RESET}`
        : entry.status === "running"
          ? `${YELLOW}…${RESET}`
          : `${DIM}·${RESET}`;
  const time =
    entry.status === "pending" ? "" : `  ${DIM}${formatDuration(entry.durationMs)}${RESET}`;
  return `  ${marker}  ${check.name.padEnd(20)}${time}`;
}

async function runTier(tier, tierIndex) {
  process.stderr.write(`${BOLD}Tier ${tierIndex + 1}/${TIERS.length}${RESET}\n`);
  if (tierIndex + 1 === SHARED_CARGO_TARGET_TIER) {
    // These Cargo commands share a build directory and would wait on the same lock.
    for (const check of tier) await runCheck(check);
  } else {
    await Promise.all(tier.map(runCheck));
  }
  for (const check of tier) {
    process.stderr.write(`${progressLine(check)}\n`);
  }
}

// Playwright owns this IPv4 endpoint and never reuses the development server.
(async () => {
  if (NO_BAIL) {
    process.stderr.write(
      `${DIM}--no-bail: running every tier even after a failure; dependent checks may also fail.${RESET}\n`,
    );
  }
  const startedAt = Date.now();
  let tierIndex = 0;
  let aborted = false;
  for (const tier of TIERS) {
    await runTier(tier, tierIndex);
    tierIndex += 1;
    const tierFailures = tier.filter((check) => state.get(check.name).status === "fail");
    if (tierFailures.length > 0 && !NO_BAIL) {
      aborted = true;
      break;
    }
  }

  const totalMs = Date.now() - startedAt;
  const failed = allChecks.filter((check) => state.get(check.name).status === "fail");
  const skipped = allChecks.filter((check) => state.get(check.name).status === "pending");

  process.stderr.write(`\n${BOLD}verify-push summary${RESET}  (${formatDuration(totalMs)})\n`);
  for (const check of allChecks) {
    process.stderr.write(`${progressLine(check)}\n`);
  }

  if (failed.length > 0) {
    process.stderr.write(`\n${BOLD}${RED}Failed checks${RESET}\n`);
    for (const check of failed) {
      const log = readFileSync(state.get(check.name).logFile, "utf8");
      const trimmed = log.length > 4_000 ? `${log.slice(-4_000)}\n${DIM}…(truncated)${RESET}` : log;
      process.stderr.write(`\n${RED}── ${check.name} ──${RESET}\n${trimmed}\n`);
      process.stderr.write(`${DIM}full log: ${state.get(check.name).logFile}${RESET}\n`);
    }
  }

  if (failed.length > 0 || (aborted && skipped.length > 0)) {
    process.stderr.write(
      `\n${RED}${BOLD}verify-push: ${failed.length} failed${RESET}${aborted ? `, ${skipped.length} skipped (later tier)` : ""}\n`,
    );
    process.stderr.write(`${DIM}Fix the failures locally before pushing.${RESET}\n`);
    if (aborted && skipped.length > 0) {
      process.stderr.write(
        `${DIM}Later tiers were skipped after the first failure. To surface every failure in one run: pnpm verify:push:all${RESET}\n`,
      );
    }
    process.exit(1);
  }

  for (const check of allChecks) {
    try {
      unlinkSync(state.get(check.name).logFile);
    } catch {
      // Best-effort cleanup.
    }
  }

  rmSync(engineOutput, { recursive: true, force: true });
  process.stderr.write(`\n${GREEN}${BOLD}verify-push: all checks passed${RESET}\n`);
})();
