#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  unlinkSync,
} from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  classifyBindError,
  isolatedGitEnvironment,
  missingBrowserPaths,
  resolveRepositoryRoot,
} from "./verify-push-lib.mjs";

const ROOT = resolveRepositoryRoot(import.meta.url);
const CHECK_ENV = isolatedGitEnvironment(ROOT, process.env);

const NO_BAIL = process.argv.slice(2).some((arg) => arg === "--no-bail" || arg === "--all");

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
  // Knip resolves MCP test imports through the compiled output.
  [{ name: "mcp-build", cmd: "pnpm --filter sitecmd-mcp run build" }],
  [
    { name: "typecheck", cmd: "pnpm run typecheck" },
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
      name: "frontend-constants",
      cmd: "bash tools/scripts/audit/forbid-inline-frontend-constants.sh",
    },
    {
      name: "gitleaks",
      cmd: 'gitleaks git --redact --no-banner --log-opts="origin/main..HEAD"',
    },
    // The same engine and suite the CodeQL workflow runs, limited to alerts on
    // lines this branch added, so a pull-request blocker surfaces here instead
    // of one CI round trip at a time.
    { name: "codeql", cmd: "pnpm run audit:codeql" },
    { name: "agents-md", cmd: "node tools/scripts/audit/check-agents-md.mjs" },
    { name: "regex-audit", cmd: "pnpm run audit:regex" },
    {
      name: "audit:deps:rust",
      cmd: "SITECMD_RUST_AUDIT_FETCH=1 pnpm run audit:deps:rust",
    },
    { name: "audit:deps:js", cmd: "pnpm run audit:deps:js" },
    { name: "audit:licenses:js", cmd: "pnpm run audit:licenses:js" },
    { name: "audit:deps:signer", cmd: "pnpm run audit:deps:signer" },
    { name: "cargo-deny", cmd: "pnpm run audit:deps:rust-policy" },
    {
      name: "tauri-commands",
      cmd: "node tools/scripts/audit/tauri-command-surface.mjs --check",
    },
    {
      name: "cli-build",
      cmd: "cargo build --manifest-path crates/cli/Cargo.toml",
      cwd: "apps/desktop/src-tauri",
    },
  ],
  // Keep JavaScript suites separate from CPU-heavy Rust tests.
  [
    { name: "desktop-vitest", cmd: "pnpm --filter @sitecmd/desktop run test" },
    {
      name: "worker-vitest",
      cmd: "pnpm --filter sitecmd-mcp run test",
    },
    {
      name: "guardrails-tests",
      cmd: "pnpm run guardrails:repo:test",
    },
    {
      name: "cli-smoke",
      cmd: "node tools/scripts/cli-smoke.mjs",
    },
  ],
  [
    {
      name: "rust-nextest",
      cmd: "cargo nextest run --no-fail-fast --workspace",
      cwd: "apps/desktop/src-tauri",
    },
    // nextest excludes doctests.
    { name: "rust-doctest", cmd: "cargo test --doc --workspace", cwd: "apps/desktop/src-tauri" },
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
      cmd: "cargo +1.89.0 check --locked --workspace --all-targets",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "rust-msrv-cli",
      cmd: "cargo +1.89.0 check --locked --manifest-path crates/cli/Cargo.toml --all-targets",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "engine-wasm",
      cmd: "cargo check -p sitecmd-engine-wasm --target wasm32-unknown-unknown",
      cwd: "apps/desktop/src-tauri",
    },
    {
      name: "engine-wasm-checks",
      cmd: "cargo check -p sitecmd-engine-wasm --target wasm32-unknown-unknown --features checks",
      cwd: "apps/desktop/src-tauri",
    },
  ],
  [{ name: "perf-baseline", cmd: "pnpm run perf:baseline" }],
  [
    {
      name: "rust-perf-gates",
      cmd: "cargo nextest run -p sitecmd-runtime --lib --run-ignored only --no-tests fail -- resolver_p95_under_60ms preview_deploy_risk_p95_under_200ms",
      cwd: "apps/desktop/src-tauri",
    },
  ],
  [{ name: "desktop-build", cmd: "pnpm --filter @sitecmd/desktop run build" }],
  [
    {
      name: "size-limit",
      cmd: "pnpm --filter @sitecmd/desktop exec size-limit",
    },
    { name: "playwright", cmd: "pnpm --filter @sitecmd/desktop exec playwright test e2e/" },
    { name: "naming-audit", cmd: "pnpm run naming:audit" },
  ],
];

const tempDir = mkdtempSync(join(tmpdir(), "sitecmd-verify-"));
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
        // Reuse the verified production build on the dedicated push-gate port.
        SITECMD_VERIFY_PUSH: "1",
        SITECMD_E2E_PORT: String(E2E_PORT),
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
  const promises = tier.map((check) => runCheck(check));
  await Promise.all(promises);
  for (const check of tier) {
    process.stderr.write(`${progressLine(check)}\n`);
  }
}

// Playwright owns this IPv4 endpoint and never reuses the development server.
const E2E_HOST = "127.0.0.1";
const E2E_PORT = 5183;

// Return the bind error for Playwright's exact IPv4 endpoint, if any.
function bindError(host, port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", (error) => resolve(error));
    server.listen(port, host, () => server.close(() => resolve(null)));
  });
}

async function preflightPortCheck() {
  const error = await bindError(E2E_HOST, E2E_PORT);
  if (error === null) return;

  const classification = classifyBindError(error);
  if (classification !== "occupied") {
    const code = typeof error.code === "string" ? ` (${error.code})` : "";
    const remedy =
      classification === "denied"
        ? "Playwright needs permission to open that local endpoint for its preview server.\n"
        : "Playwright needs that exact address for its preview server; check the loopback interface and any network policy in effect.\n";
    process.stderr.write(
      `${RED}${BOLD}verify-push: could not bind ${E2E_HOST}:${E2E_PORT}${code}.${RESET}\n` + remedy,
    );
    process.exit(1);
  }

  const probe = spawnSync("bash", [
    "-lc",
    `lsof -nP -iTCP@${E2E_HOST}:${E2E_PORT} -sTCP:LISTEN -t 2>/dev/null`,
  ]);
  const pids = probe.stdout.toString().trim().split(/\s+/).filter(Boolean).join(" ");
  process.stderr.write(
    `${RED}${BOLD}verify-push: ${E2E_HOST}:${E2E_PORT} is already held${pids ? ` (PID ${pids})` : ""}.${RESET}\n` +
      `Playwright (CI mode, no server reuse) needs to bind that address for its own preview server.\n` +
      (pids ? `  Quick fix:  kill ${pids}\n` : ""),
  );
  process.exit(1);
}

// Fail early when the resolved Playwright version lacks Chromium.
function preflightBrowserCheck() {
  const probe = spawnSync(
    "bash",
    ["-lc", "pnpm --filter @sitecmd/desktop exec playwright install chromium --dry-run"],
    { cwd: ROOT, env: CHECK_ENV },
  );
  if (probe.status !== 0) return;
  const missing = missingBrowserPaths(probe.stdout.toString(), existsSync);
  if (missing === null) {
    // Unparseable output is distinct from a confirmed complete browser install.
    process.stderr.write(
      `${YELLOW}verify-push: could not read Playwright's install locations; skipping the browser preflight.${RESET}\n`,
    );
    return;
  }
  if (missing.length === 0) return;

  process.stderr.write(
    `${RED}${BOLD}verify-push: Playwright browsers are not installed.${RESET}\n` +
      `The e2e tier would fail at browser launch after the full run.\n` +
      missing.map((location) => `  missing: ${location}\n`).join("") +
      `  Quick fix:  pnpm --filter @sitecmd/desktop exec playwright install chromium\n`,
  );
  process.exit(1);
}

(async () => {
  await preflightPortCheck();
  preflightBrowserCheck();
  if (NO_BAIL) {
    process.stderr.write(
      `${DIM}--no-bail: running every tier even after a failure; dependent checks (size-limit, playwright) may cascade if their build fails.${RESET}\n`,
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

  process.stderr.write(`\n${GREEN}${BOLD}verify-push: all checks passed${RESET}\n`);
})();
