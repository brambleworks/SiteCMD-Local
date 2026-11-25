#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const CRATE_DIR = path.join(ROOT, "apps", "desktop", "src-tauri");
const CLI_MANIFEST = path.join(CRATE_DIR, "crates", "cli", "Cargo.toml");
const STANDIN = process.argv.includes("--standin");
const CONFIGURED_BINARY = process.env.SITECMD_CLI_BINARY?.trim();
const BINARY = CONFIGURED_BINARY
  ? path.resolve(ROOT, CONFIGURED_BINARY)
  : path.join(
      CRATE_DIR,
      "target",
      "debug",
      process.platform === "win32" ? "sitecmd_cli.exe" : "sitecmd_cli",
    );

const FIXTURE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SiteCMD CLI smoke fixture</title>
<meta name="description" content="Local fixture page for the CLI smoke guardrail.">
</head>
<body><main><h1>SiteCMD CLI smoke fixture</h1><p>Served from a local test server.</p></main></body>
</html>
`;
const FIXTURE_TOKEN = ["sk", "_live_", "abcdefghijklmnopqrstu"].join("");
const HELP_SNAPSHOTS = [
  {
    label: "sitecmd --help",
    args: ["--help"],
    sha256: "bb9f1ed6fa9f7c85162acc84fa1277998b693e53cb30f8ed7b4453a448a854aa",
  },
  {
    label: "sitecmd init --help",
    args: ["init", "--help"],
    sha256: "ee94220c5f060b7e84121986b8cf2e80e4a0226b2f7ef319f5d78a444d4c03b3",
  },
  {
    label: "sitecmd audit --help",
    args: ["audit", "--help"],
    sha256: "387c35b47923bf97152e4627e99df90acd367b43f580455435e0b9855d1a635d",
  },
  {
    label: "sitecmd rules --help",
    args: ["rules", "--help"],
    sha256: "184413a44026ee308df3eeb2113668174c255770a6c000e6e403ca89799c74d4",
  },
  {
    label: "sitecmd autofix --help",
    args: ["autofix", "--help"],
    sha256: "41a34d9c94db4cf6118c4c805c6723cc782616af8c7cacaa876726d5fc72dc8f",
  },
  {
    label: "sitecmd scan --help",
    args: ["scan", "--help"],
    sha256: "a19e4b0f7826407d069ec07b89d7853863a722b0bfff3352fe00ad52e6b37f96",
  },
  {
    label: "sitecmd fix --help",
    args: ["fix", "--help"],
    sha256: "24324b3960893df981e671699dbe787511a9f2bbb15438c9030b780362e567b7",
  },
  {
    label: "sitecmd watch --help",
    args: ["watch", "--help"],
    sha256: "4665ec6eb98ec5c3556674d3b89fe37be9f93201d057f6b7dc9b6ebdf9d48195",
  },
  {
    label: "sitecmd check --help",
    args: ["check", "--help"],
    sha256: "beb20ffdbdac677ba6d34c0ccc31fe0907ce9eb4ad2105b8704f5932a3f34cc8",
  },
  {
    label: "sitecmd connected --help",
    args: ["connected", "--help"],
    sha256: "140c077f6a5c75593d856f4a9be7d34258f2df5e7f94fcd20a94d63a50fdd6c2",
  },
  {
    label: "sitecmd deploy --help",
    args: ["deploy", "--help"],
    sha256: "b56b3a3ea290d36f6fb8412a801bb996a34b15f735d5f430e5c8f33f72718dfa",
  },
  {
    label: "sitecmd gate --help",
    args: ["gate", "--help"],
    sha256: "ac527858d4047e7209c08a71665737849c80321f11e132a7e390354ec8cb415e",
  },
];

function fail(message) {
  console.error(`cli-smoke: FAIL - ${message}`);
  process.exit(1);
}

function ensureBinary() {
  if (existsSync(BINARY)) return;
  if (CONFIGURED_BINARY) fail(`configured binary does not exist: ${BINARY}`);
  console.log("cli-smoke: binary missing, building the headless CLI package...");
  const build = spawnSync("cargo", ["build", "--manifest-path", CLI_MANIFEST], {
    cwd: ROOT,
    stdio: "inherit",
  });
  if (build.status !== 0) fail("cargo build for the CLI package failed");
}

function crateVersion() {
  const manifest = readFileSync(CLI_MANIFEST, "utf8");
  const match = manifest.match(/^version = "([^"]+)"/m);
  if (!match) fail("could not read crate version from Cargo.toml");
  return match[1];
}

function checkVersion() {
  const expected = crateVersion();
  const result = spawnSync(BINARY, ["--version"], { encoding: "utf8", timeout: 30_000 });
  if (result.status !== 0) fail(`--version exited ${result.status}: ${result.stderr}`);
  const actual = result.stdout.trim();
  const pinned = `sitecmd ${expected}`;
  const allowUnpinned = process.env.SITECMD_ENGINE_UNPINNED === "1";
  if (actual !== pinned && !(allowUnpinned && actual === `${pinned}+unpinned`)) {
    fail(`--version printed "${actual}", expected "sitecmd ${expected}"`);
  }
  console.log(`cli-smoke: --version ok (${actual})`);
}

function checkHelp() {
  for (const snapshot of HELP_SNAPSHOTS) {
    const result = spawnSync(BINARY, snapshot.args, { encoding: "utf8", timeout: 30_000 });
    if (result.status !== 0) {
      fail(`${snapshot.label} exited ${result.status}: ${result.stderr}`);
    }
    const rendered = `${result.stdout}${result.stderr}`.replace(/\r\n/g, "\n").trimEnd() + "\n";
    const actual = createHash("sha256").update(rendered).digest("hex");
    if (actual !== snapshot.sha256) {
      fail(
        `${snapshot.label} changed (expected ${snapshot.sha256}, got ${actual}); review the rendered help and update its snapshot intentionally`,
      );
    }
  }

  const short = spawnSync(BINARY, ["-h"], { encoding: "utf8", timeout: 30_000 });
  if (short.status !== 0) fail(`-h exited ${short.status}: ${short.stderr}`);
  const renderedShort = `${short.stdout}${short.stderr}`.replace(/\r\n/g, "\n").trimEnd() + "\n";
  const shortHash = createHash("sha256").update(renderedShort).digest("hex");
  if (shortHash !== HELP_SNAPSHOTS[0].sha256) fail("-h differs from the top-level --help snapshot");

  console.log(`cli-smoke: help snapshots ok (${HELP_SNAPSHOTS.length} command surfaces)`);
}

function checkParserGuards() {
  const invalidCases = [
    { args: ["scan", "--categories", "security,typo"], message: "Unknown category: typo" },
    { args: ["scan", "--type", "security"], message: "Unknown option: --type" },
    {
      args: ["scan", "--diff", "--categories", "security"],
      message: "--diff cannot be combined with --categories",
    },
    { args: ["scan", "--fail-under", "101"], message: "between 0 and 100" },
    { args: ["scan", "--cwv"], message: "Unknown option: --cwv" },
    { args: ["scan", "--no-browser"], message: "Unknown option: --no-browser" },
  ];
  for (const { args, message } of invalidCases) {
    const result = spawnSync(BINARY, args, { encoding: "utf8", timeout: 30_000 });
    if (result.status !== 2 || !result.stderr.includes(message)) {
      fail(`${args.join(" ")} did not fail closed with the expected usage error`);
    }
  }
  console.log("cli-smoke: parser guardrails ok (categories, scores, retired flags)");
}

function serveFixture() {
  return new Promise((resolve) => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(FIXTURE_HTML);
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

// The fixture server shares this event loop, so the child must run asynchronously.
function runScan(url) {
  return new Promise((resolve) => {
    const child = spawn(BINARY, ["scan", "--url", url, "--json", "--timeout", "15"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    const timer = setTimeout(() => child.kill("SIGKILL"), 180_000);
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ status: null, stdout, stderr, error });
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

async function checkScan(url) {
  const result = await runScan(url);
  if (result.error) fail(`scan did not run: ${result.error.message}`);
  if (result.status !== 0) fail(`scan exited ${result.status}: ${result.stderr}`);
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch (error) {
    fail(`scan --json emitted invalid JSON (${error.message})`);
  }
  if (typeof parsed.overallScore !== "number") {
    fail(`scan JSON has no numeric overallScore (got ${typeof parsed.overallScore})`);
  }
  if (!Array.isArray(parsed.issues)) {
    fail("scan JSON has no issues array");
  }
  console.log(
    `cli-smoke: scan ok (score ${parsed.overallScore}, ${parsed.issues.length} issues, ${parsed.durationMs}ms)`,
  );
}

function checkAudit() {
  const fixture = mkdtempSync(path.join(os.tmpdir(), "sitecmd-cli-audit-"));
  try {
    mkdirSync(path.join(fixture, "src"));
    writeFileSync(path.join(fixture, "package.json"), '{ "name": "sitecmd-cli-audit" }\n');
    writeFileSync(path.join(fixture, "src", "keys.js"), `const key = "${FIXTURE_TOKEN}";\n`);

    const result = spawnSync(BINARY, ["audit", fixture, "--format", "json"], {
      encoding: "utf8",
      timeout: 180_000,
    });
    if (result.status !== 0) fail(`audit exited ${result.status}: ${result.stderr}`);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch (error) {
      fail(`audit --format json emitted invalid JSON (${error.message})`);
    }
    if (!Array.isArray(parsed.issues) || parsed.issues.length === 0) {
      fail("audit JSON has no findings for the vulnerable fixture");
    }
    if (STANDIN) {
      const ids = parsed.issues.map((issue) => issue.id).sort();
      if (
        JSON.stringify(ids) !==
        JSON.stringify(["standin.rule:package.json:0", "standin.rule:src/keys.js:0"])
      ) {
        fail("audit JSON did not contain one stand-in finding per fixture file");
      }
    } else if (!parsed.issues.some((issue) => issue.id?.startsWith("hardcoded-secret:"))) {
      fail("audit JSON did not contain the expected hardcoded-secret finding");
    }
    if (result.stdout.includes(FIXTURE_TOKEN)) {
      fail("audit JSON exposed the detected credential");
    }

    const severity = STANDIN ? "low" : "high";
    const threshold = spawnSync(BINARY, ["audit", fixture, "--fail-on", severity], {
      encoding: "utf8",
      timeout: 180_000,
    });
    if (threshold.status !== 1) {
      fail(
        `audit --fail-on ${severity} exited ${threshold.status}, expected 1: ${threshold.stderr}`,
      );
    }
    console.log(`cli-smoke: audit ok (${parsed.issues.length} findings, threshold exit 1)`);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

ensureBinary();
checkVersion();
checkHelp();
checkParserGuards();
const server = await serveFixture();
const { port } = server.address();
try {
  await checkScan(`http://127.0.0.1:${port}`);
} finally {
  server.close();
}
checkAudit();
console.log("cli-smoke: PASS");
