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
    sha256: "f84eb4eab8b38a4df63da8349d95a175d195c8bc0d667b5042bb92f765c63619",
  },
  {
    label: "sitecmd init --help",
    args: ["init", "--help"],
    sha256: "ddb1aa807ad0f80e15d7a3ac8ecf01646cd0c37fd75c1a3aff646d70ae405838",
  },
  {
    label: "sitecmd audit --help",
    args: ["audit", "--help"],
    sha256: "be89a099872b81eeb251b53c0440b2268d9fdc91f95b2370716b95fa1b2e715d",
  },
  {
    label: "sitecmd autofix --help",
    args: ["autofix", "--help"],
    sha256: "7b8df194bb8c4ae236d188852433c816eccc9224a3c6707b972cfa9806df4c2c",
  },
  {
    label: "sitecmd scan --help",
    args: ["scan", "--help"],
    sha256: "1cf31800e10e57346e43209b888e2327f3721df00c2cb304fb669a357f636d3d",
  },
  {
    label: "sitecmd fix --help",
    args: ["fix", "--help"],
    sha256: "0ef2ead0b23f4d9e21b951acd9cec3586c2a8ba2fbaf6229c010c846c183c5da",
  },
  {
    label: "sitecmd watch --help",
    args: ["watch", "--help"],
    sha256: "c53e4aeb071a84840ba3e675097d777a32a2faba585b02a63e692e9c407f418a",
  },
  {
    label: "sitecmd check --help",
    args: ["check", "--help"],
    sha256: "b2613d4835a6aa02b8c7733f863cbf8a436ba988fa6a0272688e7672cf8206a6",
  },
  {
    label: "sitecmd connected --help",
    args: ["connected", "--help"],
    sha256: "bf53e146d6c78f1890ce0bb5873e88aedaab9e78b7e276fde6927b5b9dc12dca",
  },
  {
    label: "sitecmd deploy --help",
    args: ["deploy", "--help"],
    sha256: "b56b3a3ea290d36f6fb8412a801bb996a34b15f735d5f430e5c8f33f72718dfa",
  },
  {
    label: "sitecmd gate --help",
    args: ["gate", "--help"],
    sha256: "770613872e83810d19f67463ca7d06cceb20001e2e0822ab8c2e0dd364cb35b1",
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
  if (actual !== `sitecmd ${expected}`) {
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
    { args: ["scan", "--categories", "security,typo"], message: "Unknown Web Scan category" },
    { args: ["scan", "--fail-under", "101"], message: "between 0 and 100" },
    { args: ["scan", "--cwv"], message: "browser-enabled source build" },
  ];
  for (const { args, message } of invalidCases) {
    const result = spawnSync(BINARY, args, { encoding: "utf8", timeout: 30_000 });
    if (result.status !== 2 || !result.stderr.includes(message)) {
      fail(`${args.join(" ")} did not fail closed with the expected usage error`);
    }
  }
  console.log("cli-smoke: parser guardrails ok (categories, scores, browser flags)");
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
    if (!parsed.issues.some((issue) => issue.id?.startsWith("hardcoded-secret:"))) {
      fail("audit JSON did not contain the expected hardcoded-secret finding");
    }
    if (result.stdout.includes(FIXTURE_TOKEN)) {
      fail("audit JSON exposed the detected credential");
    }

    const threshold = spawnSync(BINARY, ["audit", fixture, "--fail-on", "high"], {
      encoding: "utf8",
      timeout: 180_000,
    });
    if (threshold.status !== 1) {
      fail(`audit --fail-on high exited ${threshold.status}, expected 1: ${threshold.stderr}`);
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
