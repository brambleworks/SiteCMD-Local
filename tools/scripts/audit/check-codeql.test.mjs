import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const SCRIPT = path.join(ROOT, "tools/scripts/audit/check-codeql.mjs");
const WORK_PREFIX = "sitecmd-codeql-";
const INTEGRATION_TEST_TIMEOUT_MS = 15_000;

let scratch;
let fakeBin;
let argsLog;
let filtersLog;
let fixture;

/**
 * A codeql stand-in, so these tests exercise the gate's own logic without the
 * several minutes and gigabyte of database a real analysis costs. It records
 * every invocation, creates the database directory it is asked for, and writes
 * an empty SARIF result set.
 */
function installFakeCodeql() {
  const stub = path.join(fakeBin, "codeql");
  fs.writeFileSync(
    stub,
    [
      "#!/usr/bin/env node",
      'const fs = require("node:fs");',
      "const args = process.argv.slice(2);",
      `fs.appendFileSync(${JSON.stringify(argsLog)}, args.join(" ") + "\\n");`,
      'if (args[0] === "version") { console.log("0.0.0-fake"); process.exit(0); }',
      "// FAKE_CODEQL_FAIL names the subcommand that should report failure.",
      "if (process.env.FAKE_CODEQL_FAIL === args[1]) process.exit(9);",
      'if (args[1] === "create") {',
      `  fs.appendFileSync(${JSON.stringify(filtersLog)}, String(process.env.LGTM_INDEX_FILTERS ?? "") + "\\n");`,
      "  fs.mkdirSync(args[2], { recursive: true });",
      "  process.exit(0);",
      "}",
      'if (args[1] === "analyze") {',
      '  const out = args.find((a) => a.startsWith("--output=")).slice("--output=".length);',
      "  // FAKE_CODEQL_SARIF names a prepared result set; otherwise the analysis is clean.",
      "  if (process.env.FAKE_CODEQL_SARIF) fs.copyFileSync(process.env.FAKE_CODEQL_SARIF, out);",
      "  else fs.writeFileSync(out, JSON.stringify({ runs: [] }));",
      "}",
      "process.exit(0);",
    ].join("\n"),
  );
  fs.chmodSync(stub, 0o755);
}

/**
 * A two-commit repository the gate analyzes instead of this checkout, so the
 * tests do not depend on how deeply CI cloned. The second commit adds lines,
 * which is what puts the gate on its analysis path.
 */
function createFixtureRepository() {
  const repo = path.join(scratch, "repo");
  fs.mkdirSync(repo);
  const git = (...args) => {
    const result = spawnSync("git", args, {
      cwd: repo,
      encoding: "utf8",
      env: {
        ...process.env,
        GIT_CONFIG_GLOBAL: os.devNull,
        GIT_CONFIG_SYSTEM: os.devNull,
        GIT_AUTHOR_NAME: "fixture",
        GIT_AUTHOR_EMAIL: "fixture@example.invalid",
        GIT_COMMITTER_NAME: "fixture",
        GIT_COMMITTER_EMAIL: "fixture@example.invalid",
      },
    });
    if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  };
  git("init", "-q", "-b", "main");
  fs.writeFileSync(path.join(repo, "app.js"), "export const base = 1;\n");
  git("add", "app.js");
  git("commit", "-q", "-m", "base");
  fs.appendFileSync(path.join(repo, "app.js"), "export const added = 2;\n");
  git("commit", "-q", "-a", "-m", "add lines");
  return repo;
}

/** Age a directory past the staleness cutoff without waiting an hour. */
function makeOld(directory) {
  const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
  fs.utimesSync(directory, old, old);
}

function seedWorkDirectory(name) {
  const directory = path.join(scratch, name);
  fs.mkdirSync(path.join(directory, "db"), { recursive: true });
  makeOld(directory);
  return directory;
}

/** Work directories the gate left behind in its temp directory. */
function leftovers() {
  return fs.readdirSync(scratch).filter((name) => name.startsWith(WORK_PREFIX));
}

/** A SARIF result set with one alert at `file`:`line`, as CodeQL would report it. */
function sarifWithAlert(file, line) {
  const sarif = path.join(scratch, "alert.sarif");
  const rule = { id: "js/fixture-rule", properties: { "security-severity": "7.5" } };
  const location = {
    physicalLocation: { artifactLocation: { uri: `file://${file}` }, region: { startLine: line } },
  };
  const result = { ruleId: rule.id, message: { text: "fixture finding" }, locations: [location] };
  fs.writeFileSync(
    sarif,
    JSON.stringify({ runs: [{ tool: { driver: { rules: [rule] } }, results: [result] }] }),
  );
  return sarif;
}

function runGate(env = {}) {
  return spawnSync(process.execPath, [SCRIPT], {
    cwd: fixture,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH}`,
      TMPDIR: scratch,
      SITECMD_CODEQL_ROOT: fixture,
      SITECMD_CODEQL_BASE: "HEAD",
      ...env,
    },
  });
}

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "check-codeql-test-"));
  fakeBin = path.join(scratch, "bin");
  fs.mkdirSync(fakeBin);
  argsLog = path.join(scratch, "codeql-args.log");
  filtersLog = path.join(scratch, "codeql-filters.log");
  installFakeCodeql();
  fixture = createFixtureRepository();
});

afterEach(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

describe("check-codeql stale database sweep", () => {
  it(
    "removes an abandoned database even when there is nothing to analyze",
    () => {
      const abandoned = seedWorkDirectory(`${WORK_PREFIX}999999-abandoned`);

      const result = runGate();

      expect(result.stdout).toContain("no added lines");
      expect(fs.existsSync(abandoned)).toBe(false);
    },
    INTEGRATION_TEST_TIMEOUT_MS,
  );

  it(
    "keeps a directory whose owner is still running, however old it looks",
    () => {
      // CodeQL writes below work/db, so a live run's parent mtime stops advancing
      // and the age test alone would eventually mistake it for abandoned work.
      const live = seedWorkDirectory(`${WORK_PREFIX}${process.pid}-live`);

      runGate();

      expect(fs.existsSync(live)).toBe(true);
    },
    INTEGRATION_TEST_TIMEOUT_MS,
  );

  it(
    "leaves a recent directory alone",
    () => {
      const directory = path.join(scratch, `${WORK_PREFIX}999999-recent`);
      fs.mkdirSync(directory, { recursive: true });

      runGate();

      expect(fs.existsSync(directory)).toBe(true);
    },
    INTEGRATION_TEST_TIMEOUT_MS,
  );
});

describe("check-codeql analysis root", () => {
  it("analyzes the repository it is pointed at, not this checkout", () => {
    // CI clones shallowly, so HEAD~1 has to come from the fixture.
    const result = runGate({ SITECMD_CODEQL_BASE: "HEAD~1" });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("1 changed file(s)");
    expect(fs.readFileSync(argsLog, "utf8")).toContain(`--source-root=${fixture}`);
  });
});

describe("check-codeql extraction filters", () => {
  it("keeps the extractor out of the Rust build directory", () => {
    // cli-build writes that tree in the same gate tier, and a cargo artifact
    // removed mid-walk aborts database creation instead of failing a check.
    const result = runGate({ SITECMD_CODEQL_BASE: "HEAD~1" });

    expect(result.status).toBe(0);
    expect(fs.readFileSync(filtersLog, "utf8").trim().split("\n")).toContain(
      "exclude:apps/desktop/src-tauri/target",
    );
  });
});

describe("check-codeql memory budget", () => {
  const analyzed = { SITECMD_CODEQL_BASE: "HEAD~1" };

  function ramFlags() {
    return fs
      .readFileSync(argsLog, "utf8")
      .split("\n")
      .flatMap((line) => line.split(" ").filter((arg) => arg.startsWith("--ram=")));
  }

  it("passes the default budget when no override is set", () => {
    const result = runGate(analyzed);

    expect(result.status).toBe(0);
    expect(ramFlags()).toContain("--ram=4096");
  });

  it.each(["", "abc", "0", "-1", "4.5"])(
    "falls back to the default rather than sending %j to codeql",
    (value) => {
      // CodeQL requires a positive integer, and an unchecked Number() turns
      // these into --ram=0 or --ram=NaN, which fails the analysis.
      runGate({ ...analyzed, SITECMD_CODEQL_RAM: value });

      expect(ramFlags()).toContain("--ram=4096");
    },
  );

  it("honours a valid override", () => {
    runGate({ ...analyzed, SITECMD_CODEQL_RAM: "8192" });

    expect(ramFlags()).toContain("--ram=8192");
  });

  it("removes its work directory once the analysis is clean", () => {
    const result = runGate(analyzed);

    expect(result.status).toBe(0);
    const left = fs.readdirSync(scratch).filter((name) => name.startsWith(WORK_PREFIX));
    expect(left).toEqual([]);
  });
});

describe("check-codeql alert reporting", () => {
  const analyzed = { SITECMD_CODEQL_BASE: "HEAD~1" };

  it("reports an alert on an added line and still frees the database", () => {
    const result = runGate({
      ...analyzed,
      FAKE_CODEQL_SARIF: sarifWithAlert(path.join(fixture, "app.js"), 2),
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("1 new alert(s)");
    expect(result.stderr).toContain("app.js:2");
    expect(leftovers()).toEqual([]);
  });

  it("matches absolute SARIF paths when the root carries a trailing separator", () => {
    // normalizeUri strips `${ROOT}/`; an unresolved "repo/" root would never
    // match "repo/app.js", and every alert would be silently dropped.
    const result = runGate({
      ...analyzed,
      SITECMD_CODEQL_ROOT: fixture + path.sep,
      FAKE_CODEQL_SARIF: sarifWithAlert(path.join(fixture, "app.js"), 2),
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("app.js:2");
  });
});

describe("check-codeql cleanup discipline", () => {
  const analyzed = { SITECMD_CODEQL_BASE: "HEAD~1" };

  // die() calls process.exit, which skips the finally that frees the database,
  // so it has to remove the directory itself. Both failures happen after the
  // work directory exists, which is what makes them worth driving.
  it.each([
    ["create", "database creation failed"],
    ["analyze", "analysis failed"],
  ])("frees the database when codeql %s fails", (subcommand, message) => {
    const result = runGate({ ...analyzed, FAKE_CODEQL_FAIL: subcommand });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(message);
    expect(leftovers()).toEqual([]);
  });

  it("exits through die(), so no path skips the finally that frees the database", () => {
    // The alert path is driven above; this guards the failure paths that are
    // not: process.exit belongs only to die(), which removes the directory
    // before it runs.
    const source = fs.readFileSync(SCRIPT, "utf8");
    const callers = source
      .split("\n")
      .map((line, index) => ({ line: line.trim(), number: index + 1 }))
      .filter((entry) => entry.line.startsWith("process.exit("));

    expect(callers).toHaveLength(1);
    const die = source.slice(source.indexOf("function die("), source.indexOf("/** Line ranges"));
    expect(die).toContain("process.exit(1)");
  });
});
