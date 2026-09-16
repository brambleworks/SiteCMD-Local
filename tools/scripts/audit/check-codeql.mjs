#!/usr/bin/env node
/**
 * Run CodeQL's security-extended suite over the JavaScript and TypeScript
 * sources before a push, so an alert that would block the pull request is seen
 * here instead of one CI round trip at a time.
 *
 * Only findings on lines this branch actually added are reported. CodeQL sees
 * the whole tree, so without that filter every pre-existing alert on main would
 * fail the gate for whoever touched the file next.
 *
 * Rust is out of scope on purpose: its analysis runs past twelve minutes in CI,
 * longer than the entire local gate, and every alert this gate was written for
 * was JavaScript.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path, { join } from "node:path";
import { fileURLToPath } from "node:url";

// Tests point the gate at a fixture repository; a push always analyzes this
// checkout. Resolved either way, because normalizeUri strips `${ROOT}/` from
// absolute SARIF paths and a trailing separator would defeat that match.
const ROOT = path.resolve(
  process.env.SITECMD_CODEQL_ROOT ||
    path.join(path.dirname(fileURLToPath(import.meta.url)), "../../.."),
);
const LANGUAGE = "javascript-typescript";
const SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls";
const BASE_REF = process.env.SITECMD_CODEQL_BASE ?? "origin/main";

/** Inline escape hatch, matching how the rest of the guardrails are silenced. */
const ALLOW_MARKER = "codeql-allow:";

const WORK_PREFIX = "sitecmd-codeql-";

/**
 * Cap the analysis budget so a loaded machine keeps some headroom. CodeQL
 * splits this between JVM heap and off-heap: 4096 resolves to a 1800M heap
 * plus 1379M off-heap, while 2048 gives 1188M and no off-heap at all, which
 * the security-extended evaluation exhausts and dies on without a message.
 */
const RAM_DEFAULT_MB = 4096;
const RAM_MB = positiveInteger(process.env.SITECMD_CODEQL_RAM) ?? RAM_DEFAULT_MB;

/** CodeQL rejects --ram unless it is a positive integer, and "" coerces to 0. */
function positiveInteger(value) {
  if (value === undefined) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

/**
 * Directories the extractor must not walk, relative to the source root. The
 * Rust build directory holds no tracked JavaScript, runs to tens of thousands
 * of files, and the gate's cli-build step writes it in the same tier: cargo
 * removing an incremental artifact mid-walk aborts database creation with a
 * NoSuchFileException. Excluding it also spares the walk 22G of build output.
 */
const EXTRACTION_EXCLUDES = ["apps/desktop/src-tauri/target"];

/** The JavaScript extractor reads its path filters from this variable. */
const INDEX_FILTERS = EXTRACTION_EXCLUDES.map((directory) => `exclude:${directory}`).join("\n");

/** An hour is far longer than a run takes, so this only sees abandoned work. */
const STALE_MS = 60 * 60 * 1000;

/** Still running, so its directory is in use no matter how old it looks. */
function ownerAlive(name) {
  const pid = Number(name.slice(WORK_PREFIX.length).split("-")[0]);
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the pid exists but belongs to another user.
    return error.code === "EPERM";
  }
}

/**
 * Delete databases an earlier run left behind. Cleanup happens in a finally
 * block, which a SIGKILL skips, and each database runs to several hundred
 * megabytes.
 *
 * A directory has to be both idle and ownerless to qualify. CodeQL writes
 * below work/db, so the parent mtime stops advancing once the database exists,
 * and the age test alone would eventually see a live run as abandoned.
 */
function sweepStaleDatabases() {
  let entries;
  try {
    entries = readdirSync(tmpdir());
  } catch {
    return;
  }
  for (const name of entries) {
    if (!name.startsWith(WORK_PREFIX)) continue;
    if (ownerAlive(name)) continue;
    const directory = join(tmpdir(), name);
    try {
      if (Date.now() - statSync(directory).mtimeMs < STALE_MS) continue;
      rmSync(directory, { recursive: true, force: true });
    } catch {
      // A directory that vanished or refuses removal is not worth failing over.
    }
  }
}

function run(command, args, { capture = false, env } = {}) {
  return spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
    maxBuffer: 64 * 1024 * 1024,
    env: env ? { ...process.env, ...env } : process.env,
  });
}

/** Set once the database directory exists, so die() can still remove it. */
let workDirectory = null;

function die(message) {
  // process.exit skips the finally block, and an abandoned database is several
  // hundred megabytes, so the cleanup has to happen here too.
  if (workDirectory) rmSync(workDirectory, { recursive: true, force: true });
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/** Line ranges this branch added, keyed by repository-relative path. */
function addedLines() {
  const merged = run("git", ["merge-base", BASE_REF, "HEAD"], { capture: true });
  if (merged.status !== 0) die(`check-codeql: cannot resolve ${BASE_REF}; fetch it first.`);
  const base = merged.stdout.trim();
  const diff = run("git", ["diff", "-U0", `${base}..HEAD`], { capture: true });
  if (diff.status !== 0) die("check-codeql: git diff failed.");

  const ranges = new Map();
  let file = null;
  for (const line of diff.stdout.split("\n")) {
    if (line.startsWith("+++ b/")) {
      file = line.slice(6);
      continue;
    }
    if (!file || !line.startsWith("@@")) continue;
    // @@ -old,count +new,count @@
    // One flat capture split by hand. Nesting \d+ inside an optional group
    // raises the star height to two, which the regex audit refuses.
    const hunk = /^@@ -[0-9,]+ \+([0-9,]+) @@/.exec(line);
    if (!hunk) continue;
    const [startText, countText] = hunk[1].split(",");
    const start = Number(startText);
    const count = countText === undefined ? 1 : Number(countText);
    if (count === 0) continue;
    if (!ranges.has(file)) ranges.set(file, []);
    ranges.get(file).push([start, start + count - 1]);
  }
  return ranges;
}

function touched(ranges, file, start, end) {
  const spans = ranges.get(file);
  if (!spans) return false;
  return spans.some(([from, to]) => start <= to && end >= from);
}

/** SARIF artifact URIs are escaped and may be absolute; diff paths are neither. */
function normalizeUri(uri) {
  if (typeof uri !== "string") return null;
  let value = uri;
  try {
    value = decodeURIComponent(value);
  } catch {
    // A malformed escape keeps its raw form rather than losing the location.
  }
  value = value.replace(/^file:\/\//, "");
  if (value.startsWith(`${ROOT}/`)) value = value.slice(ROOT.length + 1);
  return value.replace(/^\.\//, "");
}

/**
 * Every physical location a result points at, primary and related. A taint
 * finding often reports the sink on an untouched line while the source the
 * branch introduced sits in relatedLocations, so both have to be considered.
 */
function physicalLocations(result) {
  const found = [];
  for (const entry of [...(result.locations ?? []), ...(result.relatedLocations ?? [])]) {
    const physical = entry?.physicalLocation;
    const file = normalizeUri(physical?.artifactLocation?.uri);
    const start = physical?.region?.startLine;
    if (!file || typeof start !== "number") continue;
    const end = typeof physical.region.endLine === "number" ? physical.region.endLine : start;
    found.push({ file, start, end });
  }
  return found;
}

/**
 * True when the flagged line, or the ten lines above it, carry
 * `codeql-allow: <rule id>`. A finding dismissed on GitHub stays dismissed
 * there; this marker is how the same decision is recorded in the source, where
 * a reviewer reading the code can see it.
 */
function allowed(sources, file, line, rule) {
  if (!sources.has(file)) {
    try {
      sources.set(file, readFileSync(join(ROOT, file), "utf8").split("\n"));
    } catch {
      sources.set(file, []);
    }
  }
  const lines = sources.get(file);
  // CodeQL points at the expression inside a call, which can sit several
  // lines below the comment that explains it, so the window covers the
  // statement rather than just the line.
  return lines
    .slice(Math.max(0, line - 11), line)
    .some((text) => text.includes(`${ALLOW_MARKER} ${rule}`));
}

function main() {
  // The pack is deliberately not pinned. CI analyzes with the bundle shipped
  // inside github/codeql-action, which Renovate advances, so a version frozen
  // here would drift away from the run this gate exists to predict. The
  // version is reported instead, which is what makes a mismatch visible.
  const cli = run("codeql", ["version", "--format=terse"], { capture: true });
  if (cli.status !== 0)
    die(
      "check-codeql: the CodeQL CLI is not installed.\n" +
        "  Install it with:  brew install --cask codeql\n" +
        "  It is the same engine the CodeQL workflow runs, so this gate\n" +
        "  reports the alerts that would otherwise block the pull request.",
    );

  // Ahead of the early return below, so a run with nothing to analyze still
  // clears what an earlier one abandoned.
  sweepStaleDatabases();

  const ranges = addedLines();
  if (ranges.size === 0) {
    console.log("check-codeql: no added lines to analyze.");
    return;
  }

  const work = mkdtempSync(join(tmpdir(), `${WORK_PREFIX}${process.pid}-`));
  workDirectory = work;
  try {
    // The extractor already skips node_modules; EXTRACTION_EXCLUDES covers the
    // generated trees it would otherwise walk. Analysis still reaches every
    // tracked JavaScript and TypeScript file.
    const database = join(work, "db");
    const created = run(
      "codeql",
      [
        "database",
        "create",
        database,
        `--language=${LANGUAGE}`,
        "--build-mode=none",
        `--source-root=${ROOT}`,
        `--ram=${RAM_MB}`,
        "--overwrite",
      ],
      { env: { LGTM_INDEX_FILTERS: INDEX_FILTERS } },
    );
    if (created.status !== 0) die("check-codeql: database creation failed.");

    const sarif = join(work, "results.sarif");
    const analyzed = run("codeql", [
      "database",
      "analyze",
      database,
      SUITE,
      "--format=sarif-latest",
      `--output=${sarif}`,
      `--ram=${RAM_MB}`,
      "--download",
    ]);
    if (analyzed.status !== 0) die("check-codeql: analysis failed.");

    const report = JSON.parse(readFileSync(sarif, "utf8"));
    const rules = new Map();
    for (const run_ of report.runs ?? [])
      for (const rule of run_.tool?.driver?.rules ?? [])
        rules.set(rule.id, rule.properties?.["security-severity"]);

    const sources = new Map();
    const findings = [];
    for (const run_ of report.runs ?? [])
      for (const result of run_.results ?? []) {
        const locations = physicalLocations(result);
        const hit = locations.find((where) => touched(ranges, where.file, where.start, where.end));
        if (!hit) continue;
        // A marker beside any location of the alert counts, because the author
        // may reasonably annotate the sink or the source.
        if (locations.some((where) => allowed(sources, where.file, where.start, result.ruleId)))
          continue;
        findings.push({
          rule: result.ruleId,
          severity: rules.get(result.ruleId),
          file: hit.file,
          line: hit.start,
          message: result.message?.text ?? "",
        });
      }

    if (findings.length === 0) {
      console.log(
        `check-codeql: no new alerts across ${ranges.size} changed file(s) ` +
          `(CodeQL ${cli.stdout.trim()}).`,
      );
      return;
    }

    findings.sort((a, b) => Number(b.severity ?? 0) - Number(a.severity ?? 0));
    process.stderr.write(
      `check-codeql: ${findings.length} new alert(s) on added lines ` +
        `(CodeQL ${cli.stdout.trim()}).\n\n`,
    );
    for (const finding of findings)
      process.stderr.write(
        `  ${finding.file}:${finding.line}\n` +
          `    ${finding.rule}${finding.severity ? ` (severity ${finding.severity})` : ""}\n` +
          `    ${finding.message}\n\n`,
      );
    process.stderr.write(
      "These are the alerts the CodeQL check reports on the pull request.\n" +
        `Fix them, or record the decision in the source with a ${ALLOW_MARKER} <rule id> comment.\n`,
    );
    // Not process.exit: that skips the finally below, and reporting alerts is
    // the failure this gate takes most often. Nothing runs after main().
    process.exitCode = 1;
  } finally {
    rmSync(work, { recursive: true, force: true });
    workDirectory = null;
  }
}

main();
