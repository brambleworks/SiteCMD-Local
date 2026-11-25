#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const MIGRATIONS_DIR = "apps/desktop/src-tauri/src/db/migrations/";
const PLACEHOLDER_REASON_RE = /^(?:<[^>]*>|todo|tbd|reason(?: here)?|n\/?a|because|\.+)$/i;

const TRIPWIRES = [
  {
    id: "new-persisted-data",
    label: "new persisted data",
    why: "a new migration means the app stores something it did not before",
    match: ({ changes }) =>
      changes
        .filter((c) => c.status.startsWith("A") && c.file.startsWith(MIGRATIONS_DIR))
        .map((c) => c.file),
  },
];

export function git(args, { cwd = ROOT, allowFailure = false } = {}) {
  try {
    // Suppress expected `git` misses from optional probes.
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    if (allowFailure) return "";
    throw error;
  }
}

/** The most recent `v*` tag reachable from `rev`, or null when none exists. */
export function lastReleaseTag(rev = "HEAD", { cwd = ROOT } = {}) {
  return (
    git(["describe", "--tags", "--abbrev=0", "--match", "v*", rev], {
      cwd,
      allowFailure: true,
    }) || null
  );
}

/** Everything the tripwires need, gathered from real git state. */
export function collectReleaseSignals({ from, to = "HEAD", cwd = ROOT } = {}) {
  const raw = git(["diff", "--name-status", `${from}..${to}`], { cwd });
  const changes = raw
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [status, ...rest] = line.split("\t");
      // Use the destination path for renames.
      return { status, file: rest[rest.length - 1] };
    });

  return { changes };
}

/** True when `next` only advances the patch component of `current`. */
export function isPatchLevel(current, next) {
  const a = current.match(/^(\d+)\.(\d+)\.(\d+)/);
  const b = next.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!a || !b) return false;
  return a[1] === b[1] && a[2] === b[2] && a[3] !== b[3];
}

/** Pure evaluation, so the rules are testable without a repo. */
export function evaluateReleaseBump(signals, rules = TRIPWIRES) {
  return rules
    .map((rule) => ({ rule, evidence: rule.match(signals) }))
    .filter((hit) => hit.evidence.length > 0);
}

function releaseHits(from, to, cwd) {
  const hits = evaluateReleaseBump(collectReleaseSignals({ from, to, cwd }));
  const manifest = path.join(cwd, "package.json");
  if (!existsSync(manifest)) return hits;
  const command = "private:release-signals";
  if (!JSON.parse(readFileSync(manifest, "utf8")).scripts?.[command]) return hits;
  const privateHits = execFileSync("pnpm", ["--silent", "run", command, from, to], {
    cwd,
    encoding: "utf8",
  });
  return [...hits, ...JSON.parse(privateHits)];
}

function formatRefusal(hits, { from, to }) {
  const lines = [
    `"patch" refused: ${from}..${to} is at least a minor.`,
    "",
    ...hits.flatMap(({ rule, evidence }) => [
      `  ${rule.label} (${rule.why}):`,
      ...evidence.slice(0, 5).map((item) => `    ${item}`),
      ...(evidence.length > 5 ? [`    ...and ${evidence.length - 5} more`] : []),
    ]),
    "",
    "Use `pnpm release minor`, or override on the record with",
    '  --force-patch "<why this is genuinely only fixes>"',
  ];
  return lines.join("\n");
}

/** Reject patch bumps that the requested range cannot represent. */
export function assertBumpAllowed({ currentVersion, nextVersion, forcePatch, cwd = ROOT } = {}) {
  if (!isPatchLevel(currentVersion, nextVersion)) return { checked: false };

  const from = lastReleaseTag("HEAD", { cwd });
  if (!from) return { checked: false, note: "no previous v* tag to compare against" };

  const hits = releaseHits(from, "HEAD", cwd);
  if (hits.length === 0) return { checked: true, from, hits };

  if (forcePatch) {
    if (PLACEHOLDER_REASON_RE.test(forcePatch.trim()) || forcePatch.trim().length < 12) {
      throw new Error(
        `--force-patch needs a real justification, got "${forcePatch}".\n` +
          "It is recorded in the release commit, so write the reason you would\n" +
          "want to read back when this release is questioned later.",
      );
    }
    return { checked: true, from, hits, forced: forcePatch.trim() };
  }

  throw new Error(formatRefusal(hits, { from, to: "HEAD" }));
}

function main() {
  const argv = process.argv.slice(2);
  const positional = argv.filter((a) => !a.startsWith("--"));
  const flagValue = (name) => {
    const inline = argv.find((a) => a.startsWith(`--${name}=`));
    if (inline) return inline.slice(name.length + 3);
    const index = argv.indexOf(`--${name}`);
    return index >= 0 ? argv[index + 1] : undefined;
  };

  // Resolve paths against the caller's repository root.
  const cwd =
    git(["rev-parse", "--show-toplevel"], { cwd: process.cwd(), allowFailure: true }) || ROOT;

  const from = flagValue("from") ?? lastReleaseTag("HEAD", { cwd });
  const to = flagValue("to") ?? "HEAD";
  if (!from) {
    console.log("check-release-bump: no previous v* tag; nothing to compare.");
    process.exit(0);
  }

  const hits = releaseHits(from, to, cwd);
  const bump = positional[0] ?? "patch";

  if (hits.length === 0) {
    console.log(`check-release-bump: ${from}..${to} shows no minor-level signals.`);
    process.exit(0);
  }

  if (bump === "patch") {
    console.error(`check-release-bump: ${formatRefusal(hits, { from, to })}`);
    process.exit(1);
  }

  console.log(`check-release-bump: ${from}..${to} is at least a minor:`);
  for (const { rule, evidence } of hits) {
    console.log(`  ${rule.label}: ${evidence.length} signal(s)`);
  }
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
