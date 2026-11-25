#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const BUDGET_FILE_PATTERNS = [
  /^tools\/scripts\/check-repo-guardrails\.mjs$/,
  /^tools\/scripts\/lib\/guardrail-.*\.mjs$/,
  /^tools\/scripts\/check-knip-export-budget\.mjs$/,
  // Rust ratchet constants (e.g. STRING_RESULT_COMMAND_BUDGET) live in the
  // test module, not a tools/scripts/*.mjs file; cover it explicitly.
  /^apps\/desktop\/src-tauri\/src\/lib_tests\.rs$/,
];

const BYPASS_TOKEN_RE = /^\[budget-raised:[^\]]+\]/m;
const BYPASS_PLACEHOLDER_RE = /^\[budget-raised:\s*(?:<[^>]+>|TODO|todo|reason here)\s*\]/m;
const BYPASS_ISSUE_REFERENCE_RE = /(?:#|\b(?:GH|PR|gh|pr)-)\d+/;

function bypassTokenStatus(message) {
  if (!BYPASS_TOKEN_RE.test(message)) {
    return { ok: false, reason: "no_token" };
  }
  // GitHub hard-wraps squash commit bodies, so a token can span lines.
  const candidates = [...message.matchAll(new RegExp(BYPASS_TOKEN_RE.source, "gm"))].map(
    ([token]) => token.replace(/\s+/g, " "),
  );

  for (const line of candidates) {
    if (BYPASS_PLACEHOLDER_RE.test(line)) continue;
    if (!BYPASS_ISSUE_REFERENCE_RE.test(line)) {
      return { ok: false, reason: "missing_issue_reference", line };
    }
    return { ok: true };
  }
  return { ok: false, reason: "placeholder_only" };
}

function extractThresholds(source) {
  const thresholds = new Map();
  const lines = source.split("\n");

  const code = lines.map((rawLine) => rawLine.replace(/\/\/.*$/, "")).join("\n");
  // A path long enough for the formatter to wrap spreads its pair over lines.
  for (const match of code.matchAll(/\[\s*"([^"]+)"\s*,\s*(\d+)\s*,?\s*\]/g)) {
    thresholds.set(match[1], Number(match[2]));
  }

  for (const rawLine of lines) {
    const line = rawLine.replace(/\/\/.*$/, "");

    for (const match of line.matchAll(/file:\s*"([^"]+)"[^}]*maxLines:\s*(\d+)/g)) {
      thresholds.set(match[1], Number(match[2]));
    }
    // Matches both the JS shape (`export const NAME = N`) and the Rust
    // shape (`pub(crate) const NAME: usize = N;`), whose optional type
    // annotation sits between the name and the `=`. The threshold-suffix
    // test lives in plain code because folding it into the name pattern
    // makes the regex superlinear (safe-regex flags it).
    // Only declarations define budgets; quoted source assertions do not.
    const declaration = line
      .trimStart()
      .replace(/^export\s+/, "")
      .replace(/^pub\s+/, "")
      .replace(/^pub\([a-z:]+\)\s+/, "");
    for (const match of declaration.matchAll(/^const\s+([A-Z][A-Z0-9_]*)/g)) {
      const name = match[1];
      if (!/_(?:LIMIT|BUDGET|CAP|MAXLINES)$/.test(name) && !/_MAX_[A-Z_]+$/.test(name)) {
        continue;
      }
      const rest = declaration.slice(match.index + match[0].length);
      const eq = rest.indexOf("=");
      if (eq === -1) {
        continue;
      }
      const annotation = rest.slice(0, eq).trim();
      if (annotation !== "" && !annotation.startsWith(":")) {
        continue;
      }
      const value = rest
        .slice(eq + 1)
        .trimStart()
        .match(/^\d+/);
      if (!value) {
        continue;
      }
      thresholds.set(`const:${name}`, Number(value[0]));
    }
  }

  const multilineRe = /file:\s*"([^"]+)"[^}]*?maxLines:\s*(\d+)/gs;
  for (const match of source.matchAll(multilineRe)) {
    thresholds.set(match[1], Number(match[2]));
  }

  return thresholds;
}

function readFromRevision(revision, relativePath) {
  try {
    return execFileSync("git", ["show", `${revision}:${relativePath}`], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    // New files have no previous thresholds.
    return "";
  }
}

function readFromStaged(relativePath) {
  try {
    return execFileSync("git", ["show", `:${relativePath}`], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
}

// A file git records as renamed keeps its threshold under the new path, so the
// moved key is compared with the value its old path held.
function renamedPaths(range) {
  const args = range
    ? ["diff", "-M", "--name-status", "--diff-filter=R", `${range.base}..${range.head}`]
    : ["diff", "--cached", "-M", "--name-status", "--diff-filter=R"];
  const renames = new Map();
  for (const line of execFileSync("git", args, { encoding: "utf8" }).split("\n")) {
    const [status, from, to] = line.split("\t");
    if (status?.startsWith("R") && from && to) renames.set(to, from);
  }
  return renames;
}

function diffThresholds(oldMap, newMap, renames = new Map()) {
  const violations = [];
  for (const [key, newValue] of newMap) {
    const oldValue = oldMap.get(key) ?? oldMap.get(renames.get(key));
    if (oldValue === undefined) {
      violations.push({ key, kind: "new", oldValue: null, newValue });
    } else if (newValue > oldValue) {
      violations.push({ key, kind: "increase", oldValue, newValue });
    }
  }
  return violations;
}

function commitEditMessagePath() {
  // `.git` is a file (a gitlink), not a directory, in a linked worktree, so a
  // hardcoded `.git/COMMIT_EDITMSG` join silently misses the real file there
  // and this falls back to the previous commit's message instead of the
  // pending one. Ask git, which resolves the per-worktree path correctly.
  try {
    return execFileSync("git", ["rev-parse", "--git-path", "COMMIT_EDITMSG"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return path.join(".git", "COMMIT_EDITMSG");
  }
}

function commitMessage(rangeTip) {
  // Accept a bypass marker from any commit in the checked range.
  if (rangeTip) {
    try {
      return execFileSync("git", ["log", "--pretty=%B", `${rangeTip.base}..${rangeTip.head}`], {
        encoding: "utf8",
      });
    } catch {
      return "";
    }
  }
  const messageFile = commitEditMessagePath();
  if (fs.existsSync(messageFile)) {
    try {
      return fs.readFileSync(messageFile, "utf8");
    } catch {
      // Fall back to the latest commit message.
    }
  }
  try {
    return execFileSync("git", ["log", "-1", "--pretty=%B"], { encoding: "utf8" });
  } catch {
    return "";
  }
}

function checkFile(relativePath, source, baseRev, renames, baselineFiles) {
  const oldSource = readFromRevision(baseRev, renames.get(relativePath) ?? relativePath);
  const oldMap = new Map([
    ...baselineFiles.flatMap((file) => [...extractThresholds(readFromRevision(baseRev, file))]),
    ...extractThresholds(oldSource),
  ]);
  const newMap = extractThresholds(source);
  return diffThresholds(oldMap, newMap, renames);
}

function parseArgs(argv, isBudgetFile) {
  const args = argv.slice(2);
  if (args.length === 0 || args[0] === "--staged") {
    const staged = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=AMR"], {
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean);
    return { files: staged.filter(isBudgetFile), mode: "staged" };
  }
  if (args[0] === "--range") {
    const range = args[1];
    if (!range) {
      console.error("--range requires a revision range argument (e.g., HEAD~1..HEAD)");
      process.exit(2);
    }
    const [, , option, messageFile, extra] = args;
    if (
      option !== undefined &&
      (option !== "--message-file" || !messageFile || extra !== undefined)
    ) {
      console.error("--range accepts only an optional --message-file <path>");
      process.exit(2);
    }
    const [base, head] = range.split("..");
    if (!base || !head) {
      console.error("--range expects A..B format (e.g., HEAD~1..HEAD)");
      process.exit(2);
    }
    const changed = execFileSync("git", ["diff", "--name-only", "--diff-filter=AMR", range], {
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean);
    return {
      files: changed.filter(isBudgetFile),
      mode: "range",
      range: { base, head },
      messageFile,
    };
  }
  return { files: args.filter(isBudgetFile), mode: "files" };
}

export function runBudgetRatchet({ patterns = BUDGET_FILE_PATTERNS, baselines = new Map() } = {}) {
  const isBudgetFile = (file) => {
    const normalized = file.replace(/\\/g, "/");
    return patterns.some((pattern) => pattern.test(normalized));
  };
  const parsed = parseArgs(process.argv, isBudgetFile);
  const { mode, range } = parsed;
  const renames = mode === "files" ? new Map() : renamedPaths(range);
  // A budget file moved to a path outside the patterns is still checked.
  const movedBudgets = [...renames].filter(([, from]) => isBudgetFile(from)).map(([to]) => to);
  const files = [...new Set([...parsed.files, ...movedBudgets])];
  if (files.length === 0) return;

  const baseRev = range ? range.base : "HEAD";

  const allViolations = [];
  for (const file of files) {
    let source;
    if (mode === "staged") {
      source = readFromStaged(file);
    } else if (mode === "range") {
      source = readFromRevision(range.head, file);
    } else {
      source = fs.readFileSync(file, "utf8");
    }
    if (source == null) continue;
    const violations = checkFile(file, source, baseRev, renames, baselines.get(file) ?? []);
    for (const v of violations) {
      allViolations.push({ file, ...v });
    }
  }

  if (allViolations.length === 0) return;

  const message = parsed.messageFile
    ? fs.readFileSync(parsed.messageFile, "utf8")
    : commitMessage(range);
  const status = bypassTokenStatus(message);
  if (status.ok) {
    console.warn(
      `check-budget-ratchet: ${allViolations.length} budget change(s) authorized via [budget-raised:] token in commit message. Logged for audit:`,
    );
    for (const v of allViolations) describeViolation(v, console.warn);
    return;
  }

  console.error("check-budget-ratchet: refusing to raise guardrail thresholds.");
  if (status.reason === "missing_issue_reference") {
    console.error(
      "The [budget-raised:] token must reference a tracked issue or PR\n" +
        "(e.g. `#123`, `PR-456`, `fixes #789`) so every override has a\n" +
        "reviewable artifact. CODEOWNERS on .github/CODEOWNERS gates the\n" +
        "review step on the same files.\n",
    );
    if (status.line) console.error(`  Found: ${status.line}\n`);
  } else {
    console.error(
      "Ratchets may only decrease. If the code can't be refactored to fit, add\n" +
        "`[budget-raised: <reason> (#123)]` to the commit message to record an\n" +
        "explicit override tied to a tracked issue/PR.\n",
    );
  }
  for (const v of allViolations) describeViolation(v, console.error);
  process.exit(1);
}

function describeViolation(v, log) {
  if (v.kind === "new") {
    log(`  ${v.file}: new threshold "${v.key}" = ${v.newValue} (was absent)`);
  } else {
    log(`  ${v.file}: "${v.key}" raised ${v.oldValue} -> ${v.newValue}`);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  runBudgetRatchet();
}
