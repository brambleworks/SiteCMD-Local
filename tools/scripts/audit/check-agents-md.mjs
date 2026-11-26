#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { posix as path } from "node:path";
import { fileURLToPath } from "node:url";
import { guideTriggers, markdownParts } from "../lib/agent-guide-markdown.mjs";
import { guidePath, referenceFailures } from "../lib/agent-guide-references.mjs";
import { bypassTokenStatus, changeMessage } from "../lib/change-message.mjs";

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
}

function paths(output) {
  return [...new Set(output.split("\0").filter(Boolean))].sort();
}

function isGuide(file) {
  return path.basename(file) === "AGENTS.md";
}

function checkReferences() {
  const guides = paths(git("ls-files", "-z", "--cached", "--others", "--exclude-standard"))
    .filter(isGuide)
    .filter((file) => fs.existsSync(file));
  const failures = guides.flatMap((guide) =>
    referenceFailures(guide, fs.readFileSync(guide, "utf8")),
  );
  if (failures.length) {
    console.error(`AGENTS.md staleness check failed:\n  ${failures.join("\n  ")}`);
    return 1;
  }
  console.log(`AGENTS.md staleness check passed (${guides.length} files).`);
  return 0;
}

function checkTriggers({ base, head, messageFile }) {
  const diff = base ? [`${base}..${head}`] : ["--cached"];
  const changed = paths(git("diff", "--no-renames", "--name-only", "-z", ...diff, "--"));
  const files = head
    ? git("ls-tree", "-r", "--name-only", "-z", head)
    : git("ls-files", "-z", "--cached");
  const unchangedGuides = paths(files).filter((file) => isGuide(file) && !changed.includes(file));
  const violations = [];
  for (const guide of unchangedGuides) {
    const { prose } = markdownParts(git("show", `${head ?? ""}:${guide}`));
    const globs = (guideTriggers(prose) ?? []).map((trigger) => guidePath(guide, trigger));
    const matches = changed.filter((file) => globs.some((glob) => path.matchesGlob(file, glob)));
    if (matches.length) violations.push(`  ${guide}: ${matches.join(", ")}`);
  }
  if (violations.length === 0) {
    console.log("Guide trigger check passed.");
    return 0;
  }

  const status = bypassTokenStatus(changeMessage({ base, head, messageFile }), "guide-unchanged");
  if (status.ok) {
    console.warn("Guide trigger check authorized via [guide-unchanged:]:");
    console.warn(violations.join("\n"));
    return 0;
  }
  console.error(
    "Guide trigger check failed. Update each guide below or add [guide-unchanged: <reason> (#123)].",
  );
  if (status.reason === "missing_issue_reference") {
    console.error(
      `The [guide-unchanged:] token must reference a tracked issue or PR. Found: ${status.line}`,
    );
  }
  console.error(violations.join("\n"));
  return 1;
}

function main(args) {
  if (args.length === 0) return checkReferences();
  const mode = args.shift();
  const revisions = mode === "--range" ? args.shift()?.split("..") : [];
  const [base, head] = revisions ?? [];
  const [messageOption, messageFile] = args;
  if (
    !(mode === "--staged" || (mode === "--range" && revisions?.length === 2 && base && head)) ||
    (args.length !== 0 && (args.length !== 2 || messageOption !== "--message-file" || !messageFile))
  ) {
    console.error(
      "Usage: check-agents-md.mjs [--range BASE..HEAD | --staged] [--message-file PATH]",
    );
    return 2;
  }
  return checkTriggers({ base, head, messageFile });
}

process.chdir(fileURLToPath(new URL("../../..", import.meta.url)));
process.exitCode = main(process.argv.slice(2));
