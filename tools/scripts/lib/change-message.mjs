/** Read commit messages and validate tracked-issue overrides for repository checks. */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ISSUE_REFERENCE = /(?:#|\b(?:GH|PR|gh|pr)-)\d+/;

export function bypassTokenStatus(message, label) {
  const tokenPattern = new RegExp(`^\\[${label}:[^\\]]+\\]`, "gm");
  const placeholder = new RegExp(`^\\[${label}:\\s*(?:<[^>]+>|TODO|todo|reason here)\\s*\\]`);
  const tokens = [...message.matchAll(tokenPattern)];
  if (tokens.length === 0) return { ok: false, reason: "no_token" };

  // GitHub hard-wraps squash commit bodies, so a token can span lines.
  for (const [token] of tokens) {
    const line = token.replace(/\s+/g, " ");
    if (placeholder.test(line)) continue;
    if (!ISSUE_REFERENCE.test(line)) {
      return { ok: false, reason: "missing_issue_reference", line };
    }
    return { ok: true };
  }
  return { ok: false, reason: "placeholder_only" };
}

function commitEditMessagePath() {
  // Ask Git for the per-worktree message path.
  try {
    return execFileSync("git", ["rev-parse", "--git-path", "COMMIT_EDITMSG"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return path.join(".git", "COMMIT_EDITMSG");
  }
}

export function changeMessage({ base, head, messageFile } = {}) {
  if (messageFile) return fs.readFileSync(messageFile, "utf8");

  if (!base) {
    const pending = commitEditMessagePath();
    if (fs.existsSync(pending)) {
      try {
        return fs.readFileSync(pending, "utf8");
      } catch {
        // Fall back to the latest commit message.
      }
    }
  }

  try {
    return execFileSync("git", ["log", "--pretty=%B", base ? `${base}..${head}` : "-1"], {
      encoding: "utf8",
    });
  } catch {
    return "";
  }
}
