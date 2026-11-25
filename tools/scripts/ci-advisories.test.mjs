import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

it.each([
  ["", "create"],
  ["17", "edit"],
])("reports a failed dependency audit with gh issue %s -> %s", (issue, operation) => {
  const temp = mkdtempSync(join(tmpdir(), "ci-advisory-"));
  try {
    const calls = join(temp, "calls");
    writeFileSync(
      join(temp, "gh"),
      `#!/bin/sh
printf '%s\\n' "$*" >> "$GH_CALLS"
if [ "$2" = list ] && [ -n "$OPEN_ISSUE" ]; then printf '%s\\n' "$OPEN_ISSUE"; fi
`,
      { mode: 0o700 },
    );
    const result = spawnSync("bash", [".github/scripts/report-advisory-failure.sh"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${temp}:${process.env.PATH}`,
        GH_REPO: "owner/repository",
        RUN_URL: "https://github.com/owner/repository/actions/runs/23",
        GH_CALLS: calls,
        OPEN_ISSUE: issue,
      },
    });
    expect(result.status, result.stderr).toBe(0);
    const commands = readFileSync(calls, "utf8").split("\n");
    expect(commands[0]).toContain("issue list");
    expect(commands[1]).toContain(`issue ${operation}${issue ? " " + issue : ""}`);
    expect(commands[1]).toContain("actions/runs/23");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
