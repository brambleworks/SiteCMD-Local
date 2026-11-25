import { configDefaults, defineConfig } from "vitest/config";
import { workerCount } from "./tools/scripts/lib/test-workers.mjs";

// Agent worktrees checked out under .claude/worktrees/ carry full copies of
// tools/scripts; without this exclusion `vitest run tools/scripts` discovers
// every copy and each one scans its own stale tree (30 installer timeouts and
// duplicated guardrail failures on 2026-08-24). Codex worktrees live outside
// the repository directory and are never discovered.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "**/.claude/**"],
    maxWorkers: workerCount(),
  },
});
