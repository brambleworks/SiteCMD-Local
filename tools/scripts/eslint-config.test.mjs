import { ESLint } from "eslint";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../..", import.meta.url));

describe("ESLint build output exclusions", () => {
  it.each([
    "target/debug/sitecmd-mcp/sitecmd-mcp.mjs",
    "apps/desktop/src-tauri/target/debug/sitecmd-mcp/sitecmd-mcp.mjs",
  ])("ignores generated output at %s", async (path) => {
    // Rust target bundles are linted as source and fail on bundled dependency directives.
    const eslint = new ESLint({ cwd: root });
    expect(await eslint.isPathIgnored(path)).toBe(true);
  });
});
