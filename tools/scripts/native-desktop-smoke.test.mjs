import { readFileSync } from "node:fs";
import path from "node:path";
import { runInNewContext } from "node:vm";
import { expect, it } from "vitest";

const source = readFileSync("tools/scripts/native-desktop-smoke.mjs", "utf8");
const assignments = source.slice(
  source.indexOf("const binary ="),
  source.indexOf("await Promise.all"),
);
const root = "/tmp/sitecmd-smoke";

it("uses the default native artifacts when overrides are empty", () => {
  const result = runInNewContext(`${assignments}\n({ binary, bundle });`, {
    path,
    root,
    process: { env: { SITECMD_SMOKE_BINARY: "", SITECMD_SMOKE_MCP: "" } },
  });
  expect(result.binary).toBe(path.join(root, "apps/desktop/src-tauri/target/debug/sitecmd"));
  expect(result.bundle).toBe(path.join(root, "apps/mcp-server/dist-bundle/sitecmd-mcp.mjs"));
});

it("uses explicit native artifact overrides", () => {
  const result = runInNewContext(`${assignments}\n({ binary, bundle });`, {
    path,
    root,
    process: {
      env: {
        SITECMD_SMOKE_BINARY: "/tmp/custom-sitecmd",
        SITECMD_SMOKE_MCP: "/tmp/custom-mcp.mjs",
      },
    },
  });
  expect(result.binary).toBe("/tmp/custom-sitecmd");
  expect(result.bundle).toBe("/tmp/custom-mcp.mjs");
});
