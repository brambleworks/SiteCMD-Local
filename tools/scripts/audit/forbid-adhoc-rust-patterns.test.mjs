import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPT = path.resolve("tools/scripts/audit/forbid-adhoc-rust-patterns.sh");
const SRC = "apps/desktop/src-tauri/src";
const RAW_ERROR = ".map_err(|e| e.to_string())";

describe("forbid-adhoc-rust-patterns", () => {
  let root;

  function write(file, source) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), source);
  }

  const run = () => spawnSync("bash", [SCRIPT], { cwd: root, encoding: "utf8" });

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-rust-patterns-"));
    for (const dir of ["cli", "core", "db"]) write(`${SRC}/${dir}/mod.rs`, "pub fn ok() {}\n");
  });

  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  // Bug: the guides beside this code quote the forbidden patterns while
  // describing the rule, and the check matched the Markdown as a violation.
  it("ignores the patterns quoted in a guide", () => {
    write(`${SRC}/cli/AGENTS.md`, `- Never use \`${RAW_ERROR}\` or \`reqwest::Client::new\`.\n`);
    write(`${SRC}/db/AGENTS.md`, `- The database layer never uses \`${RAW_ERROR}\`.\n`);
    const result = run();
    expect(result.status, result.stdout + result.stderr).toBe(0);
  });

  it("still rejects a raw error in production Rust", () => {
    write(`${SRC}/db/store.rs`, `pub fn read() -> Result<(), String> { load()${RAW_ERROR} }\n`);
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(`${SRC}/db/store.rs:1:`);
  });

  it("still rejects an ad hoc HTTP client in production Rust", () => {
    write(`${SRC}/core/fetch.rs`, "let client = reqwest::Client::new();\n");
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(`${SRC}/core/fetch.rs:1:`);
  });
});
