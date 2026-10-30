import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

it("makes the checks script exit non-zero when cargo produces a checkout path leak", () => {
  const fixture = realpathSync(mkdtempSync(path.join(tmpdir(), "sitecmd-wasm-script-")));
  const sourceRoot = fileURLToPath(new URL("../..", import.meta.url));
  try {
    const scripts = path.join(fixture, "tools", "scripts");
    const bin = path.join(fixture, "bin");
    mkdirSync(path.join(scripts, "lib"), { recursive: true });
    mkdirSync(path.join(fixture, "apps", "desktop", "src-tauri"), { recursive: true });
    mkdirSync(bin);
    for (const file of ["build-checks-wasm.mjs", "lib/wasm-vendor.mjs"]) {
      copyFileSync(path.join(sourceRoot, "tools", "scripts", file), path.join(scripts, file));
    }
    expect(spawnSync("git", ["init", "--quiet", fixture]).status).toBe(0);
    writeFileSync(
      path.join(bin, "cargo"),
      `#!/usr/bin/env node
const { mkdirSync, writeFileSync } = require("node:fs");
const path = require("node:path");
const target = path.join(process.cwd(), "target", "wasm32-unknown-unknown", "wasm-release");
mkdirSync(target, { recursive: true });
writeFileSync(path.join(target, "sitecmd_engine_wasm.wasm"),
  Buffer.from(${JSON.stringify(`\0asm\0${fixture}/crates/engine/src/lib.rs`)}));
`,
      { mode: 0o755 },
    );
    const outDir = path.join(fixture, "output");
    const result = spawnSync(
      process.execPath,
      [path.join(scripts, "build-checks-wasm.mjs"), "--allow-dirty", "--out", outDir],
      {
        cwd: fixture,
        env: {
          ...process.env,
          PATH: `${bin}${path.delimiter}${process.env.PATH}`,
          CARGO_HOME: path.join(fixture, "..", "external-cargo"),
        },
        encoding: "utf8",
      },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`WASM artifact contains local path: ${fixture}`);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
