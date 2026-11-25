import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

it.skipIf(process.platform === "win32").each([undefined, "0"])(
  "refuses an unpinned CLI with SITECMD_ENGINE_UNPINNED=%s",
  (optIn) => {
    // Bug: Smoke accepts an unpinned binary without an explicit opt-in.
    const dir = mkdtempSync(join(tmpdir(), "sitecmd-cli-version-"));
    try {
      const manifest = readFileSync("apps/desktop/src-tauri/crates/cli/Cargo.toml", "utf8");
      const [, version] = manifest.match(/^version = "([^"]+)"/m);
      const binary = join(dir, "sitecmd");
      writeFileSync(binary, `#!/bin/sh\nprintf '%s\\n' 'sitecmd ${version}+unpinned'\n`, {
        mode: 0o755,
      });
      const env = { ...process.env, SITECMD_CLI_BINARY: binary };
      if (optIn === undefined) delete env.SITECMD_ENGINE_UNPINNED;
      else env.SITECMD_ENGINE_UNPINNED = optIn;
      const result = spawnSync(process.execPath, ["tools/scripts/cli-smoke.mjs"], {
        encoding: "utf8",
        env,
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        `--version printed "sitecmd ${version}+unpinned", expected "sitecmd ${version}"`,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
