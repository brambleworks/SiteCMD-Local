import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

// Runs the check with only a fake actionlint on the path, which prints the given version.
function checkWith(printed) {
  const bin = mkdtempSync(join(tmpdir(), "sitecmd-actionlint-"));
  try {
    const fake = join(bin, "actionlint");
    writeFileSync(
      fake,
      `#!/bin/sh\n[ "$1" = "-version" ] && printf '%s\\n' '${printed}'\nexit 0\n`,
    );
    chmodSync(fake, 0o755);
    return spawnSync(process.execPath, ["tools/scripts/check-workflows.mjs"], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:/usr/bin:/bin` },
    });
  } finally {
    rmSync(bin, { recursive: true, force: true });
  }
}

it.skipIf(process.platform === "win32")(
  "prevents a Homebrew build of the pinned actionlint failing the version check",
  () => {
    // Bug: Homebrew's build prints `1.7.12` where `go install` prints `v1.7.12`, so the same release failed.
    expect(checkWith("1.7.12").status).toBe(0);
    expect(checkWith("v1.7.12").status).toBe(0);
    const older = checkWith("1.7.11");
    expect(older.status).toBe(1);
    expect(older.stderr).toContain("found v1.7.11");
  },
);
