import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import {
  collectReleaseSignals,
  evaluateReleaseBump,
  git as runGit,
  isPatchLevel,
  lastReleaseTag,
} from "./check-release-bump.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = path.join(ROOT, "tools/scripts/check-release-bump.mjs");

const NO_SIGNALS = {
  changes: [],
};

const signals = (overrides) => ({ ...NO_SIGNALS, ...overrides });
const firedIds = (input) => evaluateReleaseBump(input).map((hit) => hit.rule.id);

describe("tripwire rules", () => {
  it("stays silent on a range with nothing minor-level in it", () => {
    expect(
      firedIds(
        signals({
          changes: [
            { status: "M", file: ".github/workflows/ci.yml" },
            { status: "M", file: "apps/desktop/src-tauri/src/cli/output.rs" },
          ],
        }),
      ),
    ).toEqual([]);
  });

  it("fires on an added migration but not on editing an existing one", () => {
    const added = signals({
      changes: [{ status: "A", file: "apps/desktop/src-tauri/src/db/migrations/010_thing.sql" }],
    });
    expect(firedIds(added)).toContain("new-persisted-data");

    const edited = signals({
      changes: [{ status: "M", file: "apps/desktop/src-tauri/src/db/migrations/001_baseline.sql" }],
    });
    expect(firedIds(edited)).not.toContain("new-persisted-data");
  });

  it("carries evidence so a refusal explains itself", () => {
    const [hit] = evaluateReleaseBump(
      signals({
        changes: [{ status: "A", file: "apps/desktop/src-tauri/src/db/migrations/010_thing.sql" }],
      }),
    );
    expect(hit.evidence).toEqual(["apps/desktop/src-tauri/src/db/migrations/010_thing.sql"]);
    expect(hit.rule.why).toMatch(/persists|stores/);
  });
});

describe("isPatchLevel", () => {
  it("recognises a patch-only advance", () => {
    expect(isPatchLevel("1.3.1", "1.3.2")).toBe(true);
  });

  it("rejects minor and major advances", () => {
    expect(isPatchLevel("1.3.1", "1.4.0")).toBe(false);
    expect(isPatchLevel("1.3.1", "2.0.0")).toBe(false);
  });
});

describe("against real git state", { timeout: 30_000 }, () => {
  const made = [];

  afterEach(() => {
    while (made.length) fs.rmSync(made.pop(), { recursive: true, force: true });
  });

  function makeRepo() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "release-bump-"));
    made.push(dir);
    const git = (...a) => execFileSync("git", a, { cwd: dir, encoding: "utf8" });
    git("init", "--quiet");
    git("config", "user.email", "test@example.com");
    git("config", "user.name", "Test");
    git("config", "commit.gpgSign", "false");
    git("config", "tag.gpgSign", "false");
    return { dir, git };
  }

  function write(dir, rel, contents) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, contents);
  }

  it("reads a real diff and refuses a patch over an added migration", () => {
    const { dir, git } = makeRepo();
    write(dir, "README.md", "seed\n");
    git("add", "-A");
    git("commit", "--quiet", "-m", "seed");
    git("tag", "-m", "Release v1.0.0", "v1.0.0");

    write(dir, "apps/desktop/src-tauri/src/db/migrations/010_thing.sql", "SELECT 1;\n");
    git("add", "-A");
    git("commit", "--quiet", "-m", "add migration");

    expect(lastReleaseTag("HEAD", { cwd: dir })).toBe("v1.0.0");

    const collected = collectReleaseSignals({ from: "v1.0.0", to: "HEAD", cwd: dir });
    expect(collected.changes).toContainEqual({
      status: "A",
      file: "apps/desktop/src-tauri/src/db/migrations/010_thing.sql",
    });
    expect(firedIds(collected)).toContain("new-persisted-data");

    const run = spawnSync("node", [SCRIPT, "patch", "--from", "v1.0.0"], {
      cwd: dir,
      encoding: "utf8",
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/at least a minor/);
    expect(run.stderr).toMatch(/010_thing\.sql/);
  });

  it("returns no revision when an optional Git probe misses", () => {
    // Bug: A missing Git revision can abort a release signal probe.
    const { dir } = makeRepo();
    expect(runGit(["rev-parse", "--verify", "HEAD"], { cwd: dir, allowFailure: true })).toBe("");
  });

  it("allows a patch when the range is genuinely only fixes", () => {
    const { dir, git } = makeRepo();
    write(dir, "README.md", "seed\n");
    git("add", "-A");
    git("commit", "--quiet", "-m", "seed");
    git("tag", "-m", "Release v1.0.0", "v1.0.0");

    write(dir, "README.md", "seed\nfixed a typo\n");
    git("add", "-A");
    git("commit", "--quiet", "-m", "fix typo");

    const run = spawnSync("node", [SCRIPT, "patch", "--from", "v1.0.0"], {
      cwd: dir,
      encoding: "utf8",
    });
    expect(run.status).toBe(0);
    expect(run.stdout).toMatch(/no minor-level signals/);
  });
});
