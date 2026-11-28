import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { workflowBlock } from "./lib/guardrail-text-utils.mjs";

const releaseWorkflow = readFileSync(
  new URL("../../.github/workflows/release.yml", import.meta.url),
  "utf8",
);

function assertReleaseEngineProvisioning(source) {
  const preflight = source.slice(
    source.indexOf("\n  preflight:"),
    source.indexOf("\n  prepare-candidate:"),
  );
  const [preflightHeader, ...steps] = preflight.split(/^ {6}- /m);
  const workflowHeader = source.split(/^jobs:/m, 1)[0];
  expect(workflowHeader + preflightHeader, "unscoped unpinned flag").not.toContain(
    "SITECMD_ENGINE_UNPINNED",
  );
  const standInStep = steps.find((step) =>
    step.includes("run: node tools/scripts/build-standin.mjs"),
  );
  expect(standInStep, "stand-in working directory").not.toContain("working-directory:");
  const pinnedFetch = preflight.indexOf("run: pnpm engine:fetch");
  const standInBuild = preflight.indexOf("run: node tools/scripts/build-standin.mjs");
  const tests = [...preflight.matchAll(/run: cargo nextest run.*$/gm)];
  expect(tests).toHaveLength(2);
  expect(pinnedFetch).toBeGreaterThanOrEqual(0);
  expect(pinnedFetch).toBeLessThan(tests[0].index);
  expect(standInBuild).toBeGreaterThan(tests[0].index);
  expect(standInBuild).toBeLessThan(tests[1].index);
  expect(preflight.slice(pinnedFetch, tests[0].index)).not.toContain("SITECMD_ENGINE_UNPINNED");
  const flagScope = "unpinned flag is confined to the stand-in replay";
  expect(preflight.match(/SITECMD_ENGINE_UNPINNED/g), flagScope).toHaveLength(1);
  const replay = steps.findLast((step) => /^ {8}run: cargo nextest run/m.test(step));
  expect(replay, flagScope).toMatch(/^name: Replay workspace tests with the stand-in\n/);
  expect(workflowBlock(replay, "env", 8), flagScope).toMatch(
    /^ {10}SITECMD_ENGINE_UNPINNED: "1"$/m,
  );
}

describe("CLI release module provisioning", () => {
  it("provisions the pinned and stand-in modules before their respective CLI suites", () => {
    // Release tests can run against the wrong embedded module.
    assertReleaseEngineProvisioning(releaseWorkflow);
  });

  it.each([
    [
      "workflow env",
      "\njobs:",
      '\nenv:\n  SITECMD_ENGINE_UNPINNED: "1"\n\njobs:',
      "unscoped unpinned flag",
    ],
    [
      "preflight job env",
      "  preflight:\n",
      '  preflight:\n    env:\n      SITECMD_ENGINE_UNPINNED: "1"\n',
      "unscoped unpinned flag",
    ],
    [
      "stand-in build directory",
      "      - name: Build the stand-in engine\n",
      "      - name: Build the stand-in engine\n        working-directory: apps/desktop/src-tauri\n",
      "stand-in working directory",
    ],
  ])("rejects a release with a changed %s", (_scenario, before, after, diagnostic) => {
    // Inherited unpinned mode or a relocated stand-in build breaks the preflight contract.
    expect(releaseWorkflow).toContain(before);
    expect(() => assertReleaseEngineProvisioning(releaseWorkflow.replace(before, after))).toThrow(
      diagnostic,
    );
  });

  it("rejects an earlier preflight step exporting unpinned mode", () => {
    // A prior step can enable unpinned mode for the pinned suite through GITHUB_ENV.
    const fetch = "      - name: Fetch the pinned engine\n";
    const exportFlag = [
      "      - name: Configure engine mode",
      "        shell: bash",
      '        run: echo "SITECMD_ENGINE_UNPINNED=1" >> "$GITHUB_ENV"',
      "",
      "",
    ].join("\n");
    expect(releaseWorkflow).toContain(fetch);
    expect(() =>
      assertReleaseEngineProvisioning(releaseWorkflow.replace(fetch, exportFlag + fetch)),
    ).toThrow("unpinned flag is confined to the stand-in replay");
  });

  it("rejects the unpinned flag on the stand-in build instead of the replay", () => {
    // Finding the flag between the build and test commands does not prove it is on the replay step.
    const flag = '          SITECMD_ENGINE_UNPINNED: "1"\n';
    const replay = "      - name: Replay workspace tests with the stand-in\n";
    expect(releaseWorkflow).toContain(flag);
    expect(releaseWorkflow).toContain(replay);
    const source = releaseWorkflow
      .replace(flag, "")
      .replace(replay, `        env:\n${flag}\n${replay}`);
    expect(() => assertReleaseEngineProvisioning(source)).toThrow(
      "unpinned flag is confined to the stand-in replay",
    );
  });

  it("rejects unpinned mode on the first suite even when it is named as the replay", () => {
    // Renaming the pinned step cannot make its unpinned run the second suite.
    const flag = '          SITECMD_ENGINE_UNPINNED: "1"\n';
    const pinned = "      - name: Rust tests\n";
    const replay = "      - name: Replay workspace tests with the stand-in\n";
    const doctests = "\n      - name: Rust doctests\n";
    for (const anchor of [flag, pinned, replay, doctests])
      expect(releaseWorkflow).toContain(anchor);
    const source = releaseWorkflow
      .replace(flag, "")
      .replace(replay, pinned)
      .replace(pinned, replay)
      .replace(doctests, `        env:\n${flag}${doctests}`);
    expect(() => assertReleaseEngineProvisioning(source)).toThrow(
      "unpinned flag is confined to the stand-in replay",
    );
  });
});
