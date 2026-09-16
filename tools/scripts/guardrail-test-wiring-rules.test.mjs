import { describe, expect, it } from "vitest";
import { coveredTestPaths, testWiringFailures } from "./lib/guardrail-test-wiring-rules.mjs";

const WORKSPACE_DIRS = new Map([
  ["@sitecmd/desktop", "apps/desktop"],
  ["sitecmd-mcp", "apps/mcp-server"],
  ["example-worker", "apps/example-worker"],
]);

function repo({ scripts, workspaces = WORKSPACE_DIRS }) {
  const files = { "package.json": JSON.stringify({ scripts }) };
  for (const [name, dir] of workspaces) {
    files[`${dir}/package.json`] = JSON.stringify({ name });
  }
  return {
    read: (file) => {
      if (!(file in files)) throw new Error(`no such file: ${file}`);
      return files[file];
    },
    listDirectories: (parent) =>
      [...workspaces.values()]
        .filter((dir) => dir.startsWith(`${parent}/`))
        .map((dir) => dir.slice(parent.length + 1)),
  };
}

function failuresFor(scripts, trackedFiles) {
  const { read, listDirectories } = repo({ scripts });
  return testWiringFailures(read, {
    listTrackedFiles: () => trackedFiles,
    listDirectories,
  });
}

describe("deriving runner coverage from package.json", () => {
  it("resolves --filter names to workspace directories", () => {
    expect(
      coveredTestPaths(
        { "test:workspaces": "pnpm --filter sitecmd-mcp --filter example-worker run test" },
        WORKSPACE_DIRS,
      ).sort(),
    ).toEqual(["apps/example-worker", "apps/mcp-server"]);
  });

  it("reads the explicit paths off a root vitest sweep", () => {
    expect(
      coveredTestPaths(
        { "guardrails:repo:test": "vitest run tools/scripts tools/reporting/lib" },
        new Map(),
      ).sort(),
    ).toEqual(["tools/reporting/lib", "tools/scripts"]);
  });

  it("reads both runners out of one chained script", () => {
    expect(
      coveredTestPaths(
        {
          "guardrails:repo:test":
            "vitest run tools/scripts && node --test tools/reporting/lib/*.test.mjs",
        },
        new Map(),
      ).sort(),
    ).toEqual(["tools/reporting/lib", "tools/scripts"]);
  });

  it("stops reading paths at the first flag", () => {
    expect(
      coveredTestPaths({ test: "vitest run tools/scripts --reporter=json" }, new Map()),
    ).toEqual(["tools/scripts"]);
  });

  it("ignores a filter that is not a run test invocation", () => {
    expect(
      coveredTestPaths({ build: "pnpm --filter sitecmd-mcp run build" }, WORKSPACE_DIRS),
    ).toEqual([]);
  });
});

describe("uncollected tracked test files", () => {
  const SCRIPTS = {
    "test:desktop": "pnpm --filter @sitecmd/desktop run test",
    "guardrails:repo:test": "vitest run tools/scripts",
  };

  it("accepts a test file inside a covered runner path", () => {
    expect(
      failuresFor(SCRIPTS, ["tools/scripts/repo-guardrail-rules-unit.test.mjs", "README.md"]),
    ).toEqual([]);
  });

  it("accepts a test file inside a covered workspace", () => {
    expect(failuresFor(SCRIPTS, ["apps/desktop/src/App.render.test.tsx"])).toEqual([]);
  });

  it("flags a tracked test file that no runner collects", () => {
    const failures = failuresFor(SCRIPTS, ["tools/reporting/lib/report.test.mjs"]);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain("tools/reporting/lib/report.test.mjs");
    expect(failures[0]).toContain("no package.json test script collects");
  });

  it("clears once the sweep is widened to include it", () => {
    expect(
      failuresFor(
        { ...SCRIPTS, "guardrails:repo:test": "vitest run tools/scripts tools/reporting/lib" },
        ["tools/reporting/lib/report.test.mjs"],
      ),
    ).toEqual([]);
  });

  it("recognises every test-file extension the repo uses", () => {
    const failures = failuresFor(SCRIPTS, [
      "orphan/a.test.mjs",
      "orphan/b.test.ts",
      "orphan/c.test.tsx",
      "orphan/d.spec.ts",
      "orphan/e.test.js",
    ]);
    expect(failures).toHaveLength(5);
  });

  it("does not treat a non-test source file as a test", () => {
    expect(failuresFor(SCRIPTS, ["tools/reporting/lib/report.mjs"])).toEqual([]);
  });

  it("skips quietly outside a git checkout", () => {
    const { read, listDirectories } = repo({ scripts: SCRIPTS });
    expect(testWiringFailures(read, { listTrackedFiles: () => null, listDirectories })).toEqual([]);
  });

  it("refuses to pass silently when no runner paths can be derived", () => {
    const failures = failuresFor({ build: "tsc -b" }, ["tools/scripts/a.test.mjs"]);
    expect(failures[0]).toContain("no test runner paths could be derived");
  });
});

describe("the live repository", () => {
  it("has every tracked test file wired into a runner", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const url = await import("node:url");
    const root = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "../..");
    const failures = testWiringFailures((file) => fs.readFileSync(path.join(root, file), "utf8"), {
      root,
    });
    expect(failures).toEqual([]);
  });
});
