import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, it, vi } from "vitest";
import { resolveConfig } from "vitest/node";
import { testWorkerFailures } from "./lib/guardrail-test-workers-rules.mjs";

const configUrl = new URL("../../vitest.config.mjs", import.meta.url);
const workerImport = 'import { workerCount } from "./tools/scripts/lib/test-workers.mjs";';

it("accepts the worker helper in the root config shared by both suites", () => {
  expect(testWorkerFailures(() => readFileSync(configUrl, "utf8"))).toEqual([]);
});

it.each([
  `${workerImport}\nexport default { test: { maxWorkers: 2 } }; // maxWorkers: workerCount()`,
  'import { workerCount } from "./other.mjs";\n' +
    "export default { test: { maxWorkers: workerCount() } };",
  `// ${workerImport}\nexport default { test: { maxWorkers: workerCount() } };`,
  `${workerImport}\nexport default { test: { maxWorkers: workerCount(), "maxWorkers": 2 } };`,
  `${workerImport}\nexport default { test: { maxWorkers: workerCount() }, test: {} };`,
  `${workerImport}\nexport default defineConfig({ test: { maxWorkers: workerCount(), ...options } });`,
])("rejects a config that bypasses the worker helper (%s)", (source) => {
  expect(testWorkerFailures(() => source)).toEqual([
    "vitest.config.mjs: set maxWorkers from workerCount() in tools/scripts/lib/test-workers.mjs.",
  ]);
});

it("checks the last top-level worker setting in the exported test object", () => {
  const source = `${workerImport}
    export default defineConfig({
      test: {
        maxWorkers: 1,
        maxWorkers: workerCount(),
        anotherOption: { maxWorkers: 1, text: "},", values: [1, 2] },
      },
    });`;
  expect(testWorkerFailures(() => source)).toEqual([]);
});

it("normalizes an invalid VITEST_MAX_WORKERS before Vitest resolves its worker count", async () => {
  vi.stubEnv("CI", "1");
  vi.stubEnv("VITEST_MAX_WORKERS", "9invalid");
  try {
    const { vitestConfig } = await resolveConfig({ config: fileURLToPath(configUrl) });
    expect(vitestConfig.maxWorkers).toBe(2);
    expect(process.env.VITEST_MAX_WORKERS).toBe("2");
  } finally {
    vi.unstubAllEnvs();
  }
});
