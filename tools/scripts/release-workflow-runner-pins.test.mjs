import { expect, it } from "vitest";
import { realRead } from "./guardrail-test-support.mjs";
import { workflowSafetyFailures } from "./lib/guardrail-workflow-rules.mjs";

const MATRIX_OS = "${{ matrix.os }}";

it.each([
  [
    "release linux-x86_64 moved to ubuntu-26.04",
    "release",
    "os: ubuntu-22.04\n            target: linux-x86_64",
    "os: ubuntu-26.04\n            target: linux-x86_64",
    "release.yml job build target linux-x86_64 must run on ubuntu-22.04.",
  ],
  [
    "release linux-aarch64 moved to ubuntu-26.04-arm",
    "release",
    "os: ubuntu-22.04-arm\n            target: linux-aarch64",
    "os: ubuntu-26.04-arm\n            target: linux-aarch64",
    "release.yml job build target linux-aarch64 must run on ubuntu-22.04-arm.",
  ],
  [
    "release build ignoring its matrix runner",
    "release",
    `runs-on: ${MATRIX_OS}`,
    "runs-on: ubuntu-26.04",
    "release.yml job build target linux-x86_64 must run on ubuntu-22.04.",
  ],
  [
    "release verification moved to ubuntu-26.04",
    "release",
    "os: ubuntu-22.04\n            target: linux-x86_64\n          - os:",
    "os: ubuntu-26.04\n            target: linux-x86_64\n          - os:",
    "release.yml job verify-release target linux-x86_64 must run on ubuntu-22.04.",
  ],
  [
    "CI arm64 CLI smoke test moved to ubuntu-26.04-arm",
    "ci",
    "runs-on: ubuntu-22.04-arm",
    "runs-on: ubuntu-26.04-arm",
    "ci.yml job cli-linux-arm64 must run on ubuntu-22.04-arm.",
  ],
  [
    "cache warmer moved to ubuntu-26.04",
    "cache",
    "os: ubuntu-22.04\n            prefix:",
    "os: ubuntu-26.04\n            prefix:",
    "cache.yml job warm-engine-pin must warm ubuntu-22.04 with prefix engine-pin-ubuntu-22.04.",
  ],
  [
    "cache warmer using the wrong arm64 prefix",
    "cache",
    "prefix: engine-pin-ubuntu-22.04-arm",
    "prefix: engine-pin-ubuntu-26.04-arm",
    "cache.yml job warm-engine-pin must warm ubuntu-22.04-arm with prefix engine-pin-ubuntu-22.04-arm.",
  ],
  [
    "cache warmer ignoring the matrix prefix",
    "cache",
    "prefix-key: ${{ matrix.prefix }}",
    "prefix-key: engine-pin",
    "cache.yml job warm-engine-pin must use matrix.prefix as its cache prefix.",
  ],
])("rejects %s", (_scenario, name, before, after, diagnostic) => {
  const path = `.github/workflows/${name}.yml`;
  const source = realRead(path);
  expect(source).toContain(before);
  const read = (file) => (file === path ? source.replace(before, after) : realRead(file));
  expect(
    workflowSafetyFailures(read, () => [".github/workflows/release.yml"], { exported: true }),
  ).toContain(diagnostic);
});
