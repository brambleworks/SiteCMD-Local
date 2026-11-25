import { expect, it } from "vitest";
import { repoGuardrailIo } from "./check-repo-guardrails.mjs";
import { workflowPinFailures } from "./lib/guardrail-workflow-pins.mjs";

const WORKFLOW = ".github/workflows/ci.yml";
const NODE = "26.13.1";
const DIGEST = `sha256:${"a".repeat(64)}`;
const IMAGE = `postgres:18.7-trixie@${DIGEST}`;
const MATRIX_OS = "${{ matrix.os }}";

function run(job, version = NODE) {
  const body = job
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n");
  return workflowPinFailures(
    (file) => (file === ".nvmrc" ? version : `jobs:\n  sample:\n${body}\n`),
    () => [WORKFLOW],
  );
}

it.each(["26", "26.13", "v26.13.1", "lts/*", "26.13.1-rc.1"])(
  "requires a complete Node version instead of %s",
  (version) => {
    expect(run("runs-on: ubuntu-26.04", version)).toContain(".nvmrc must pin X.Y.Z.");
  },
);

it.each([
  ["a scalar runner", "runs-on: ubuntu-latest"],
  ["an array label", "runs-on: [self-hosted, windows-latest-8-cores]"],
  ["a runner label object", "runs-on:\n  group: default\n  labels:\n    - macos-latest"],
  [
    "a matrix axis",
    `runs-on: ${MATRIX_OS}\nstrategy:\n  matrix:\n    os: [ubuntu-26.04, ubuntu-latest]`,
  ],
  [
    "a matrix include row in a runner label object",
    [
      "runs-on:",
      "  group: default",
      "  labels: ${{ matrix['os'] }}",
      "strategy:",
      "  matrix:",
      "    include:",
      "      - os: macos-latest",
    ].join("\n"),
  ],
])("refuses a floating runner from %s", (_label, job) => {
  expect(run(job)).toContain(`${WORKFLOW} job sample: no -latest runner labels.`);
});

it.each([
  ["an older macOS scalar", "runs-on: macos-15", "macos-26"],
  ["an Xcode runner alias", "runs-on: xcode-27", "macos-26"],
  [
    "a macOS runner with a different architecture",
    "runs-on:\n  group: default\n  labels: [macos-26-intel]",
    "macos-26",
  ],
  [
    "an older macOS matrix label",
    `runs-on: ["${MATRIX_OS}"]\nstrategy:\n  matrix:\n    os: [macos-26, macos-15]`,
    "macos-26",
  ],
  ["an older Windows runner", "runs-on: windows-2022", "windows-2025-vs2026"],
])("requires the pinned runner image instead of %s", (_label, job, image) => {
  expect(run(job)).toContain(`${WORKFLOW} job sample must run on ${image}.`);
});

it.each(["ubuntu-22.04", "ubuntu-22.04-arm", "ubuntu-24.04", "ubuntu-26.04"])(
  "accepts the exact Ubuntu label %s",
  (runner) => {
    expect(run(`runs-on: ${runner}`)).toEqual([]);
  },
);

it("rejects an unversioned Ubuntu runner label", () => {
  expect(run("runs-on: ubuntu-slim")).toContain(
    `${WORKFLOW} job sample must use a versioned Ubuntu runner label.`,
  );
});

it("requires runner expressions to resolve through a literal matrix", () => {
  expect(run("runs-on: ${{ inputs.runner }}")).toContain(
    `${WORKFLOW} job sample must use literal runner labels or a literal runner matrix.`,
  );
});

it.each([
  ["only a tag", "postgres:18.7"],
  ["only a digest", `postgres@${DIGEST}`],
  ["a digest with a registry port and no tag", `localhost:5000/postgres@${DIGEST}`],
  ["a malformed digest", "postgres:18.7@sha256:abc"],
])("refuses %s for service and job container images", (_label, image) => {
  expect(run(`services:\n  postgres:\n    image: ${image}\ncontainer: ${image}`)).toEqual([
    `${WORKFLOW} job sample service postgres must pin an image tag and sha256 digest.`,
    `${WORKFLOW} job sample container must pin an image tag and sha256 digest.`,
  ]);
  expect(run(`container:\n  image: ${image}`)).toEqual([
    `${WORKFLOW} job sample container must pin an image tag and sha256 digest.`,
  ]);
});

it("accepts exact runner, Node, service and container pins", () => {
  const job = [
    `runs-on: ${MATRIX_OS}`,
    "strategy:",
    "  matrix:",
    "    os: [ubuntu-26.04, macos-26]",
    "    cache: [cache-latest]",
    "    include:",
    "      - os: ubuntu-26.04-arm",
    "      - os: windows-2025-vs2026",
    "container:",
    `  image: localhost:5000/${IMAGE}`,
    "services:",
    "  postgres:",
    `    image: ${IMAGE}`,
  ].join("\n");
  expect(run(job, `${NODE}\n`)).toEqual([]);
});

it("accepts the repository's workflow and Node pins", () => {
  const { read, listFiles } = repoGuardrailIo(process.cwd());
  expect(workflowPinFailures(read, listFiles)).toEqual([]);
});
