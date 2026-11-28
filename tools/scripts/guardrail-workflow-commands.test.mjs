import { expect, it } from "vitest";
import { realRead, rules } from "./guardrail-test-support.mjs";
import {
  readJobs,
  runCommand,
  scalar,
  workflowFields,
  workflowJobSteps,
} from "./lib/guardrail-workflow-yaml.mjs";

const fixture = ".github/workflows/example.yml";
const workflow = (...steps) =>
  [
    "jobs:",
    "  check:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    ...steps.map((step) => `      - ${step}`),
  ].join("\n");

function failures(source) {
  return rules
    .workflowSafetyFailures(
      (file) => (file === fixture ? source : realRead(file)),
      () => [fixture, ".github/workflows/ci.yml"],
      { exported: true },
    )
    .join("\n");
}

it.each([
  ["no install", workflow("run: pnpm engine:fetch")],
  ["corepack wrapper", workflow("run: corepack pnpm engine:fetch")],
  ["quoted command", workflow('run: "pnpm engine:fetch"')],
  [
    "shell-conditional install",
    workflow(
      "run: |\n          if false; then\n            pnpm install\n          fi",
      "run: pnpm test",
    ),
  ],
  ["late install", workflow("run: pnpm run engine:fetch", "run: pnpm install")],
  [
    "conditional install",
    workflow("if: matrix.install\n        run: pnpm install", "run: pnpm test"),
  ],
  [
    "another job's install",
    `${workflow("run: pnpm install")}\n  build:\n    steps:\n      - run: pnpm test`,
  ],
])("rejects a pnpm script with %s", (_scenario, source) => {
  // A pnpm script can install dependencies and run lifecycle hooks before its command.
  expect(failures(source)).toContain("requires an earlier unconditional pnpm install");
});

it("accepts a pnpm script after an install in the same job", () => {
  // A completed install in the same job can be missed.
  expect(failures(workflow("run: pnpm install --frozen-lockfile", "run: pnpm test"))).not.toContain(
    "requires an earlier unconditional pnpm install",
  );
});

it.each([
  ["exec", "run: pnpm exec lefthook install"],
  ["restart", "run: pnpm restart"],
  ["quoted executable", "run: 'time \"pnpm\" exec lefthook install'"],
  ["shell wrapper", 'run: bash -c "pnpm run engine:fetch"'],
  ["reported install", "run: echo pnpm install"],
  ["piped install", "run: pnpm install | tee install.log"],
])("rejects pnpm %s without an unconditional install", (scenario, step) => {
  // pnpm can install dependencies implicitly when no direct install has completed.
  const steps = scenario.endsWith("install") ? [step, "run: pnpm test"] : [step];
  expect(failures(workflow(...steps))).toContain("requires an earlier unconditional pnpm install");
});

it.each([
  ["the repository root", "run: cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml"],
  ["another directory", "working-directory: scripts\n        run: |\n          cargo build"],
  ["a quoted command at the root", 'run: "cargo check"'],
])("rejects Cargo invoked from %s", (_scenario, step) => {
  // Cargo outside the workspace selects a different rustup toolchain.
  expect(failures(workflow(step))).toContain("must run Cargo from apps/desktop/src-tauri");
});

it.each([
  "if true; then cargo build; fi",
  "for target in host; do cargo build; done",
  'bash -c "cargo build"',
  "time cargo build",
  "env -u FOO cargo build",
  "echo x | cargo build",
  "echo $(cargo metadata)",
  'time "cargo" build',
])("rejects Cargo hidden in %s", (command) => {
  // Cargo after a wrapper or shell operator can bypass the toolchain check.
  expect(failures(workflow(`run: ${command}`))).toContain(
    "must run Cargo from apps/desktop/src-tauri",
  );
});

it("checks jobs declared with an inline comment", () => {
  // An inline comment on jobs can suppress all command checks.
  const source = workflow("run: cargo build", "run: pnpm test").replace(
    "jobs:",
    "jobs: # Command checks still apply",
  );
  expect(failures(source)).toContain("must run Cargo from apps/desktop/src-tauri");
  expect(failures(source)).toContain("requires an earlier unconditional pnpm install");
});

it.each(["cargo +stable build", "cargo +beta build", "cargo +nightly build"])(
  "refuses Cargo on a floating channel in %s",
  (command) => {
    // A floating channel named on the command line was accepted as a pinned toolchain.
    expect(failures(workflow(`run: ${command}`))).toContain(
      "must run Cargo from apps/desktop/src-tauri",
    );
  },
);

it.each([
  "cargo +1.97.0 build --locked",
  'bash -c "cargo +nightly-2026-09-01 build"',
  "cd apps/desktop/src-tauri && cargo build",
])("accepts Cargo with a selected toolchain in %s", (command) => {
  // Cargo can select its toolchain explicitly or from a guarded change of directory.
  expect(failures(workflow(`run: ${command}`))).not.toContain(
    "must run Cargo from apps/desktop/src-tauri",
  );
});

it("rejects unpinned Cargo after a guarded change of directory fails", () => {
  // A fallback command can still run at the root when changing directories fails.
  expect(
    failures(workflow("run: cd apps/desktop/src-tauri && cargo check || cargo build")),
  ).toContain("must run Cargo from apps/desktop/src-tauri");
});

it("accepts the workspace directory inherited from workflow defaults", () => {
  // A Cargo step can inherit the correct directory without setting it on the step.
  const defaults = "defaults:\n  run:\n    working-directory: apps/desktop/src-tauri\n";
  expect(failures(defaults + workflow("run: cargo build"))).not.toContain(
    "must run Cargo from apps/desktop/src-tauri",
  );
});

it.each(["before", "after"])("applies job working-directory defaults %s steps", (position) => {
  // Job defaults after steps can be lost or applied only to the last step.
  const defaults = "    defaults:\n      run:\n        working-directory: apps/desktop/src-tauri\n";
  const source = workflow("run: cargo build", "run: cargo check");
  const withDefaults =
    position === "before"
      ? source.replace("    steps:", `${defaults}    steps:`)
      : `${source}\n${defaults}`;
  expect(failures(withDefaults)).not.toContain("must run Cargo from apps/desktop/src-tauri");
});

it("applies a job directory override after steps to every step", () => {
  // Job defaults misattributed to the last step can let earlier Cargo commands pass.
  const workflowDefaults = "defaults:\n  run:\n    working-directory: apps/desktop/src-tauri\n";
  const jobDefaults = "    defaults:\n      run:\n        working-directory: .github\n";
  const source = `${workflowDefaults}${workflow("run: cargo build", "run: echo done")}\n${jobDefaults}`;
  expect(failures(source)).toContain("must run Cargo from apps/desktop/src-tauri");
});

it("keeps a step directory override ahead of job defaults", () => {
  // Job defaults cannot authorize Cargo in a step that overrides its directory.
  const defaults = "    defaults:\n      run:\n        working-directory: apps/desktop/src-tauri\n";
  const source = workflow("run: cargo build\n        working-directory: scripts");
  expect(failures(`${source}\n${defaults}`)).toContain(
    "must run Cargo from apps/desktop/src-tauri",
  );
});

it("release.yml fetches the pinned engine without credentials", () => {
  const source = realRead(".github/workflows/release.yml");
  const steps = workflowJobSteps(readJobs(workflowFields(source)));
  const fetchSteps = [...steps.values()]
    .flat()
    .filter((step) => scalar(step.get("name")) === "Fetch the pinned engine");
  expect(fetchSteps).toHaveLength(2);
  for (const step of fetchSteps) {
    expect(runCommand(step)).toBe("pnpm engine:fetch");
    expect(step.has("env")).toBe(false);
    expect(step.has("if")).toBe(false);
  }
});

it("builds the standalone release verifier in its sparse checkout", () => {
  // The standalone verifier should not need workspace files or a floating toolchain.
  const verifier = realRead(".github/workflows/release.yml")
    .split(/^ {2}verify-release:$/m)[1]
    .split(/^ {2}[\w-]+:/m, 1)[0];
  expect(verifier).toContain("working-directory: .github/updater-verifier");
  expect(verifier).toMatch(
    /^ {10}rustup toolchain install ([\d.]+) --profile minimal\n {10}cargo \+\1 build --release --locked$/m,
  );
  // A bump of the workspace pin left the verifier on the old toolchain.
  const [, verifierToolchain] = /rustup toolchain install ([\d.]+)/.exec(verifier);
  const [, workspaceToolchain] = /^channel = "([^"]+)"$/m.exec(
    realRead("apps/desktop/src-tauri/rust-toolchain.toml"),
  );
  expect(verifierToolchain).toBe(workspaceToolchain);
  expect(verifier).not.toContain("apps/desktop/src-tauri/rust-toolchain.toml");
  expect(verifier).not.toContain("uses: dtolnay/rust-toolchain@");
});

it("release.yml provisions minisign before the engine bump tests", () => {
  // CI skips the signature tests when minisign is absent.
  const source = realRead(".github/workflows/release.yml");
  const install = source.indexOf("run: bash .github/scripts/install-minisign.sh");
  expect(install).toBeGreaterThanOrEqual(0);
  expect(install).toBeLessThan(source.indexOf("run: pnpm test"));
  const script = realRead(".github/scripts/install-minisign.sh");
  expect(script).toContain("releases/download/0.12/minisign-0.12-linux.tar.gz");
  expect(script).toContain("9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73");
  expect(script.indexOf("sha256sum -c -")).toBeGreaterThanOrEqual(0);
  expect(script.indexOf("sha256sum -c -")).toBeLessThan(script.indexOf("tar -xzf"));
});

it("ignores interrupted engine download directories", () => {
  // Interrupted downloads can leave untracked staging files beside the downloaded module.
  expect(realRead(".gitignore")).toMatch(/^\/engine\/\.download-\*$/m);
});
