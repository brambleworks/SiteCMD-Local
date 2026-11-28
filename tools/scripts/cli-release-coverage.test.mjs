import { it } from "vitest";
import {
  expectGuardrailFailure,
  mustMutate,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const { releaseWorkflowSafetyFailures } = rules;

it("fails when release signing can run before quality preflight", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          "      - name: Repository guardrails\n        run: pnpm guardrails:repo",
          "      - name: Repository guardrails\n        run: echo disabled",
        ),
      );
    },
    "Release workflow must run tests, guardrails, legal-artifact checks, workspace and updater-signer dependency audits, and Rust gates before building signed CLI archives.",
  );
});

it("fails when CLI archives stop publishing their production signature", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          '            add_upload "$dir/$cli_archive.sig" "$cli_archive.sig"',
          "            # CLI signature publication disabled",
        ),
      );
    },
    "sign, verify, and publish every CLI archive signature",
  );
});

it("fails when the CLI build stops baking in the connected-service endpoint", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      const cliStepStart = workflow.indexOf("        id: cli");
      const endpoint = '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"\n';
      const endpointStart = workflow.indexOf(endpoint, cliStepStart);
      if (cliStepStart === -1 || endpointStart === -1) {
        throw new Error("CLI build endpoint was not found in release.yml");
      }
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        workflow.slice(0, endpointStart) + workflow.slice(endpointStart + endpoint.length),
      );
    },
    "the standalone CLI build step must set SITECMD_CONNECTED_ENDPOINT",
  );
});

it("fails when the tag-gate verifies signatures without re-fetching the tag object", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        workflow.replace(
          /\n.*git fetch --force origin "refs\/tags\/\$\{TAG_NAME\}:refs\/tags\/\$\{TAG_NAME\}"\n/,
          "\n",
        ),
      );
    },
    "release.yml tag-gate must re-fetch the annotated tag object from origin before git verify-tag",
  );
});
