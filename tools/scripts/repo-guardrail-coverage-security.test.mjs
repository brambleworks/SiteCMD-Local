import { describe, expect, it } from "vitest";
import {
  GUARDRAIL_TEST_TIMEOUT_MS,
  expectGuardrailFailure,
  mustMutate,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const {
  codeScanSecurityFailures,
  nativeUpdateInventoryFailures,

  releaseArtifactSafetyFailures,
  repoGuardrailFailures,
} = rules;

describe.concurrent(
  "repo guardrail coverage: security and privileged boundaries",
  { timeout: GUARDRAIL_TEST_TIMEOUT_MS },
  () => {
    it("fails when dependency reads stop using the engine host byte limit", () => {
      // A dependency file could exceed the shared byte budget before reaching the parser.
      expectGuardrailFailure(
        nativeUpdateInventoryFailures,
        (fixtureRoot) => {
          const path = "apps/desktop/src-tauri/crates/engine-host/src/wants.rs";
          const source = readFixtureFile(fixtureRoot, path);
          const changed = source.replace("let bytes = read(limit)", "let bytes = read(u64::MAX)");
          expect(changed).not.toBe(source);
          writeFixtureFile(fixtureRoot, path, changed);
        },
        "Dependency manifests and lockfiles must use the engine host dependency read limit",
      );
    });

    it("fails when host project metadata bypasses the bounded reader", () => {
      // Bug: A project metadata read can follow a symlink or load unbounded text.
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const path = "apps/desktop/src-tauri/src/core/engine_facts/inventory.rs";
          const source = readFixtureFile(fixtureRoot, path);
          writeFixtureFile(
            fixtureRoot,
            path,
            mustMutate(
              source,
              "read_project_path(directory, Path::new(name), limit)",
              "std::fs::read(Path::new(name))",
            ),
          );
        },
        "Project detection must use shared bounded reads for repository-controlled metadata",
      );
    });

    it("fails when the public history helper stops creating a signed root commit", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const script = readFixtureFile(fixtureRoot, "tools/scripts/prepare-public-history.mjs");
          writeFixtureFile(
            fixtureRoot,
            "tools/scripts/prepare-public-history.mjs",
            mustMutate(
              script,
              '["commit-tree", "-S", details.tree, "-m", "Publish SiteCMD source"]',
              '["commit-tree", details.tree, "-m", "Publish SiteCMD source"]',
            ),
          );
        },
        "publication helper must default to a dry run",
      );
    });

    it("fails when the public history helper stops proving exact ref coverage", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const scriptPath = "tools/scripts/prepare-public-history.mjs";
          const script = readFixtureFile(fixtureRoot, scriptPath);
          writeFixtureFile(
            fixtureRoot,
            scriptPath,
            mustMutate(
              script,
              '["bundle", "list-heads", backup]',
              '["bundle", "heads-unchecked", backup]',
            ),
          );
        },
        "publication helper must default to a dry run",
      );
    });

    it("fails when a dispatchable workflow's job uses release-publish", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/manual-publish.yml",
            [
              "name: Manual publish",
              "on:",
              "  workflow_dispatch:",
              "jobs:",
              "  publish:",
              "    runs-on: ubuntu-22.04",
              "    permissions:",
              "      id-token: write",
              "    environment:",
              "      name: release-publish",
              "    steps:",
              "      - run: echo publish",
              "",
            ].join("\n"),
          );
        },
        ".github/workflows/manual-publish.yml#publish",
      );
    });

    it("fails when a release helper script reads the stored publish key", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            ".github/scripts/release/advance-manifest.sh",
            'curl -H "Authorization: Bearer ${RELEASE_ADMIN_KEY}" https://releases.sitecmd.com/api/releases-admin\n',
          );
        },
        "RELEASE_ADMIN_KEY must not return to the release pipeline (found in .github/scripts/release/advance-manifest.sh)",
      );
    });

    it("fails when the process-wide DNS cache loses its capacity bound", () => {
      expectGuardrailFailure(
        codeScanSecurityFailures,
        (fixtureRoot) => {
          const cache = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/src/dns_cache.rs");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/dns_cache.rs",
            cache.replace(".max_capacity(max_entries)", ".max_capacity(u64::MAX)"),
          );
        },
        "HTTP DNS resolution must re-check cached and fresh answers against the shared scan URL policy and keep a bounded TTL cache.",
      );
    });
  },
);
