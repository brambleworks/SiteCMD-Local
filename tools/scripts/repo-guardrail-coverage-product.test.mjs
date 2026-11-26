import { describe, expect, it } from "vitest";
import {
  GUARDRAIL_TEST_TIMEOUT_MS,
  expectGuardrailFailure,
  guardrailFailuresFor,
  mustMutate,
  readFixtureFile,
  readJson,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const {
  OVERLAY_DELETED,
  agentGuidanceFailures,
  emDashFailures,

  releaseWorkflowSafetyFailures,
  repoGuardrailFailures,
  rustlsCryptoProviderFailures,

  supplyChainSafetyFailures,

  versionSyncFailures,
} = rules;

describe.concurrent(
  "repo guardrail coverage: product contracts",
  { timeout: GUARDRAIL_TEST_TIMEOUT_MS },
  () => {
    it("keeps the repository guardrail suite in the root test command", () => {
      const packageJson = readJson("package.json");

      expect(packageJson.scripts.test).toContain("pnpm run guardrails:repo:test");
    });

    it("rejects disabling the pnpm minimum release age quarantine", () => {
      expectGuardrailFailure(
        supplyChainSafetyFailures,
        (fixtureRoot) => {
          const workspaceConfig = readFixtureFile(fixtureRoot, "pnpm-workspace.yaml");
          writeFixtureFile(
            fixtureRoot,
            "pnpm-workspace.yaml",
            workspaceConfig.replace("minimumReleaseAge: 1440", "minimumReleaseAge: 0"),
          );
        },
        "pnpm-workspace.yaml must keep minimumReleaseAge at 1440 minutes or higher",
      );
    });

    it("rejects a release runbook that overwrites the tag trust file", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          const runbookPath = "docs/operations/releasing.md";
          const source = readFixtureFile(fixtureRoot, runbookPath);
          writeFixtureFile(
            fixtureRoot,
            runbookPath,
            source.replace(">> .github/allowed-signers", "> .github/allowed-signers"),
          );
        },
        "docs/operations/releasing.md must append to .github/allowed-signers",
      );
    });

    it("rejects an emptied tag trust file", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          writeFixtureFile(fixtureRoot, ".github/allowed-signers", "# every key removed\n");
        },
        ".github/allowed-signers must list at least one signing key",
      );
    });

    it("rejects a SiteCMD version that is out of sync across release files", () => {
      expectGuardrailFailure(
        versionSyncFailures,
        (fixtureRoot) => {
          const lockPath = "apps/desktop/src-tauri/Cargo.lock";
          const source = readFixtureFile(fixtureRoot, lockPath);
          writeFixtureFile(
            fixtureRoot,
            lockPath,
            source.replace(/(name = "sitecmd-cli"\nversion = ")[^"]+(")/, "$1999.0.0$2"),
          );
        },
        "SiteCMD version is out of sync across release files",
      );
    });

    it.each(["cli", "runtime", "protocol", "engine-host"])(
      "rejects %s when its Rust package advertises an untested MSRV",
      (crate) => {
        // Bug: A crate omitted from the manifest inventory can advertise a different Rust floor.
        expectGuardrailFailure(
          versionSyncFailures,
          (fixtureRoot) => {
            const manifestPath = `apps/desktop/src-tauri/crates/${crate}/Cargo.toml`;
            const source = readFixtureFile(fixtureRoot, manifestPath);
            writeFixtureFile(
              fixtureRoot,
              manifestPath,
              source.replace('rust-version = "1.95.0"', 'rust-version = "1.82.0"'),
            );
          },
          `${crate}/Cargo.toml=1.82.0`,
        );
      },
    );

    it("rejects a workspace whose member list can't be read", () => {
      // Bug: an unreadable member list silently shrinks the check to the root manifest.
      expectGuardrailFailure(
        versionSyncFailures,
        (fixtureRoot) => {
          const rootManifest = "apps/desktop/src-tauri/Cargo.toml";
          writeFixtureFile(
            fixtureRoot,
            rootManifest,
            mustMutate(
              readFixtureFile(fixtureRoot, rootManifest),
              "[workspace]\nmembers = [",
              "[workspace]\nmember_list = [",
            ),
          );
        },
        "must list its [workspace] members",
      );
    });

    it("rejects a root Node engine that drifts from .nvmrc", () => {
      expectGuardrailFailure(
        versionSyncFailures,
        (fixtureRoot) => {
          const packagePath = "package.json";
          const source = readFixtureFile(fixtureRoot, packagePath);
          writeFixtureFile(
            fixtureRoot,
            packagePath,
            source.replace(/("node":\s*")[^"]+/, (_match, prefix) => `${prefix}0.0.0`),
          );
        },
        "The root Node engine must use .nvmrc as its minimum",
      );
    });

    it("rejects a workspace that only warns about the wrong Node runtime", () => {
      expectGuardrailFailure(
        versionSyncFailures,
        (fixtureRoot) => {
          const workspacePath = "pnpm-workspace.yaml";
          const source = readFixtureFile(fixtureRoot, workspacePath);
          writeFixtureFile(
            fixtureRoot,
            workspacePath,
            source.replace("engineStrict: true", "engineStrict: false"),
          );
        },
        "incompatible dependency engines fail installation",
      );
    });

    it("rejects a development runtime that only warns on mismatch", () => {
      expectGuardrailFailure(
        versionSyncFailures,
        (fixtureRoot) => {
          const manifestPath = "package.json";
          const source = readFixtureFile(fixtureRoot, manifestPath);
          writeFixtureFile(
            fixtureRoot,
            manifestPath,
            source.replace('"onFail": "error"', '"onFail": "warn"'),
          );
        },
        "devEngines.runtime must enforce the same Node range",
      );
    });

    it("fails when a manual rustls path uses the provider-less ClientConfig::builder()", () => {
      const sslPath = "apps/desktop/src-tauri/src/http_client/loopback_tls.rs";

      expectGuardrailFailure(
        rustlsCryptoProviderFailures,
        (fixtureRoot) => {
          const source = readFixtureFile(fixtureRoot, sslPath);
          const mutated = source.replace(
            "ClientConfig::builder_with_provider(provider)",
            "ClientConfig::builder()",
          );
          if (mutated === source) {
            throw new Error(
              "fixture mutation was a no-op: loopback TLS no longer selects a crypto provider",
            );
          }
          writeFixtureFile(fixtureRoot, sslPath, mutated);
        },
        "must bind a crypto provider via builder_with_provider",
      );
    });

    it("fails when a Rust backend source reintroduces an em-dash", () => {
      // Bug: A public Rust source can reintroduce an em dash.
      const emDash = String.fromCharCode(0x2014);
      expectGuardrailFailure(
        emDashFailures,
        (fixtureRoot) => {
          const rustPath = "apps/desktop/src-tauri/src/runtime.rs";
          const source = readFixtureFile(fixtureRoot, rustPath);
          writeFixtureFile(fixtureRoot, rustPath, `${source}\n// reintroduced em${emDash}dash\n`);
        },
        "uses an em-dash (U+2014)",
      );
    });

    it("requires the guide listed for the CI configuration", () => {
      expectGuardrailFailure(
        agentGuidanceFailures,
        (fixtureRoot) => fixtureRoot.set(".github/AGENTS.md", OVERLAY_DELETED),
        ".github/AGENTS.md",
      );
    });

    it("requires an exact Claude import, including in a new dot folder", () => {
      expectGuardrailFailure(
        agentGuidanceFailures,
        (fixtureRoot) => {
          writeFixtureFile(fixtureRoot, ".example/AGENTS.md", "# Example\n");
          writeFixtureFile(fixtureRoot, ".example/CLAUDE.md", "Read @AGENTS.md first.\n");
        },
        ".example/CLAUDE.md must be exactly @AGENTS.md followed by a newline",
      );
    });

    it.each(["tools/scripts", ".github", "packaging/npm"])(
      "fails when the %s guide reintroduces an em-dash",
      (dir) => {
        const file = `${dir}/AGENTS.md`;
        expectGuardrailFailure(
          emDashFailures,
          (fixtureRoot) => writeFixtureFile(fixtureRoot, file, "# Example\n\nA \u2014 B\n"),
          `${file}:3 - uses an em-dash (U+2014)`,
        );
      },
    );

    it("fails when a maintained doc reintroduces an em-dash", () => {
      // The em-dash guardrail can overlook maintained Markdown under docs/.
      const emDash = String.fromCharCode(0x2014);
      expectGuardrailFailure(
        emDashFailures,
        (fixtureRoot) => {
          const docPath = "docs/README.md";
          const source = readFixtureFile(fixtureRoot, docPath);
          writeFixtureFile(fixtureRoot, docPath, `${source}\nReintroduced em${emDash}dash.\n`);
        },
        "uses an em-dash (U+2014)",
      );
    });

    it("fails when a tooling script reintroduces an em-dash", () => {
      const emDash = String.fromCharCode(0x2014);
      expectGuardrailFailure(
        emDashFailures,
        (fixtureRoot) => {
          const scriptPath = "tools/scripts/sitecmd.mjs";
          const source = readFixtureFile(fixtureRoot, scriptPath);
          writeFixtureFile(fixtureRoot, scriptPath, `${source}\n// reintroduced em${emDash}dash\n`);
        },
        "uses an em-dash (U+2014)",
      );
    });

    it("allows an em-dash on a line marked allow-em-dash (detection needles)", () => {
      const emDash = String.fromCharCode(0x2014);
      const scriptPath = "tools/scripts/sitecmd.mjs";
      const reported = guardrailFailuresFor(repoGuardrailFailures, (fixtureRoot) => {
        const source = readFixtureFile(fixtureRoot, scriptPath);
        writeFixtureFile(
          fixtureRoot,
          scriptPath,
          `${source}\n// needle "${emDash} Score:" allow-em-dash\n`,
        );
      });
      expect(reported).not.toContain(`${scriptPath}:`);
    });
  },
);
