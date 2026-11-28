import { describe, expect, it } from "vitest";
import {
  GUARDRAIL_TEST_TIMEOUT_MS,
  expectGuardrailFailure,
  guardrailFailuresFor,
  mustMutate,
  readFixtureFile,
  realRead,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const {
  codeScanSecurityFailures,
  ciCostSafetyFailures,
  cliSurfaceFailures,

  documentationSafetyFailures,

  guardrailScriptLineBudgets,
  publicationRecordFailures,
  releaseArtifactSafetyFailures,
  repoGuardrailFailures,
  rustLineBudgetFailures,
  rustRatchetFailures,
  rustUnwrapBudgetFailures,
} = rules;

describe.concurrent(
  "repo guardrail coverage: quality and release preparation",
  { timeout: GUARDRAIL_TEST_TIMEOUT_MS },
  () => {
    it.each(["crates/protocol/src/vocab.rs"])(
      "fails when the issue payload in %s loses its confidence default",
      (relative) => {
        // Removing the confidence default breaks loading findings that predate the field.
        expectGuardrailFailure(
          repoGuardrailFailures,
          (fixtureRoot) => {
            const path = `apps/desktop/src-tauri/${relative}`;
            const source = readFixtureFile(fixtureRoot, path);
            const changed = source.replace(
              "#[serde(default)]\n    pub confidence: IssueConfidence",
              "pub confidence: IssueConfidence",
            );
            expect(changed).not.toBe(source);
            writeFixtureFile(fixtureRoot, path, changed);
          },
          "Rust web/code issue payloads must carry confidence fields",
        );
      },
    );

    it.each(["pub enum Category", "pub const fn label", "the_list_is_the_ten_categories_in_order"])(
      "fails when the protocol loses its canonical category contract %s",
      (pin) => {
        expectGuardrailFailure(
          repoGuardrailFailures,
          (fixtureRoot) => {
            const file = "apps/desktop/src-tauri/crates/protocol/src/vocab.rs";
            const source = readFixtureFile(fixtureRoot, file);
            writeFixtureFile(fixtureRoot, file, mustMutate(source, pin, "removed"));
          },
          "must keep the canonical Category helper surface",
        );
      },
    );

    it("fails when a workflow reintroduces a daily-or-more-frequent cron", () => {
      expectGuardrailFailure(
        ciCostSafetyFailures,
        (fixtureRoot) => {
          const auditPath = ".github/workflows/weekly-advisories.yml";
          const source = readFixtureFile(fixtureRoot, auditPath);
          writeFixtureFile(
            fixtureRoot,
            auditPath,
            source.replace('cron: "0 12 * * 1"', 'cron: "0 12 * * *"'),
          );
        },
        "Scheduled workflows must run no more than weekly",
      );
    });

    it("fails when dependency CI stops auditing the updater signer", () => {
      expectGuardrailFailure(
        ciCostSafetyFailures,
        (fixtureRoot) => {
          const auditPath = ".github/workflows/ci.yml";
          const source = readFixtureFile(fixtureRoot, auditPath);
          writeFixtureFile(
            fixtureRoot,
            auditPath,
            mustMutate(source, "run: pnpm run audit:deps:signer", "run: echo skipped"),
          );
        },
        "must audit the standalone updater signer when dependencies change",
      );
    });

    it("fails when verify-push.mjs drops a Rust check that no longer runs on push", () => {
      expectGuardrailFailure(
        ciCostSafetyFailures,
        (fixtureRoot) => {
          const verifyPath = "tools/scripts/verify-push.mjs";
          const source = readFixtureFile(fixtureRoot, verifyPath);
          writeFixtureFile(
            fixtureRoot,
            verifyPath,
            source.replace("cargo test --doc", "cargo test --DISABLED"),
          );
        },
        "verify-push.mjs must keep running `cargo test --doc`",
      );
    });

    it("fails when verify-push.mjs drops the headless CLI package build", () => {
      expectGuardrailFailure(
        ciCostSafetyFailures,
        (fixtureRoot) => {
          const verifyPath = "tools/scripts/verify-push.mjs";
          const source = readFixtureFile(fixtureRoot, verifyPath);
          const mutated = source
            .split("\n")
            .filter((line) => !line.includes("cargo build --manifest-path crates/cli/Cargo.toml"))
            .join("\n");
          if (mutated === source) {
            throw new Error(
              "fixture mutation was a no-op: verify-push.mjs no longer contains the headless CLI build line",
            );
          }
          writeFixtureFile(fixtureRoot, verifyPath, mutated);
        },
        "verify-push.mjs must keep running `cargo build --manifest-path crates/cli/Cargo.toml`",
      );
    });

    it("fails when a Rust binary is added to the app's src/bin (it would ship in the signed bundle)", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/bin/leaky_tool.rs",
            "fn main() {}\n",
          );
        },
        "apps/desktop/src-tauri/src/bin must contain no Rust binaries",
      );
    });

    it("fails when a production Rust module adds a bare unwrap", () => {
      expectGuardrailFailure(
        rustUnwrapBudgetFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/core/guardrail_fixture.rs",
            "fn guardrail_fixture_bare_unwrap(input: Option<&str>) -> &str { input.unwrap() }\n",
          );
        },
        "apps/desktop/src-tauri/src/core/guardrail_fixture.rs: 1 bare `.unwrap()`",
      );
    });

    it("fails when a production Rust module adds a bare expect", () => {
      expectGuardrailFailure(
        rustRatchetFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/core/guardrail_fixture.rs",
            'fn guardrail_fixture_bare_expect(input: Option<&str>) -> &str { input.expect("must exist") }\n',
          );
        },
        "apps/desktop/src-tauri/src/core/guardrail_fixture.rs: 1 bare `.expect()`",
      );
    });

    it("fails when a new file adds an inline Duration::from_* outside constants.rs", () => {
      expectGuardrailFailure(
        rustRatchetFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/core/guardrail_fixture.rs",
            "fn guardrail_fixture_inline_duration() -> std::time::Duration { std::time::Duration::from_secs(7) }\n",
          );
        },
        "apps/desktop/src-tauri/src/core/guardrail_fixture.rs: 1 inline `Duration::from_*` outside constants.rs",
      );
    });

    it("allows Duration literals in #[path]-mounted *_tests.rs sibling test files", () => {
      const reported = guardrailFailuresFor(repoGuardrailFailures, (fixtureRoot) => {
        writeFixtureFile(
          fixtureRoot,
          "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture_tests.rs",
          "fn guardrail_fixture_test_duration() -> std::time::Duration { std::time::Duration::from_secs(7) }\n",
        );
      });
      expect(reported).not.toContain("guardrail_fixture_tests.rs");
    });

    it("fails when a Rust production module grows past the 800-line ceiling", () => {
      expectGuardrailFailure(
        rustLineBudgetFailures,
        (fixtureRoot) => {
          const fixturePath = "apps/desktop/src-tauri/src/core/guardrail_fixture.rs";
          const filler = "// guardrail-fixture-pad\n".repeat(900);
          writeFixtureFile(fixtureRoot, fixturePath, filler);
        },
        "apps/desktop/src-tauri/src/core/guardrail_fixture.rs has",
      );
    });

    it("fails when Code Scan outputs add source excerpts", () => {
      // Bug: A public Code Scan output can carry excerpts of customer code.
      expectGuardrailFailure(
        codeScanSecurityFailures,
        (fixtureRoot) => {
          const excerptPath = "apps/desktop/src-tauri/crates/protocol/src/code_scan.rs";
          const source = readFixtureFile(fixtureRoot, excerptPath);
          writeFixtureFile(
            fixtureRoot,
            excerptPath,
            source + "\npub source_excerpt: Option<String>,\n",
          );
        },
        "Code Scan outputs must omit source excerpts and code lines",
      );
    });

    it("applies a default line budget to newly extracted guardrail modules", () => {
      // Bug: New public modules can escape the default line budget.
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const modulePath = "tools/scripts/lib/guardrail-new-fixture-rules.mjs";
          writeFixtureFile(
            fixtureRoot,
            modulePath,
            `// A guardrail module.\n${"// module line\n".repeat(399)}`,
          );
        },
        "tools/scripts/lib/guardrail-new-fixture-rules.mjs has 401 lines (budget 400)",
      );
    });

    it("fails when the main guardrail runner grows past its line budget", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const guardrail = readFixtureFile(fixtureRoot, "tools/scripts/check-repo-guardrails.mjs");
          const maxLines = guardrailScriptLineBudgets.get(
            "tools/scripts/check-repo-guardrails.mjs",
          );
          if (maxLines === undefined) throw new Error("main guardrail runner has no line budget");
          const addedLines = maxLines - guardrail.split("\n").length + 1;
          writeFixtureFile(
            fixtureRoot,
            "tools/scripts/check-repo-guardrails.mjs",
            `${guardrail}\n${Array.from({ length: addedLines }, (_, index) => `// budget regression ${index}`).join("\n")}\n`,
          );
        },
        "Repo guardrail scripts must stay within maintainability line budgets",
      );
    });

    it("fails when agent guidance reintroduces stale Code Scan architecture", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const guidance = readFixtureFile(fixtureRoot, "CLAUDE.md");
          writeFixtureFile(
            fixtureRoot,
            "CLAUDE.md",
            `${guidance}\nLegacy note: Code Scan lives in core/guardrails.rs and returns AppGuardrailsReport.\n`,
          );
        },
        "Repo guidance must not describe stale Code Scan or Tauri capability architecture",
      );
    });

    it("fails when canonical AGENTS guidance reintroduces stale Code Scan architecture", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const guidance = readFixtureFile(fixtureRoot, "AGENTS.md");
          writeFixtureFile(
            fixtureRoot,
            "AGENTS.md",
            `${guidance}\nLegacy note: Code Scan lives in core/guardrails.rs and returns AppGuardrailsReport.\n`,
          );
        },
        "Repo guidance must not describe stale Code Scan or Tauri capability architecture",
      );
    });

    it("fails when backend guidance claims debug credentials fall back to SQLite", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const guidance = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/CLAUDE.md");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/CLAUDE.md",
            `${guidance}\nDebug credentials fall back to SQLite.\n`,
          );
        },
        "Repo guidance must not describe stale Code Scan or Tauri capability architecture",
      );
    });

    it("fails when docs add local absolute Markdown links", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const doc = readFixtureFile(fixtureRoot, "docs/README.md");
          writeFixtureFile(
            fixtureRoot,
            "docs/README.md",
            `${doc}\n[local-only](/Users/dev/Projects/Web/SiteCMD/docs/README.md)\n`,
          );
        },
        "Documentation must not use machine-specific absolute Markdown links",
      );
    });

    it("fails when repository maintenance scripts drop ESLint coverage", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const eslintConfig = readFixtureFile(fixtureRoot, "eslint.config.js");
          writeFixtureFile(
            fixtureRoot,
            "eslint.config.js",
            eslintConfig.replace('"tools/scripts/**/*.mjs"', '"tools/scripts/**/*.off"'),
          );
        },
        "Repository maintenance scripts must be covered by root ESLint",
      );
    });

    it("fails when a CLI example passes the removed scan type option", () => {
      // Docs or examples still pass --type to sitecmd scan.
      for (const example of [
        "sitecmd scan --type",
        "sitecmd scan --type security",
        "sitecmd scan --json --type=security",
        "sitecmd scan \\\n  --type security",
        "sitecmd scan \\\r\n  --type security",
        'sitecmd scan \\\n  --url "$SITECMD_SCAN_URL" \\\n  --type security',
      ]) {
        expectGuardrailFailure(
          cliSurfaceFailures,
          (fixtureRoot) => {
            const cli = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/src/cli/connected.rs");
            writeFixtureFile(
              fixtureRoot,
              "apps/desktop/src-tauri/src/cli/connected.rs",
              mustMutate(
                cli,
                "the connection export carries an invalid fingerprint key version",
                example,
              ),
            );
          },
          "scan argument parser rejects",
        );
      }
    });

    it("fails when the public installer stops using the updater trust root", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const installerPath = "install.sh";
          const installer = readFixtureFile(fixtureRoot, installerPath);
          writeFixtureFile(
            fixtureRoot,
            installerPath,
            mustMutate(
              installer,
              "RWTtzNh0gmMU/8O1AJBbQbUEy9oD5lpqL/dV0qRqlpsCldfWNWgxr5kE",
              "RWQ000000000000000000000000000000000000000000000000000000000",
            ),
          );
        },
        "public, reviewable installer bound to the updater trust root",
      );
    });

    it("fails when the README publishes a different updater key than the installer", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const readme = readFixtureFile(fixtureRoot, "README.md");
          writeFixtureFile(
            fixtureRoot,
            "README.md",
            mustMutate(
              readme,
              "\nRWTtzNh0gmMU/8O1AJBbQbUEy9oD5lpqL/dV0qRqlpsCldfWNWgxr5kE\n",
              "\nRWQ000000000000000000000000000000000000000000000000000000\n",
            ),
          );
        },
        "must print the updater public key exactly as",
      );
    });

    it("fails when the README's minisign -P argument diverges from the installer key", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const readme = readFixtureFile(fixtureRoot, "README.md");
          writeFixtureFile(
            fixtureRoot,
            "README.md",
            mustMutate(
              readme,
              "-P RWTtzNh0gmMU/8O1AJBbQbUEy9oD5lpqL/dV0qRqlpsCldfWNWgxr5kE",
              "-P RWQ000000000000000000000000000000000000000000000000000",
            ),
          );
        },
        "must print the updater public key exactly as",
      );
    });

    it("fails when the installer gate drops syntax or behavior verification", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const packagePath = "package.json";
          const workspacePackage = JSON.parse(readFixtureFile(fixtureRoot, packagePath));
          workspacePackage.scripts["installer:check"] = "sh -n install.sh";
          writeFixtureFile(fixtureRoot, packagePath, JSON.stringify(workspacePackage, null, 2));
        },
        "installer gate must parse both scripts and run the behavior suite",
      );
    });

    it("fails when the headless CLI regains a desktop package dependency", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const manifestPath = "apps/desktop/src-tauri/crates/cli/Cargo.toml";
          const manifest = readFixtureFile(fixtureRoot, manifestPath);
          writeFixtureFile(
            fixtureRoot,
            manifestPath,
            mustMutate(
              manifest,
              'sitecmd-runtime = { path = "../runtime" }',
              'app_lib = { package = "sitecmd", path = "../.." }',
            ),
          );
        },
        "must remain a Tauri-free workspace package that depends on the shared sitecmd-runtime",
      );
    });

    it("fails when a live surface revives the retired paid Code Scan contract", () => {
      expectGuardrailFailure(
        publicationRecordFailures,
        (fixtureRoot) => {
          const readme = readFixtureFile(fixtureRoot, "README.md");
          writeFixtureFile(
            fixtureRoot,
            "README.md",
            `${readme}\nCode Scan requires Core or Pro.\n`,
          );
        },
        "repeats the retired client-side paid-feature contract",
      );
    });

    it("fails when a live surface revives local detail gating", () => {
      expectGuardrailFailure(
        publicationRecordFailures,
        (fixtureRoot) => {
          const readme = readFixtureFile(fixtureRoot, "README.md");
          writeFixtureFile(
            fixtureRoot,
            "README.md",
            `${readme}\nIndividual issue guidance is locked on this tier.\n`,
          );
        },
        "repeats the retired client-side paid-feature contract",
      );
    });

    it("fails when the release helper creates an unsigned annotated tag", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const script = readFixtureFile(fixtureRoot, "tools/scripts/tag-release.mjs");
          writeFixtureFile(
            fixtureRoot,
            "tools/scripts/tag-release.mjs",
            mustMutate(
              script,
              '["tag", "-s", "--cleanup=verbatim"',
              '["tag", "--cleanup=verbatim"',
            ),
          );
        },
        "tools/scripts/tag-release.mjs must create a signed annotated tag",
      );
    });

    it("fails when the release tag lets Git strip Markdown headings", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const script = readFixtureFile(fixtureRoot, "tools/scripts/tag-release.mjs");
          writeFixtureFile(
            fixtureRoot,
            "tools/scripts/tag-release.mjs",
            mustMutate(script, '"--cleanup=verbatim",', ""),
          );
        },
        "signed annotated tag with verbatim changelog notes",
      );
    });

    it("fails when release preparation stops writing the frozen changelog", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const script = readFixtureFile(fixtureRoot, "tools/scripts/release.mjs");
          writeFixtureFile(
            fixtureRoot,
            "tools/scripts/release.mjs",
            mustMutate(
              script,
              "fs.writeFileSync(path.join(ROOT, CHANGELOG_FILE), changelogRelease.source);",
              "console.log(changelogRelease.source.length);",
            ),
          );
        },
        "tools/scripts/release.mjs must prepare version and changelog changes only",
      );
    });

    it("fails when release preparation regains a main-branch override", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const script = readFixtureFile(fixtureRoot, "tools/scripts/release.mjs");
          writeFixtureFile(
            fixtureRoot,
            "tools/scripts/release.mjs",
            mustMutate(
              script,
              'branch === "main" || !branch.startsWith("release/")',
              '!branch.startsWith("release/") && !flags.has("--allow-branch")',
            ),
          );
        },
        "must never commit, tag, or permit a main-branch override",
      );
    });
  },
);

it("rejects a CI group shared by forks in the exported repository", () => {
  expectGuardrailFailure(
    ciCostSafetyFailures,
    (overlay) => {
      const file = ".github/workflows/ci.yml";
      overlay.set(
        file,
        mustMutate(realRead(file), "github.event.pull_request.number", "github.head_ref"),
      );
    },
    "ci.yml must isolate concurrency by event and pull request number or run ID.",
  );
});

it("rejects a traversal budget whose counter never increments", () => {
  expectGuardrailFailure(
    codeScanSecurityFailures,
    (overlay) => {
      const file = "apps/desktop/src-tauri/src/core/project_listing.rs";
      overlay.set(file, mustMutate(realRead(file), "self.visited_entries += 1;", ""));
    },
    "Code Scan filesystem collection must keep directory-entry",
  );
});

it.each([
  ['std::fs::read_to_string(".sitecmd/last-scan.json")', "a literal cache path"],
  [
    'let path = sitecmd_dir.join(".gitignore"); std::fs::write(path, "")',
    "an aliased artifact path",
  ],
  ['std::fs::read(sitecmd_dir.join("issues.json"))', "a byte read"],
])("rejects unbounded .sitecmd access through %s (%s)", (access) => {
  expectGuardrailFailure(
    repoGuardrailFailures,
    (overlay) => {
      const file = "apps/desktop/src-tauri/src/cli/fix.rs";
      overlay.set(file, `${access};\n${realRead(file)}`);
    },
    "must use the shared bounded readers and atomic writer for .sitecmd artifacts",
  );
});
