import { describe, expect, it } from "vitest";
import {
  GUARDRAIL_TEST_TIMEOUT_MS,
  deleteFixtureFile,
  expectGuardrailFailure,
  guardrailFailuresFor,
  mustMutate,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const {
  agentGuidanceFailures,
  ciCostSafetyFailures,
  cliSurfaceFailures,
  codeScanSecurityFailures,
  desktopFrontendJsonSafetyFailures,
  desktopFrontendStateFailures,
  documentationSafetyFailures,
  frontendMaintainabilityFailures,
  guardrailScriptLineBudgets,
  publicationRecordFailures,
  releaseArtifactSafetyFailures,
  releaseWorkflowSafetyFailures,
  repoGuardrailFailures,
  rustLineBudgetFailures,
  rustRatchetFailures,
  rustUnwrapBudgetFailures,
} = rules;

describe.concurrent(
  "repo guardrail coverage: quality and release preparation",
  { timeout: GUARDRAIL_TEST_TIMEOUT_MS },
  () => {
    it("fails when a workflow reintroduces a daily-or-more-frequent cron", () => {
      expectGuardrailFailure(
        ciCostSafetyFailures,
        (fixtureRoot) => {
          const auditPath = ".github/workflows/dependency-audit.yml";
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

    it("fails when dependency pull requests stop auditing the updater signer", () => {
      expectGuardrailFailure(
        ciCostSafetyFailures,
        (fixtureRoot) => {
          const auditPath = ".github/workflows/dependency-audit.yml";
          const source = readFixtureFile(fixtureRoot, auditPath);
          writeFixtureFile(
            fixtureRoot,
            auditPath,
            source.replace("  pull_request:\n", "  disabled_pull_request:\n"),
          );
        },
        "must audit the standalone updater signer on dependency pull requests",
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
            "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs",
            "fn guardrail_fixture_bare_unwrap(input: Option<&str>) -> &str { input.unwrap() }\n",
          );
        },
        "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs: 1 bare `.unwrap()`",
      );
    });

    it("fails when a production Rust module adds a bare expect", () => {
      expectGuardrailFailure(
        rustRatchetFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs",
            'fn guardrail_fixture_bare_expect(input: Option<&str>) -> &str { input.expect("must exist") }\n',
          );
        },
        "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs: 1 bare `.expect()`",
      );
    });

    it("fails when a new file adds an inline Duration::from_* outside constants.rs", () => {
      expectGuardrailFailure(
        rustRatchetFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs",
            "fn guardrail_fixture_inline_duration() -> std::time::Duration { std::time::Duration::from_secs(7) }\n",
          );
        },
        "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs: 1 inline `Duration::from_*` outside constants.rs",
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

    it("allows vite env type declarations to reference telemetry env var names", () => {
      const reported = guardrailFailuresFor(repoGuardrailFailures, (fixtureRoot) => {
        writeFixtureFile(
          fixtureRoot,
          "apps/desktop/src/vite-env.d.ts",
          '/// <reference types="vite/client" />\ninterface ImportMetaEnv {\n  readonly VITE_SITECMD_TELEMETRY_ENDPOINT?: string;\n}\ninterface ImportMeta {\n  readonly env: ImportMetaEnv;\n}\n',
        );
      });
      expect(reported).not.toContain(
        "Desktop telemetry endpoint usage must stay inside apps/desktop/src/lib/telemetry.ts: apps/desktop/src/vite-env.d.ts",
      );
    });

    it("fails when a Rust production module grows past the 800-line ceiling", () => {
      expectGuardrailFailure(
        rustLineBudgetFailures,
        (fixtureRoot) => {
          const fixturePath = "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs";
          const filler = "// guardrail-fixture-pad\n".repeat(900);
          writeFixtureFile(fixtureRoot, fixturePath, filler);
        },
        "apps/desktop/src-tauri/src/commands/scan/guardrail_fixture.rs has",
      );
    });

    it("fails when Code Scan source excerpts bypass redaction", () => {
      expectGuardrailFailure(
        codeScanSecurityFailures,
        (fixtureRoot) => {
          const issueUtilsPath = "apps/desktop/src-tauri/src/core/code_scan/issue_utils.rs";
          const issueUtils = readFixtureFile(fixtureRoot, issueUtilsPath);
          writeFixtureFile(
            fixtureRoot,
            issueUtilsPath,
            issueUtils.replace(
              "redact_sensitive_excerpt_line(line.trim_end())",
              "line.trim_end().to_string()",
            ),
          );
        },
        "Code Scan source excerpts must redact secret-like values",
      );
    });

    it("fails when report preferences merge raw localStorage JSON", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const model = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/components/reports/reports-page-model.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/components/reports/reports-page-model.ts",
            model
              .replace(
                "const parsed = parseJsonRecord(saved);",
                "const parsed = JSON.parse(saved);",
              )
              .replace(
                "if (parsed) return sectionsFromRecord(parsed);",
                "if (saved) return { ...DEFAULT_SECTIONS, ...JSON.parse(saved) };",
              ),
          );
        },
        "Desktop report preferences must validate localStorage JSON before merging into branding or section state.",
      );
    });

    it("fails when alert dossiers trust raw detail JSON", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const detailModel = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/components/alerts/alert-detail-model.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/components/alerts/alert-detail-model.ts",
            detailModel
              .replace('import { parseJsonRecord } from "@/lib/json-record";\n', "")
              .replace(
                "return parseJsonRecord(json) ?? {};",
                'if (!json) return {};\n  const parsed = JSON.parse(json) as unknown;\n  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};\n  return parsed as Record<string, unknown>;',
              ),
          );
        },
        "Desktop alert dossiers must validate detail JSON through parseJsonRecord before rendering source metadata.",
      );
    });

    it("fails when scan raw_data readers parse legacy JSON strings ad hoc", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const jsonRecord = readFixtureFile(fixtureRoot, "apps/desktop/src/lib/json-record.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/json-record.ts",
            jsonRecord.replaceAll("coerceJsonRecord", "parseLegacyJsonRecord"),
          );
        },
        "Desktop scan raw_data readers must keep coerceJsonRecord available for legacy JSON-string raw_data.",
      );
    });

    it("fails when scan preferences stop clamping persisted numeric values", () => {
      expectGuardrailFailure(
        desktopFrontendStateFailures,
        (fixtureRoot) => {
          const prefs = readFixtureFile(fixtureRoot, "apps/desktop/src/hooks/useScanPrefs.tsx");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/hooks/useScanPrefs.tsx",
            prefs
              .replace("const TIMEOUT_MIN = 10;\nconst TIMEOUT_MAX = 60;\n", "")
              .replace("const RETENTION_MIN = 5;\nconst RETENTION_MAX = 100;\n", "")
              .replace(
                "timeout: boundedInteger(value.timeout, TIMEOUT_MIN, TIMEOUT_MAX, DEFAULTS.timeout),",
                'timeout: typeof value.timeout === "number" ? value.timeout : DEFAULTS.timeout,',
              )
              .replace(
                "retentionLimit: boundedInteger(\n      value.retentionLimit,\n      RETENTION_MIN,\n      RETENTION_MAX,\n      DEFAULTS.retentionLimit,\n    ),",
                'retentionLimit: typeof value.retentionLimit === "number" ? value.retentionLimit : DEFAULTS.retentionLimit,',
              ),
          );
        },
        "Desktop scan preferences must clamp persisted timeout and retention values before use.",
      );
    });

    it("fails when desktop watch cache stops validating numeric timestamp maps", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const hook = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/hooks/useAppShellOrchestration.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/hooks/useAppShellOrchestration.ts",
            hook.replace(
              "return parseNumberRecord(parseJsonRecord(raw)) ?? {};",
              'const parsed = JSON.parse(raw);\n    return parsed && typeof parsed === "object" ? (parsed as Record<string, number>) : {};',
            ),
          );
        },
        "Desktop persisted localStorage state must parse JSON as unknown records before reading fields.",
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

    it("applies a default line budget to newly extracted guardrail modules", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const modulePath = "tools/scripts/lib/guardrail-code-scan-inventory-rules.mjs";
          const source = readFixtureFile(fixtureRoot, modulePath);
          writeFixtureFile(
            fixtureRoot,
            modulePath,
            `${source}\n${Array.from({ length: 400 }, (_, index) => `// module budget regression ${index}`).join("\n")}\n`,
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

    it("fails when an app surface loses its own agent guidance", () => {
      expectGuardrailFailure(
        agentGuidanceFailures,
        (fixtureRoot) => {
          deleteFixtureFile(fixtureRoot, "apps/desktop/AGENTS.md");
        },
        "Every app surface needs an AGENTS.md and a CLAUDE.md pointer",
      );
    });

    it("fails when guidance routes agents to index.css for component classes", () => {
      expectGuardrailFailure(
        agentGuidanceFailures,
        (fixtureRoot) => {
          const guidance = readFixtureFile(fixtureRoot, "apps/desktop/AGENTS.md");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/AGENTS.md",
            `${guidance}\nCheck index.css under @layer components before writing any className.\n`,
          );
        },
        "Agent guidance must point at src/styles/*.css partials",
      );
    });

    it("fails when guidance describes Button as CVA-based after the refactor removed it", () => {
      expectGuardrailFailure(
        agentGuidanceFailures,
        (fixtureRoot) => {
          const guidance = readFixtureFile(fixtureRoot, "AGENTS.md");
          writeFixtureFile(
            fixtureRoot,
            "AGENTS.md",
            `${guidance}\n- \`components/ui/\` - \`Button\` (with CVA variants), \`Card\`.\n`,
          );
        },
        "must not describe Button as CVA-based",
      );
    });

    it("fails when agent guidance grows an unreadable prose line", () => {
      expectGuardrailFailure(
        agentGuidanceFailures,
        (fixtureRoot) => {
          const guidance = readFixtureFile(fixtureRoot, "apps/desktop/AGENTS.md");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/AGENTS.md",
            `${guidance}\n${"One uninterrupted guidance sentence ".repeat(8)}\n`,
          );
        },
        "AGENTS.md prose lines must stay within 160 characters",
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

    it("fails when first-run docs point users back to the old Issues landing", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const doc = readFixtureFile(fixtureRoot, "docs/product/get-value-in-5-minutes.md");
          writeFixtureFile(
            fixtureRoot,
            "docs/product/get-value-in-5-minutes.md",
            `${doc}\n## Old flow\nRun the first tracked Web Scan and Go straight to Issues.\n`,
          );
        },
        "First-run docs must describe the Full Scan -> Dashboard guided flow",
      );
    });

    it("fails when the MCP README drifts from runtime requirements or registered tools", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const readme = readFixtureFile(fixtureRoot, "apps/mcp-server/README.md");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/README.md",
            readme
              .replace("- **Node.js** 22.22.1+ for manual setup", "- **Node.js** 18+")
              .replace(/\n\| `request_scan`[^\n]+/, ""),
          );
        },
        "sitecmd-mcp package, README, desktop copy, and minimum-Node workflow must agree on the tested Node 22.22.1+ requirement.",
      );
    });

    it("fails when the MCP minimum-Node workflow needs a hidden runtime flag", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const workflow = readFixtureFile(fixtureRoot, ".github/workflows/frontend-quality.yml");
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/frontend-quality.yml",
            workflow
              .replace("node-version: 22.22.1", "node-version: 22.5.0")
              .replace(
                "        run: pnpm --filter sitecmd-mcp run test",
                "        run: pnpm --filter sitecmd-mcp run test\n        env:\n          NODE_OPTIONS: --experimental-sqlite",
              ),
          );
        },
        "sitecmd-mcp package, README, desktop copy, and minimum-Node workflow must agree on the tested Node 22.22.1+ requirement.",
      );
    });

    it("fails when the desktop MCP runtime copy drifts from the supported Node floor", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const cardPath = "apps/desktop/src/components/settings/AgentToolCards.tsx";
          const source = readFixtureFile(fixtureRoot, cardPath);
          writeFixtureFile(
            fixtureRoot,
            cardPath,
            source.replace("Node 22.22.1 or newer on your PATH", "Node 22 or newer on your PATH"),
          );
        },
        "sitecmd-mcp package, README, desktop copy, and minimum-Node workflow must agree on the tested Node 22.22.1+ requirement.",
      );
    });

    it("fails when MCP manual setup points into app installation resources", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const readmePath = "apps/mcp-server/README.md";
          const readme = readFixtureFile(fixtureRoot, readmePath);
          writeFixtureFile(
            fixtureRoot,
            readmePath,
            mustMutate(
              readme,
              "/absolute/path/to/com.sitecmd.app/sitecmd-mcp/sitecmd-mcp.mjs",
              "/Applications/SiteCMD.app/Contents/Resources/sitecmd-mcp/sitecmd-mcp.mjs",
            ),
          );
        },
        "sitecmd-mcp manual setup must use the persistent per-OS script paths",
      );
    });

    it("fails when MCP compatibility guidance copies mutable tool contracts", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const pointerPath = "apps/mcp-server/CLAUDE.md";
          const pointer = readFixtureFile(fixtureRoot, pointerPath);
          writeFixtureFile(
            fixtureRoot,
            pointerPath,
            `${pointer}\nThe server is read-only except request_verification.\n`,
          );
        },
        "sitecmd-mcp CLAUDE.md must remain a pointer",
      );
    });

    it("fails when MCP README says how_to_rescan queues desktop scans", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const readme = readFixtureFile(fixtureRoot, "apps/mcp-server/README.md");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/README.md",
            readme.replace(
              /\| `how_to_rescan`[^\n]+/,
              "| `how_to_rescan`        | Ask SiteCMD to start or queue a scan through the desktop flow |",
            ),
          );
        },
        "sitecmd-mcp README must describe how_to_rescan as guidance-only",
      );
    });

    it("fails when MCP how_to_rescan tool copy says it starts desktop scans", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const source = readFixtureFile(fixtureRoot, "apps/mcp-server/src/server.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/server.ts",
            source.replace(
              "Explain how to get fresh scan results for a site. This tool does not queue a scan; it gives the exact CLI or desktop steps and what to call afterwards.",
              "Request a new scan in SiteCMD and start or queue desktop scans.",
            ),
          );
        },
        "sitecmd-mcp how_to_rescan tool description must stay guidance-only",
      );
    });

    it("fails when retired free scan-history limits come back", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const db = readFixtureFile(fixtureRoot, "apps/mcp-server/src/db.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/db.ts",
            db.replace(
              "export function sanitizeHistoryLimit(limit: number): number {",
              "const FREE_HISTORY_LIMIT = LICENSE_CONSTANTS.free_history_limit;\nexport function sanitizeHistoryLimit(limit: number): number {",
            ),
          );
        },
        "Client-side feature gating is retired with the free complete workbench",
      );

      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const policy = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/scan/policy.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/scan/policy.rs",
            policy.replace(
              "pub(super) const DEFAULT_HISTORY_QUERY_LIMIT: u32 = 100;",
              "pub(super) const FREE_HISTORY_LIMIT: u32 = 10;\npub(super) const DEFAULT_HISTORY_QUERY_LIMIT: u32 = 100;",
            ),
          );
        },
        "Client-side feature gating is retired with the free complete workbench",
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

    it("fails when the MCP recovery runbook is unlinked", () => {
      expectGuardrailFailure(
        documentationSafetyFailures,
        (fixtureRoot) => {
          const mcpReadme = readFixtureFile(fixtureRoot, "apps/mcp-server/README.md");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/README.md",
            mcpReadme.replace(/\n## Recovery[\s\S]*?\n## License\n/, "\n## License\n"),
          );
        },
        "sitecmd-mcp README must link the recovery runbook.",
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
            eslintConfig.replace('"tools/scripts/**/*.mjs",', '"tools/scripts/**/*.off",'),
          );
        },
        "Repository maintenance scripts must be covered by root ESLint",
      );
    });

    it("fails when a React Compiler hook rule is suppressed again", () => {
      expectGuardrailFailure(
        desktopFrontendStateFailures,
        (fixtureRoot) => {
          const eslintConfig = readFixtureFile(fixtureRoot, "eslint.config.js");
          writeFixtureFile(
            fixtureRoot,
            "eslint.config.js",
            eslintConfig.replace('"react-hooks/refs": "error"', '"react-hooks/refs": "off"'),
          );
        },
        "React Compiler hook rules must stay enforced",
      );
    });

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
        "Release workflow must run tests, guardrails, legal-artifact checks, workspace and updater-signer dependency audits, and Rust gates before building signed updater artifacts.",
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

    it("fails when a CLI message names a command the CLI does not have", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const cli = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/src/cli/connected.rs");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/cli/connected.rs",
            mustMutate(
              cli,
              "there is nothing here to gate",
              "run `sitecmd scan --type code` first",
            ),
          );
        },
        "which the scan argument parser rejects",
      );
    });

    it("fails when generated CI falls back to a piped remote installer", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const generatorPath = "apps/desktop/src/components/settings/cicd-workflow.ts";
          const generator = readFixtureFile(fixtureRoot, generatorPath);
          writeFixtureFile(
            fixtureRoot,
            generatorPath,
            mustMutate(
              generator,
              ".github/actions/setup-sitecmd@${setupActionRef(",
              "install.sh | sh # ${setupActionRef(",
            ),
          );
        },
        "must use the signed setup action",
      );
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

    it("fails when the benchmark bypasses the shipped Code Scan CLI", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const scannerPath = "tools/benchmark/lib/scanner.mjs";
          const scanner = readFixtureFile(fixtureRoot, scannerPath);
          writeFixtureFile(
            fixtureRoot,
            scannerPath,
            mustMutate(scanner, '"sitecmd_cli"', '"audit_code_scan"'),
          );
        },
        "must benchmark the shipped sitecmd audit command",
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

    it("fails when repository Code Scan stops gating High findings", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const workflowPath = ".github/workflows/app-guardrails.yml";
          const workflow = readFixtureFile(fixtureRoot, workflowPath);
          writeFixtureFile(
            fixtureRoot,
            workflowPath,
            mustMutate(workflow, "--fail-on high", "--fail-on critical"),
          );
        },
        "must dogfood the shipped Code Scan CLI automatically",
      );
    });

    it("fails when repository Code Scan loses its pull-request trigger", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const workflowPath = ".github/workflows/app-guardrails.yml";
          const workflow = readFixtureFile(fixtureRoot, workflowPath);
          writeFixtureFile(
            fixtureRoot,
            workflowPath,
            mustMutate(workflow, "  pull_request:\n", "  workflow_call:\n"),
          );
        },
        "must dogfood the shipped Code Scan CLI automatically",
      );
    });

    it("fails when Postgres inspection loses its pull-request trigger", () => {
      expectGuardrailFailure(
        cliSurfaceFailures,
        (fixtureRoot) => {
          const workflowPath = ".github/workflows/code-scan-postgres-integration.yml";
          const workflow = readFixtureFile(fixtureRoot, workflowPath);
          writeFixtureFile(
            fixtureRoot,
            workflowPath,
            mustMutate(workflow, "  pull_request:\n", "  workflow_call:\n"),
          );
        },
        "must automatically exercise supported localhost Postgres inspection",
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

    it("fails when a highlight grammar is imported statically again", () => {
      expectGuardrailFailure(
        frontendMaintainabilityFailures,
        (fixtureRoot) => {
          const file = "apps/desktop/src/components/ui/markdown-languages.ts";
          const source = readFixtureFile(fixtureRoot, file);
          writeFixtureFile(
            fixtureRoot,
            file,
            `import rust from "highlight.js/lib/languages/rust";\n${source}`,
          );
        },
        "must lazy-load markdown-renderer.tsx",
      );
    });
  },
);
