import { describe, expect, it } from "vitest";
import {
  GUARDRAIL_TEST_TIMEOUT_MS,
  expectGuardrailFailure,
  guardrailFailuresFor,
  mustMutate,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const {
  codeScanSecurityFailures,
  desktopFrontendJsonSafetyFailures,
  desktopFrontendStateFailures,
  desktopLicensingSafetyFailures,
  desktopOAuthSafetyFailures,
  desktopScannerBodySafetyFailures,
  desktopSeverityConsistencyFailures,
  fixGuideCspGuidanceFailures,
  issueStateSafetyFailures,
  mcpSchemaParityFailures,
  privateStorageSafetyFailures,
  privilegedTokenIssuerFailures,
  releaseArtifactSafetyFailures,
  releaseWorkflowSafetyFailures,
  repoGuardrailFailures,
  telemetrySafetyFailures,
} = rules;

describe.concurrent(
  "repo guardrail coverage: security and privileged boundaries",
  { timeout: GUARDRAIL_TEST_TIMEOUT_MS },
  () => {
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

    it("fails when release-candidate notes are read from the signed tag body", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          const scriptPath = ".github/scripts/release/build-candidate-manifest.sh";
          const script = readFixtureFile(fixtureRoot, scriptPath);
          writeFixtureFile(
            fixtureRoot,
            scriptPath,
            mustMutate(
              script,
              'NOTES=$(node ./tools/scripts/check-changelog-notes.mjs --release-notes "$VERSION")',
              "NOTES=$(git tag -l --format='%(contents:body)' \"$TAG_NAME\")",
            ),
          );
        },
        "read versioned changelog notes without exposing the signed-tag signature block",
      );
    });

    it("fails when the permanent updater key reaches a product build", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/release.yml",
            mustMutate(
              workflow,
              "          GOOGLE_CLIENT_ID: ${{ secrets.GOOGLE_CLIENT_ID }}",
              [
                "          GOOGLE_CLIENT_ID: ${{ secrets.GOOGLE_CLIENT_ID }}",
                "          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}",
              ].join("\n"),
            ),
          );
        },
        "release.yml product builds must require candidate approval, use only a throwaway updater key",
      );
    });

    it("fails when the Google Desktop client credential stops being embedded", () => {
      expectGuardrailFailure(
        desktopOAuthSafetyFailures,
        (fixtureRoot) => {
          const buildScript = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/build.rs");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/build.rs",
            mustMutate(buildScript, '    "GOOGLE_CLIENT_SECRET",\n', ""),
          );
        },
        "Desktop Google OAuth must embed the configured GOOGLE_CLIENT_SECRET",
      );
    });

    it("fails when GitHub OAuth regains unrelated organization scope", () => {
      expectGuardrailFailure(
        desktopOAuthSafetyFailures,
        (fixtureRoot) => {
          const githubOAuth = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/integrations/github_oauth.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/integrations/github_oauth.rs",
            mustMutate(
              githubOAuth,
              'pub const SCOPES: &[&str] = &["repo"];',
              'pub const SCOPES: &[&str] = &["repo", "read:org"];',
            ),
          );
        },
        "Desktop GitHub classic OAuth must not request unrelated organization scope",
      );
    });

    it("fails when OAuth falls back to the redirect-following client", () => {
      expectGuardrailFailure(
        desktopOAuthSafetyFailures,
        (fixtureRoot) => {
          const googleOAuthPath = "apps/desktop/src-tauri/src/integrations/google_oauth.rs";
          const googleOAuth = readFixtureFile(fixtureRoot, googleOAuthPath);
          writeFixtureFile(
            fixtureRoot,
            googleOAuthPath,
            mustMutate(
              googleOAuth,
              "crate::http_client::credentialed_service_client()",
              "crate::http_client::client()",
            ),
          );
        },
        "Desktop OAuth must use the strict no-redirect credentialed client and bounded response readers.",
      );
    });

    it("fails when Google OAuth stops tolerating malformed localhost callbacks", () => {
      expectGuardrailFailure(
        desktopOAuthSafetyFailures,
        (fixtureRoot) => {
          const googleOAuthPath = "apps/desktop/src-tauri/src/integrations/google_oauth.rs";
          const googleOAuth = readFixtureFile(fixtureRoot, googleOAuthPath);
          writeFixtureFile(
            fixtureRoot,
            googleOAuthPath,
            mustMutate(googleOAuth, "let callback_loop = async", "let callback_once = async"),
          );
        },
        "Google OAuth must keep listening after malformed localhost callbacks and bound each callback connection.",
      );
    });

    it("fails when GitHub OAuth opens an unvalidated provider URL", () => {
      expectGuardrailFailure(
        desktopOAuthSafetyFailures,
        (fixtureRoot) => {
          const githubOAuthPath = "apps/desktop/src-tauri/src/integrations/github_oauth.rs";
          const githubOAuth = readFixtureFile(fixtureRoot, githubOAuthPath);
          writeFixtureFile(
            fixtureRoot,
            githubOAuthPath,
            mustMutate(
              githubOAuth,
              'verification_uri.path() == "/login/device"',
              "verification_uri.path().starts_with('/')",
            ),
          );
        },
        "GitHub OAuth must validate the provider-supplied verification URL before opening it.",
      );
    });

    it("fails when desktop app data stops enforcing owner-only storage", () => {
      expectGuardrailFailure(
        privateStorageSafetyFailures,
        (fixtureRoot) => {
          const appPath = "apps/desktop/src-tauri/src/lib.rs";
          const app = readFixtureFile(fixtureRoot, appPath);
          writeFixtureFile(
            fixtureRoot,
            appPath,
            mustMutate(
              app,
              "crate::app_identity::ensure_private_directory(&app_data_dir)?;",
              "std::fs::create_dir_all(&app_data_dir)?;",
            ),
          );
        },
        "Desktop private state must keep app-data and log directories owner-only",
      );
    });

    it("fails when production updater signing no longer depends on the approved build", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/release.yml",
            mustMutate(
              workflow,
              "    needs: [prepare-candidate, build]",
              "    needs: prepare-candidate",
            ),
          );
        },
        "release.yml must expose the permanent updater key only inside the release-updater-signing environment",
      );
    });

    it("fails when protected tag trust can drift from the reviewed signer list", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          const workflowPath = ".github/workflows/release.yml";
          const workflow = readFixtureFile(fixtureRoot, workflowPath);
          writeFixtureFile(
            fixtureRoot,
            workflowPath,
            mustMutate(
              workflow,
              'if ! cmp -s "$REVIEWED_SIGNERS_FILE" "$PROTECTED_SIGNERS_FILE"; then',
              'if ! cmp -s "$PROTECTED_SIGNERS_FILE" "$PROTECTED_SIGNERS_FILE"; then',
            ),
          );
        },
        "protected release-tag-trust signer list",
      );
    });

    it("fails when the credentialed publisher checks out product source", () => {
      expectGuardrailFailure(
        releaseWorkflowSafetyFailures,
        (fixtureRoot) => {
          const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/release.yml",
            mustMutate(
              workflow,
              "    steps:\n      - uses: actions/download-artifact@",
              [
                "    steps:",
                "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                "      - uses: actions/download-artifact@",
              ].join("\n"),
            ),
          );
        },
        "release.yml must publish only after every secretless verification leg",
      );
    });

    it("fails when R2 credentials escape the isolated publisher", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/release.yml",
            mustMutate(
              workflow,
              "          GOOGLE_CLIENT_ID: ${{ secrets.GOOGLE_CLIENT_ID }}",
              [
                "          GOOGLE_CLIENT_ID: ${{ secrets.GOOGLE_CLIENT_ID }}",
                "          AWS_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}",
              ].join("\n"),
            ),
          );
        },
        "release.yml must keep R2 and manifest-promotion credentials in the checkout-free publish-release job",
      );
    });

    it("fails when the shipped desktop build drops the Connected service endpoint", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
          writeFixtureFile(
            fixtureRoot,
            ".github/workflows/release.yml",
            mustMutate(
              workflow,
              '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"\n',
              "",
            ),
          );
        },
        "release.yml and build.rs must bake SITECMD_CONNECTED_ENDPOINT",
      );
    });

    it("fails when release-time dmgbuild install drops the hash-pinned requirements closure", () => {
      expectGuardrailFailure(
        releaseArtifactSafetyFailures,
        (fixtureRoot) => {
          const scriptPath = ".github/scripts/release/build-macos-dmg.sh";
          const script = readFixtureFile(fixtureRoot, scriptPath);
          writeFixtureFile(
            fixtureRoot,
            scriptPath,
            mustMutate(
              script,
              '--require-hashes -r "$SRC/branding/dmgbuild-requirements.txt"',
              "dmgbuild",
            ),
          );
        },
        "release.yml must install dmgbuild only via --require-hashes -r $SRC/branding/dmgbuild-requirements.txt",
      );
    });

    it("fails when product fix guidance recommends unsafe script CSP sources", () => {
      expectGuardrailFailure(
        fixGuideCspGuidanceFailures,
        (fixtureRoot) => {
          const guidesPath = "apps/desktop/src/lib/fix-guides/security.ts";
          const guides = readFixtureFile(fixtureRoot, guidesPath);
          writeFixtureFile(
            fixtureRoot,
            guidesPath,
            guides.replace(
              "then build a least-privilege policy from that list,",
              "then use `script-src 'self' 'unsafe-inline'`,",
            ),
          );
        },
        "SiteCMD CSP and HTML fix guidance must not recommend unsafe script CSP sources or inline event handlers",
      );
    });

    it("fails when MCP workspace cache reads trust raw .sitecmd JSON", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const workspace = readFixtureFile(fixtureRoot, "apps/mcp-server/src/workspace.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/workspace.ts",
            workspace.replace(
              "const scan = parseWorkspaceScanResult(raw);",
              "const scan = raw as WorkspaceScanResult;",
            ),
          );
        },
        "sitecmd-mcp filesystem JSON reads must parse untrusted workspace and package JSON before using it.",
      );
    });

    it("fails when MCP workspace fallback issues are double-cast to DB issues", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const index = readFixtureFile(fixtureRoot, "apps/mcp-server/src/server.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/server.ts",
            index.replace(
              'issues: getWorkspaceIssues(url, { ...opts, status: "fail" }),',
              'issues: getWorkspaceIssues(url, { ...opts, status: "fail" }) as unknown as Issue[],',
            ),
          );
        },
        "sitecmd-mcp workspace fallback issues must be structurally typed, not double-cast to DB issues.",
      );
    });

    it("fails when MCP causal graph JSON is cast instead of parsed", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const graph = readFixtureFile(fixtureRoot, "apps/mcp-server/src/causal_graph.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/causal_graph.ts",
            graph
              .replace(
                "export const CAUSAL_LINKS: readonly CausalLink[] = parseCausalGraph(readGraphJson());",
                "",
              )
              .replace(
                "export function parseCausalGraph(value: unknown): readonly CausalLink[]",
                "function unusedParseCausalGraph(value: unknown): readonly CausalLink[]",
              )
              .replace(
                "function readGraphJson(): unknown",
                'const graphFile = JSON.parse(readFileSync(join(__dirname, "causal_graph.json"), "utf8")) as {\n  links: CausalLink[];\n};\nconst LINKS: readonly CausalLink[] = graphFile.links;\n\nfunction unusedReadGraphJson(): unknown',
              ),
          );
        },
        "sitecmd-mcp causal graph JSON must be parsed as unknown generated data before use.",
      );
    });

    it("fails when MCP package.json framework detection trusts raw manifest shapes", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const workspace = readFixtureFile(fixtureRoot, "apps/mcp-server/src/workspace.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/workspace.ts",
            workspace.replace(
              "const deps = parsePackageDependencyNames(readJson(packageJsonPath));\n  if (!deps) return null;",
              'const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {\n    dependencies?: Record<string, string>;\n    devDependencies?: Record<string, string>;\n  };\n  const deps = new Set([...Object.keys(parsed.dependencies ?? {}), ...Object.keys(parsed.devDependencies ?? {})]);',
            ),
          );
        },
        "sitecmd-mcp filesystem JSON reads must parse untrusted workspace and package JSON before using it.",
      );
    });

    it("fails when MCP dismissals read the dead project_work_items store", () => {
      expectGuardrailFailure(
        issueStateSafetyFailures,
        (fixtureRoot) => {
          const db = readFixtureFile(fixtureRoot, "apps/mcp-server/src/db.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/db.ts",
            db.replace("FROM project_issue_states s", "FROM project_work_items s"),
          );
        },
        "apps/mcp-server/src/db.ts must read scan-issue lifecycle from project_issue_states, never project_work_items (dead store deleted by audit F2).",
      );
    });

    it("fails when MCP SQL names a column that does not exist in the schema snapshot", () => {
      expectGuardrailFailure(
        mcpSchemaParityFailures,
        (fixtureRoot) => {
          const db = readFixtureFile(fixtureRoot, "apps/mcp-server/src/db_correlation.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/db_correlation.ts",
            db.replace(
              "`SELECT check_id, category, severity, title, description, source, page_url",
              "`SELECT check_id, category, severity, title, description, source, page_url,\n              COALESCE(impact_score, 0) as impact_score",
            ),
          );
        },
        'bare identifier "impact_score" is not a column on work_items',
      );
    });

    it("fails when one MCP literal hides an agent_requests update behind its insert", () => {
      expectGuardrailFailure(
        mcpSchemaParityFailures,
        (fixtureRoot) => {
          const requestsPath = "apps/mcp-server/src/db_agent_requests.ts";
          const source = readFixtureFile(fixtureRoot, requestsPath);
          writeFixtureFile(
            fixtureRoot,
            requestsPath,
            source.replace(
              "VALUES (?, ?, ?, ?, ?, ?, 'requested', ?, ?, ?, ?)`",
              "VALUES (?, ?, ?, ?, ?, ?, 'requested', ?, ?, ?, ?);\n       UPDATE agent_requests SET status = 'fulfilled'`",
            ),
          );
        },
        'apps/mcp-server/src/db_agent_requests.ts mutates "agent_requests"',
      );
    });

    it("fails when an MCP read module imports the write-capable connection", () => {
      expectGuardrailFailure(
        mcpSchemaParityFailures,
        (fixtureRoot) => {
          const correlationPath = "apps/mcp-server/src/db_correlation.ts";
          const source = readFixtureFile(fixtureRoot, correlationPath);
          writeFixtureFile(
            fixtureRoot,
            correlationPath,
            source.replace(
              'import { getDb } from "./db_connection.js";',
              'import { getDb, getDbWrite } from "./db_connection.js";',
            ),
          );
        },
        "imports or exposes the write-capable MCP connection",
      );
    });

    it("fails when MCP dismissals drop the snooze-expiry semantics", () => {
      expectGuardrailFailure(
        issueStateSafetyFailures,
        (fixtureRoot) => {
          const db = readFixtureFile(fixtureRoot, "apps/mcp-server/src/db.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/db.ts",
            db.replace(
              'const DISMISSED_STATUSES = new Set(["snoozed", "ignored", "blocked", "verified"]);',
              'const DISMISSED_STATUSES = new Set(["ignored"]);',
            ),
          );
        },
        "apps/mcp-server/src/db.ts dismissal reads must mirror the desktop's get_inactive_check_ids semantics: snoozed/ignored/blocked/verified with snooze-expiry flipping back to active.",
      );
    });

    it("fails when MCP severity ordering drifts across modules", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const causalGraph = readFixtureFile(fixtureRoot, "apps/mcp-server/src/causal_graph.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/causal_graph.ts",
            causalGraph
              .replace('import { severityRank } from "./severity.js";\n', "")
              .replace(
                "function isRecord(value: unknown): value is Record<string, unknown> {",
                "const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };\n\nfunction isRecord(value: unknown): value is Record<string, unknown> {",
              ),
          );
        },
        "Severity ordering must match between apps/desktop/src/lib/severity.ts and apps/mcp-server/src/severity.ts, and MCP DB/workspace/causal ranking must import the shared MCP severity helpers.",
      );
    });

    it("fails when MCP scan comparison mixes sources in one scan-history window", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const db = readFixtureFile(fixtureRoot, "apps/mcp-server/src/db.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/db.ts",
            db.replace(
              "AND source = ?\n         AND (",
              "AND source IN ('web_scan', 'code_scan')\n         AND (",
            ),
          );
        },
        "sitecmd-mcp scan comparison must compare Web Scan and Code Scan issues against their own scan-history windows.",
      );
    });

    it("fails when MCP DB URL lookups become trailing-slash exact again", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const db = readFixtureFile(fixtureRoot, "apps/mcp-server/src/db.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/mcp-server/src/db.ts",
            db.replace("WHERE e.url IN (?, ?)", "WHERE e.url = ?"),
          );
        },
        "sitecmd-mcp URL lookups must normalize trailing-slash variants",
      );
    });

    it("fails when desktop persisted state reads trust raw localStorage JSON", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const shellState = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/app-shell-state.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/app-shell-state.ts",
            shellState.replace(
              "const parsed = parseJsonRecord(raw);",
              "const parsed = JSON.parse(raw) as { page?: string } | null;",
            ),
          );
        },
        "Desktop persisted localStorage state must parse JSON as unknown records before reading fields.",
      );
    });

    it("fails when localStorage migrations promote unchecked JSON into durable store", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const store = readFixtureFile(fixtureRoot, "apps/desktop/src/lib/store.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/store.ts",
            store
              .replace("getAppSetting<unknown>(storeKey)", "getAppSetting<T>(storeKey)")
              .replace(
                "const parsed = parseStoredValue(JSON.parse(raw) as unknown);",
                "const parsed = JSON.parse(raw) as T;",
              ),
          );
        },
        "Desktop localStorage migrations must validate unknown JSON before promotion to durable store",
      );
    });

    it("fails when dashboard snapshot caches trust raw sessionStorage JSON", () => {
      expectGuardrailFailure(
        desktopFrontendJsonSafetyFailures,
        (fixtureRoot) => {
          const cache = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/project-summary-cache.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/project-summary-cache.ts",
            cache.replace(
              "const parsed = parseSnapshotCacheEntry<T>(JSON.parse(raw) as unknown);",
              "const parsed = JSON.parse(raw) as SnapshotCacheEntry<T>;",
            ),
          );
        },
        "Desktop dashboard/session snapshot caches must validate cached JSON entries before hydrating them.",
      );
    });

    it("fails when the durable-entry store does not hydrate from the Tauri store", () => {
      expectGuardrailFailure(
        desktopFrontendStateFailures,
        (fixtureRoot) => {
          const store = readFixtureFile(fixtureRoot, "apps/desktop/src/lib/durable-entry-store.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/durable-entry-store.ts",
            store.replace(
              "migrateFromLocalStorage<Record<string, E>>",
              "Promise.resolve<Record<string, E>>",
            ),
          );
        },
        "Desktop durable-entry-store must hydrate reads from the durable Tauri Store and merge early writes back, not read localStorage only.",
      );
    });

    it("fails when update memory does not build on createDurableEntryStore", () => {
      expectGuardrailFailure(
        desktopFrontendStateFailures,
        (fixtureRoot) => {
          const memory = readFixtureFile(fixtureRoot, "apps/desktop/src/lib/update-memory.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/update-memory.ts",
            memory.replace("createDurableEntryStore<UpdateMemoryEntry>", "makeLocalOnlyStore"),
          );
        },
        "Desktop update memory must build on createDurableEntryStore, not a bespoke localStorage-only cache.",
      );
    });

    it("fails when the durable memory hydration test no longer pins the merge-back behavior", () => {
      expectGuardrailFailure(
        desktopFrontendStateFailures,
        (fixtureRoot) => {
          const tests = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/durable-memory-hydration.test.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/durable-memory-hydration.test.ts",
            tests.replace(
              "keeps the localStorage fallback in sync when update snapshots merge after early writes",
              "does something else",
            ),
          );
        },
        "Desktop durable memory hydration must sync merged store-backed state back to the localStorage fallback after early writes.",
      );
    });

    it("fails when elevated privileged brokers are mounted back on main", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const defaultToml = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/permissions/default.toml",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/permissions/default.toml",
            defaultToml.replace(
              '"allow-get-work-items",',
              '"allow-get-work-items",\n    "allow-run-data-admin-command",',
            ),
          );
        },
        "Main-window elevated access must keep every elevated broker off main",
      );
    });

    it("fails when connector or filesystem brokers are mounted back on main", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const defaultToml = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/permissions/default.toml",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/permissions/default.toml",
            defaultToml.replace(
              '"allow-get-work-items",',
              '"allow-get-work-items",\n    "allow-run-external-connector-command",\n    "allow-run-filesystem-access-command",',
            ),
          );
        },
        "Main-window elevated access must keep every elevated broker off main",
      );
    });

    it("fails when privileged bridge windows are not created natively", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const lib = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/src/lib.rs");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/lib.rs",
            lib.replace("\n            create_privileged_bridge_windows(app)?;\n", "\n"),
          );
        },
        "Main-window elevated access must keep every elevated broker off main",
      );
    });

    it("fails when privileged bridge windows are created from the renderer", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const bridge = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
            bridge.replace(
              "if (!existing) throw new Error(`Privileged ${scope} bridge window is not available.`);",
              "if (!existing) new WebviewWindow(scope, { visible: false });",
            ),
          );
        },
        "Main-window elevated access must keep every elevated broker off main",
      );
    });

    it("fails when privileged bridge requests skip the readiness handshake", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const bridge = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
            bridge.replace("await waitForPrivilegedBridge(scope);", ""),
          );
        },
        "Privileged bridge windows must use a ping/ack readiness handshake and cleanup regression tests before privileged command dispatch.",
      );
    });

    it("fails when privileged bridge requests do not require native-issued tokens", () => {
      expectGuardrailFailure(
        privilegedTokenIssuerFailures,
        (fixtureRoot) => {
          const bridge = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
            bridge
              .replace('    typeof value.token !== "string"\n', "    false\n")
              .replace("            token: request.token,\n", ""),
          );
        },
        "Privileged bridge requests must carry argument-bound tokens",
      );
    });

    it("fails when privileged token issuers do not reject non-main windows", () => {
      expectGuardrailFailure(
        privilegedTokenIssuerFailures,
        (fixtureRoot) => {
          const broker = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/mod.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/mod.rs",
            broker.replace(
              'fn ensure_main_token_issuer_window(window: &Window) -> Result<(), String> {\n    if window.label() == "main" {\n        return Ok(());\n    }\n\n    Err("Privileged command tokens can only be issued from the main window.".to_string())\n}\n',
              "fn ensure_main_token_issuer_window(_window: &Window) -> Result<(), String> {\n    Ok(())\n}\n",
            ),
          );
        },
        "token issuers must reject non-main windows",
      );
    });

    it("fails when sensitive privileged token issuance skips native user intent", () => {
      expectGuardrailFailure(
        privilegedTokenIssuerFailures,
        (fixtureRoot) => {
          const broker = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/mod.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/mod.rs",
            mustMutate(
              broker,
              "    confirm_sensitive_token_issue(app, broker_command, &request.command, &request.args).await?;\n",
              "",
            ),
          );
        },
        "sensitive commands must use native user intent",
      );
    });

    it("fails when privileged bridge tokens are not bound to command arguments", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const bridge = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
          );
          const broker = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
            bridge
              .replace(
                "  const token = await issuePrivilegedCommandToken(brokerCommand, command, commandArgs);",
                "  const token = await issuePrivilegedCommandToken(brokerCommand, command, {});",
              )
              .replace("      args: commandArgs,\n", ""),
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
            broker.replace(
              "    token_state.consume(\n        request.token.as_deref(),\n        BROKER_COMMAND,\n        &command,\n        &request.args,\n    )?;",
              "    token_state.consume(\n        request.token.as_deref(),\n        BROKER_COMMAND,\n        &command,\n        &Value::Null,\n    )?;",
            ),
          );
        },
        "Privileged command tokens must be bound to the exact argument payload",
      );
    });

    it("fails when privileged command tokens store raw argument payloads", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const tokenState = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/token_state.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/token_state.rs",
            tokenState
              .replace("use sha2::{Digest, Sha256};\n", "")
              .replace(
                '    let canonical = serde_json::to_vec(&canonical_json_value(args))\n        .map_err(|error| format!("Could not sign privileged command arguments: {error}"))?;\n    let digest = Sha256::digest(&canonical);\n    Ok(hex::encode(digest))',
                '    serde_json::to_string(&canonical_json_value(args))\n        .map_err(|error| format!("Could not sign privileged command arguments: {error}"))',
              ),
          );
        },
        "Privileged command tokens must be bound to the exact argument payload",
      );
    });

    it("fails when broker-wide token-issue prompting returns (double-prompt regression)", () => {
      expectGuardrailFailure(
        privilegedTokenIssuerFailures,
        (fixtureRoot) => {
          const bridge = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/privileged-command-bridge.ts",
            bridge.replace(
              "const NATIVE_INTENT_CONNECTOR_COMMANDS",
              'const NATIVE_INTENT_BROKERS = new Set(["run_data_admin_command"]);\nconst NATIVE_INTENT_CONNECTOR_COMMANDS',
            ),
          );
        },
        "per-family scoped issuers must stay mounted",
      );
    });

    it("fails when scoped brokers do not consume privileged command tokens", () => {
      expectGuardrailFailure(
        privilegedTokenIssuerFailures,
        (fixtureRoot) => {
          // Every scoped broker admits through the shared BrokerScope::admit
          // seam in mod.rs, the one place that calls TokenStore::consume; a
          // regression here silently skips token consumption for all five.
          const brokerPath = "apps/desktop/src-tauri/src/commands/privileged_command_broker/mod.rs";
          const broker = readFixtureFile(fixtureRoot, brokerPath);
          writeFixtureFile(
            fixtureRoot,
            brokerPath,
            mustMutate(
              broker,
              "        tokens.consume(\n            request.token.as_deref(),\n            self.broker_command,\n            &request.command,\n            &request.args,\n        )\n",
              "        Ok(())\n",
            ),
          );
        },
        "Privileged bridge requests must carry argument-bound tokens",
      );
    });

    it("fails when the privileged command broker is missing a Rust match arm", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const broker = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
            broker.replace('"delete_project" =>', '"delete_project_missing" =>'),
          );
        },
        "Privileged broker match arms must exactly cover every brokered elevated permission",
      );
    });

    it("fails when privileged broker scope lists drift from permission files", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const broker = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
            broker.replace('    "delete_project",\n', ""),
          );
        },
        "Feature-scoped privileged broker command lists must exactly match their elevated permission files",
      );
    });

    it("fails when an elevated permission set is granted to any window", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const capability = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/capabilities/external-connectors.json",
          );
          const parsed = JSON.parse(capability);
          parsed.permissions = [...(parsed.permissions ?? []), "sitecmd-external-connectors"];
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/capabilities/external-connectors.json",
            JSON.stringify(parsed, null, 2),
          );
        },
        "must NOT include the elevated permission set",
      );
    });

    it("fails when sensitive privileged broker commands are not listed as native-confirmed", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const manifest = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/permissions/command-security.json",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/permissions/command-security.json",
            manifest.replace(
              '    {\n      "command": "write_export_file",\n      "source": "apps/desktop/src-tauri/src/commands/data/exports.rs",\n      "requires": "confirm_export_write("\n    },\n',
              "",
            ),
          );
        },
        "Sensitive privileged token broker commands must require native confirmation",
      );
    });

    it("fails when a delegated native-confirmation path is broken", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const activationPath =
            "apps/desktop/src-tauri/src/licensing/commands/license_lifecycle_activation.rs";
          const activation = readFixtureFile(fixtureRoot, activationPath);
          writeFixtureFile(
            fixtureRoot,
            activationPath,
            mustMutate(
              activation,
              "ports.confirm_replacement(&current_tier).await",
              "ports.skip_replacement(&current_tier).await",
            ),
          );
        },
        "High-risk IPC commands must require native confirmation",
      );
    });

    it("fails when export writes only confirm overwrites", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const dataExports = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/data/exports.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/data/exports.rs",
            dataExports.replace(
              "validate_export_write_path(path)?;\n    let target = Path::new(path);",
              "let target = Path::new(path);\n    if !target.exists() {\n        return Ok(false);\n    }",
            ),
          );
        },
        "Desktop export writes must require native confirmation before creating or replacing files.",
      );
    });

    it("fails when webhook delivery logs expose full destination URLs", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const webhooks = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/src/webhooks.rs");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/webhooks.rs",
            webhooks
              .replace(
                'Ok(()) => tracing::info!("Webhook delivered to {}", target),',
                'Ok(()) => tracing::info!("Webhook delivered to {}", url),',
              )
              .replace(
                'Err(e) => tracing::warn!("Webhook delivery failed for {}: {}", target, e),',
                'Err(e) => tracing::warn!("Webhook to {} failed: {}", url, e),',
              ),
          );
        },
        "Desktop webhook delivery logs must redact full destination URLs before logging delivery results.",
      );
    });

    it("fails when desktop scan logs write raw URLs", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const scan = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/scan/web_scan.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/scan/web_scan.rs",
            scan.replace(
              "crate::log_sanitizer::log_safe_url_target(&page_url)",
              "page_url.clone()",
            ),
          );
        },
        "Desktop scan logs must use log_safe_url_target before writing scan URLs to persistent logs",
      );
    });

    it("fails when frontend logs reach Rust without redaction", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const logger = readFixtureFile(fixtureRoot, "apps/desktop/src/lib/logger.ts");
          const dataDiagnostics = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/data/diagnostics.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/logger.ts",
            logger
              .replace("message: sanitizeFrontendLogText(message),", "message,")
              .replace(
                "context: context ? sanitizeFrontendLogText(context) : undefined,",
                "context,",
              ),
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/commands/data/diagnostics.rs",
            dataDiagnostics.replace(
              "let message = sanitize_frontend_log_text(&message);",
              "let message = message;",
            ),
          );
        },
        "Desktop frontend logs must redact and truncate sensitive text before writing to persistent logs",
      );
    });

    it("fails when frontend feature gating comes back in useTier", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const useTier = readFixtureFile(fixtureRoot, "apps/desktop/src/hooks/useTier.tsx");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/hooks/useTier.tsx",
            useTier.replace(
              "const effectiveTier: Tier = licenseInfo.tier;",
              'const hasFeature = () => licenseInfo.tier !== "free";\n  const effectiveTier: Tier = licenseInfo.tier;',
            ),
          );
        },
        "Client-side feature gating is retired with the free complete workbench",
      );
    });

    it("fails when license activation audit logs include key prefixes", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const lifecycle = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/licensing/commands/license_lifecycle_activation.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/licensing/commands/license_lifecycle_activation.rs",
            lifecycle
              .replace(
                "let key_fingerprint = license_key_fingerprint(&key);",
                "let key_prefix: String = key.chars().take(8).collect();",
              )
              .replace(
                "let audit_detail = license_activation_audit_detail(&key_fingerprint);",
                'let audit_detail = serde_json::json!({ "key_prefix": key_prefix });',
              ),
          );
        },
        "Desktop licensing and checkout secret handling must use hashed non-PII fingerprints",
      );
    });

    it("fails when license instance names include raw hostnames", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const api = readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/src/licensing/api.rs");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/licensing/api.rs",
            api
              .replace(
                "machine_instance_name_from_parts(&hostname, &username)",
                'format!("{}-{:08x}", hostname, 0)',
              )
              .replace(
                "machine_instance_name_does_not_leak_host_or_username",
                "machine_instance_name_leaks_host",
              ),
          );
        },
        "Desktop licensing and checkout secret handling must use hashed non-PII fingerprints",
      );
    });

    it("fails when Lemon Squeezy checkout trial entitlements stop being honored", () => {
      expectGuardrailFailure(
        desktopLicensingSafetyFailures,
        (fixtureRoot) => {
          const accessPath = "apps/desktop/src-tauri/src/licensing/access.rs";
          const access = readFixtureFile(fixtureRoot, accessPath);
          writeFixtureFile(
            fixtureRoot,
            accessPath,
            access
              .replace('matches!(status, "active" | "on_trial")', 'matches!(status, "active")')
              .replace(
                "effective_tier_keeps_recent_lemon_checkout_trial_cache",
                "effective_tier_drops_recent_lemon_checkout_trial_cache",
              ),
          );
        },
        "Lemon Squeezy on_trial license status must remain entitled and tested",
      );
    });

    it("fails when desktop subresource scan logs write raw URLs", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const cssFetch = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/checks/polish/css_fetch.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/checks/polish/css_fetch.rs",
            [
              [
                'tracing::debug!("Fetched CSS ({} bytes): {}", text.len(), safe_url);',
                'tracing::debug!("Fetched CSS ({} bytes): {}", text.len(), url);',
              ],
              [
                'tracing::warn!("Failed to read CSS body from {}: {}", safe_url, e)',
                'tracing::warn!("Failed to read CSS body from {}: {}", url, e)',
              ],
              [
                'tracing::warn!("CSS fetch returned {} for {}", resp.status(), safe_url);',
                'tracing::warn!("CSS fetch returned {} for {}", resp.status(), url);',
              ],
              [
                'tracing::warn!("CSS fetch failed for {}: {}", safe_url, e);',
                'tracing::warn!("CSS fetch failed for {}: {}", url, e);',
              ],
              [
                'tracing::warn!("CSS fetch timed out for {}", safe_url);',
                'tracing::warn!("CSS fetch timed out for {}", url);',
              ],
            ].reduce((source, [from, to]) => source.replace(from, to), cssFetch),
          );
        },
        "Desktop scan logs must use log_safe_url_target before writing scan URLs to persistent logs",
      );
    });

    it("fails when secret-bearing plugin permissions are mounted on main", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const capability = JSON.parse(
            readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/capabilities/default.json"),
          );
          capability.permissions.push("keyring:default");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/capabilities/default.json",
            `${JSON.stringify(capability, null, 2)}\n`,
          );
        },
        "Main renderer capabilities must not grant keyring secret access or install-capable updater permissions",
      );
    });

    it("fails when install-capable updater permissions are mounted on main", () => {
      expectGuardrailFailure(
        repoGuardrailFailures,
        (fixtureRoot) => {
          const capability = JSON.parse(
            readFixtureFile(fixtureRoot, "apps/desktop/src-tauri/capabilities/default.json"),
          );
          capability.permissions.push("updater:default");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/capabilities/default.json",
            `${JSON.stringify(capability, null, 2)}\n`,
          );
        },
        "Main renderer capabilities must not grant keyring secret access or install-capable updater permissions",
      );
    });

    it("fails when desktop telemetry stops pruning expired queued events", () => {
      expectGuardrailFailure(
        telemetrySafetyFailures,
        (fixtureRoot) => {
          const telemetry = readFixtureFile(fixtureRoot, "apps/desktop/src/lib/telemetry.ts");
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/lib/telemetry.ts",
            telemetry.replace(
              ".filter((event) => queuedEventIsWithinAcceptanceWindow(event.occurredAt))",
              "",
            ),
          );
        },
        "Desktop telemetry must prune queued events that the hosted acceptance window will reject.",
      );
    });

    it("fails when scanner checks read response bodies without the bounded helper", () => {
      expectGuardrailFailure(
        desktopScannerBodySafetyFailures,
        (fixtureRoot) => {
          const robots = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/checks/seo/robots.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/src/checks/seo/robots.rs",
            `${robots}\nasync fn unsafe_body_read(resp: reqwest::Response) { let _ = resp.text().await; }\n`,
          );
        },
        "scanner HTTP bodies must use http_client::read_body_limited/read_text_limited",
      );
    });

    it("accepts a run_polish_phase call that rustfmt wrapped across lines", () => {
      const scannerPath = "apps/desktop/src-tauri/src/core/scanner.rs";
      const reported = guardrailFailuresFor(desktopScannerBodySafetyFailures, (fixtureRoot) => {
        const scanner = readFixtureFile(fixtureRoot, scannerPath);
        if (!/run_polish_phase\(\s*&mut ctx/.test(scanner)) {
          throw new Error(`no run_polish_phase(&mut ctx call found in ${scannerPath}`);
        }
        // rustfmt breaks the call whenever the argument list passes
        // fn_call_width; the ordering rule must not care.
        writeFixtureFile(
          fixtureRoot,
          scannerPath,
          scanner.replace(
            /run_polish_phase\(\s*&mut ctx/,
            "run_polish_phase(\n            &mut ctx",
          ),
        );
      });
      expect(reported).not.toContain("site_facts::read_before_polish");
    });

    it("fails when the pre-polish body read moves below the polish phase", () => {
      expectGuardrailFailure(
        desktopScannerBodySafetyFailures,
        (fixtureRoot) => {
          const scannerPath = "apps/desktop/src-tauri/src/core/scanner.rs";
          const scanner = readFixtureFile(fixtureRoot, scannerPath);
          const moved = mustMutate(
            scanner,
            "site_facts::read_before_polish(",
            "site_facts::read_after_polish_placeholder(",
          );
          writeFixtureFile(
            fixtureRoot,
            scannerPath,
            `${moved}\n// site_facts::read_before_polish( now runs after the polish phase\n`,
          );
        },
        "scanner.rs must call site_facts::read_before_polish before run_polish_phase consumes the page body via mem::take",
      );
    });

    it("fails when Unicode-safe HTML offset regressions lose coverage", () => {
      expectGuardrailFailure(
        desktopScannerBodySafetyFailures,
        (fixtureRoot) => {
          const exposed = readFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/crates/engine/src/checks/security/exposed_files.rs",
          );
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src-tauri/crates/engine/src/checks/security/exposed_files.rs",
            exposed.replace(
              "script_extraction_preserves_offsets_after_unicode_case_expansion",
              "script_extraction_without_unicode_regression",
            ),
          );
        },
        "HTML offset parsing must preserve UTF-8 byte positions and keep Unicode regression coverage",
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

    it("rejects reintroducing an inline severity tone map in desktop scan components", () => {
      expectGuardrailFailure(
        desktopSeverityConsistencyFailures,
        (fixtureRoot) => {
          const modelPath = "apps/desktop/src/components/scan/CodeScanResultParts.tsx";
          const source = readFixtureFile(fixtureRoot, modelPath);
          writeFixtureFile(
            fixtureRoot,
            modelPath,
            `${source}\nconst BROKEN_SEVERITY_TONES = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400" };\n`,
          );
        },
        "Desktop issue severity styling must route through lib/severity.ts severityToneClass",
      );
    });

    it('rejects reintroducing a severity === "critical" className branch in desktop components', () => {
      expectGuardrailFailure(
        desktopSeverityConsistencyFailures,
        (fixtureRoot) => {
          writeFixtureFile(
            fixtureRoot,
            "apps/desktop/src/components/issues/dossier-badges.ts",
            'export function severityTextClass(severity: string): string {\n  if (severity === "critical") return "text-severity-critical";\n  if (severity === "high") return "text-severity-high";\n  if (severity === "medium") return "text-severity-medium";\n  if (severity === "low") return "text-severity-low";\n  return "text-muted-foreground";\n}\n',
          );
        },
        "Desktop issue severity styling must route through lib/severity.ts severityToneClass",
      );
    });
  },
);
