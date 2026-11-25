import { describe, expect, it } from "vitest";
import { exportedTree, realRead, rules } from "./guardrail-test-support.mjs";

const {
  codeOwnerSafetyFailures,
  deployWorkflowHardeningFailures,
  orderedBefore,

  unifiedScanArchitectureFailures,
  workflowSafetyFailures,
} = rules;

describe("codeOwnerSafetyFailures", () => {
  const source = realRead(".github/CODEOWNERS");

  it("accepts the repository's sensitive-path ownership contract", () => {
    expect(codeOwnerSafetyFailures(() => source)).toEqual([]);
  });

  it("rejects removal of a release or legal boundary", () => {
    const regressed = source
      .replace(/^\/apps\/desktop\/src\/components\/privacy\/.*\n/m, "")
      .replace(/^\/install\.sh.*\n/m, "")
      .replace(/^\/tools\/scripts\/.*\n/m, "");
    const failures = codeOwnerSafetyFailures(() => regressed).join("\n");
    expect(failures).toContain("/install.sh");
    expect(failures).toContain("/tools/scripts/");
  });
});

describe("unifiedScanArchitectureFailures", () => {
  const base = {
    "apps/desktop/src-tauri/src/commands/scan/execution.rs":
      "admission_request(&plan, fingerprint, ScanAdmissionClass::GeneralScan, now)",
    "apps/desktop/src-tauri/src/commands/scan/verification.rs": [
      "required_web_verification_ids(&check_ids)",
      "if coverage.is_empty()",
      "admission_class: ScanAdmissionClass::BoundedVerification",
    ].join("\n"),
    "apps/desktop/src-tauri/src/db/issue_states.rs":
      "reconcile_reobserved_lifecycle(tx, project_id, env_url, observed_at, check_ids);",
    "apps/desktop/src/pages/IssuesPage.tsx": "rankIssueGroups(visibleIssueGroups)",
    "apps/desktop/src/pages/issues/useInactiveIssueKeys.ts":
      "getWorkItems({ projectId, envUrl: normalizedUrl })",
    "apps/desktop/src/lib/project-issue-summary.ts": "buildIssueGroupSummary",
    "apps/desktop/src-tauri/build.rs": '"run_scan_execution"',
    "apps/desktop/src-tauri/src/lib.rs": "run_scan_execution",
    "apps/desktop/src/lib/commands/scan.ts": '"run_scan_execution"',
    "apps/desktop/src/lib/tauri-invoke.ts": "",
  };
  const run = (overrides = {}) => {
    const fixture = { ...base, ...overrides };
    const read = (file) => fixture[file] ?? "";
    const exists = (file) => Object.hasOwn(fixture, file);
    const listFiles = (dir, predicate) =>
      Object.keys(fixture).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
    return unifiedScanArchitectureFailures(read, exists, listFiles);
  };

  it("accepts the canonical execution, identity, lifecycle, and Issues paths", () => {
    expect(run()).toEqual([]);
  });

  it("rejects legacy SQL, path-bearing IDs, and delimiter parsers", () => {
    expect(
      run({
        "apps/desktop/src-tauri/src/db/bad.rs":
          "SELECT * FROM code_scans; const checkId = value; checkId.split(':'); const bad = 'code_scan.rule:src/a.ts';",
      }).join("\n"),
    ).toContain("legacy scan tables");
    expect(
      run({ "apps/desktop/src-tauri/src/db/bad.rs": "const id = 'code_scan.rule:src/a.ts';" }).join(
        "\n",
      ),
    ).toContain("rule-level");
    expect(
      run({ "apps/desktop/src-tauri/src/db/bad.rs": "checkId.split(':')" }).join("\n"),
    ).toContain("must not parse");
  });

  it("rejects lifecycle fan-out", () => {
    expect(
      run({
        "apps/desktop/src-tauri/src/db/issue_states.rs":
          "reconcile_reobserved_lifecycle(tx, project_id, env_url, observed_at, check_ids);\nLIKE 'code_scan.%:%'",
      }).join("\n"),
    ).toContain("without location fan-out");
  });
});

describe("orderedBefore", () => {
  it("holds only when both markers exist and the first precedes the second", () => {
    expect(orderedBefore("rate limit; then auth", "rate", "auth")).toBe(true);
    expect(orderedBefore("auth; then rate limit", "rate", "auth")).toBe(false);
  });

  it("returns false when either marker is absent (no -1 vacuous pass)", () => {
    expect(orderedBefore("only auth here", "rate", "auth")).toBe(false);
    expect(orderedBefore("only rate here", "rate", "auth")).toBe(false);
    expect(orderedBefore("neither present", "rate", "auth")).toBe(false);
  });

  it("does not let a YAML comment forge a marker's position", () => {
    // "rate" only appears for real after "auth"; a comment mentioning it
    // earlier must not let indexOf report the forged, earlier position.
    const forged = "# rate limit already handled\nauth runs\nrate limit runs for real";
    expect(orderedBefore(forged, "rate", "auth")).toBe(false);

    // A marker that appears only inside a comment does not count at all.
    const commentOnly = "# auth happens here\nrate limit runs for real";
    expect(orderedBefore(commentOnly, "rate", "auth")).toBe(false);
  });
});

describe("deployWorkflowHardeningFailures", () => {
  const WF = ".github/workflows/deploy-example.yml";
  const hardened = [
    "on:",
    "  push:",
    "    paths:",
    `      - "apps/example/**"`,
    `      - "${WF}"`,
    "  workflow_dispatch:",
    "concurrency:",
    "  group: deploy-example-${{ github.ref }}",
    "  cancel-in-progress: true",
    "jobs:",
    "  deploy:",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 15",
    "    steps:",
    "      - run: pnpm exec wrangler deploy",
    "  notify-failure:",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 5",
  ].join("\n");
  const run = (source) => deployWorkflowHardeningFailures(() => source, [WF]);

  it("passes the fully hardened workflow and ignores non-deploy workflows", () => {
    expect(run(hardened)).toEqual([]);
    expect(run("jobs:\n  test:\n    runs-on: ubuntu-latest\n")).toEqual([]);
  });

  it("fires when the concurrency group or cancel-in-progress is dropped", () => {
    const regressed = hardened.replace("  cancel-in-progress: true\n", "");
    expect(run(regressed).join("\n")).toContain("concurrency group");
  });

  it("fires when any job loses its timeout-minutes", () => {
    const regressed = hardened.replace("    timeout-minutes: 15\n", "");
    expect(run(regressed).join("\n")).toContain("timeout-minutes on every job");
  });

  it("fires when the workflow_dispatch recovery trigger is dropped", () => {
    const regressed = hardened.replace("  workflow_dispatch:\n", "");
    expect(run(regressed).join("\n")).toContain("workflow_dispatch");
  });

  it("fires when the workflow stops watching its own file in paths", () => {
    const regressed = hardened.replace(`      - "${WF}"\n`, "");
    expect(run(regressed).join("\n")).toContain("watch its own workflow file");
  });
});

describe("workflowSafetyFailures", () => {
  const RUST_WF = ".github/workflows/rust-example.yml";
  const CI = ".github/workflows/ci.yml";
  const ciSource = realRead(CI);

  const run = (rustSource, currentCi = ciSource) =>
    workflowSafetyFailures(
      (file) => (file === CI ? currentCi : file === RUST_WF ? rustSource : realRead(file)),
      () => [RUST_WF, CI],
      { exported: exportedTree },
    );

  it("passes a compiling workflow that provides the resource path", () => {
    const source = [
      "steps:",
      "  - run: mkdir -p apps/mcp-server/dist-bundle",
      "  - run: cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml",
    ].join("\n");
    expect(run(source)).toEqual([]);
  });

  it("ignores workflows that do not compile the desktop crate", () => {
    expect(run("steps:\n  - run: pnpm test")).toEqual([]);
  });

  it("rejects an MSRV job that stops compiling on Rust 1.95", () => {
    const floating = ciSource.replace("cargo +1.95.0 check", "cargo +stable check");
    expect(run("", floating).join("\n")).toContain("Rust MSRV");
  });

  it("rejects a conditional static job", () => {
    const conditional = ciSource.replace(
      "    name: Static checks\n",
      "    name: Static checks\n    if: github.event_name == 'merge_group'\n",
    );
    expect(run("", conditional).join("\n")).toContain(
      "Repository guardrails must run on every pull request",
    );
  });

  it("rejects static checks that stop validating workflow syntax", () => {
    const withoutWorkflowValidation = ciSource.replace(
      "run: pnpm run workflows:check",
      "run: pnpm test",
    );
    expect(run("", withoutWorkflowValidation).join("\n")).toContain(
      "validate workflows and the public installer",
    );
  });

  it("rejects workspace clippy that drops Linux coverage", () => {
    const job = exportedTree ? "rust-tests" : "clippy";
    const pattern = new RegExp(
      `(\n {2}${job}:\n {4}name:[^\n]+\n {4}if:[^\n]+\n {4}runs-on:) ubuntu-26\\.04`,
    );
    const macos = ciSource.replace(pattern, "$1 macos-26");
    expect(run("", macos)).toContain(
      "ci.yml must run workspace clippy on Linux in the merge queue.",
    );
  });
});
