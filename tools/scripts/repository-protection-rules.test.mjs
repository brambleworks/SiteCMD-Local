import { describe, expect, it } from "vitest";

import {
  liveRepositoryProtectionFailures,
  ownedRepositoryReferences,
  repositoryNameFailures,
  requiredCheckWorkflowFailures,
} from "./lib/repository-protection-rules.mjs";

const contract = {
  repository: "brambleworks/SiteCMD-Local",
  privateVulnerabilityReporting: true,
  securityAndAnalysis: {
    secret_scanning: "enabled",
    secret_scanning_push_protection: "enabled",
    secret_scanning_non_provider_patterns: "enabled",
  },
  branchRuleset: {
    name: "protect-main",
    target: "branch",
    refNameInclude: ["refs/heads/main"],
    refNameExclude: [],
    ruleTypes: ["deletion", "non_fast_forward", "required_linear_history", "pull_request"],
    requiredStatusChecks: ["Repository guardrails", "Analyze rust"],
  },
  tagRuleset: {
    name: "protect-release-tags",
    target: "tag",
    refNameInclude: ["refs/tags/v*"],
    refNameExclude: [],
    ruleTypes: ["deletion", "non_fast_forward", "update"],
  },
};

const workflows = {
  ".github/workflows/repository-guardrails.yml": [
    "name: repository-guardrails",
    "",
    "on:",
    "  pull_request:",
    "    types: [opened, synchronize]",
    "  merge_group:",
    "    types: [checks_requested]",
    "",
    "jobs:",
    "  check:",
    "    name: Repository guardrails",
    "    runs-on: ubuntu-latest",
    "",
  ].join("\n"),
  ".github/workflows/codeql.yml": [
    "name: CodeQL",
    "",
    "on:",
    "  pull_request:",
    "  merge_group:",
    "    types: [checks_requested]",
    "",
    "jobs:",
    "  analyze:",
    "    name: Analyze ${{ matrix.language }}",
    "    strategy:",
    "      matrix:",
    "        language:",
    "          - javascript-typescript",
    "          - rust",
    "",
  ].join("\n"),
  ".github/workflows/frontend-quality.yml": [
    "name: frontend-quality",
    "",
    "on:",
    "  pull_request:",
    "    branches: [main]",
    "  merge_group:",
    "    types: [checks_requested]",
    "",
    "jobs:",
    "  check:",
    "    name: Frontend quality",
    "",
  ].join("\n"),
  ".github/workflows/size-limit.yml": [
    "name: size-limit",
    "",
    "on:",
    "  pull_request:",
    "    types:",
    "      - opened",
    "      - reopened",
    "  merge_group:",
    "    types: [checks_requested]",
    "",
    "jobs:",
    "  check:",
    "    name: Bundle size",
    "",
  ].join("\n"),
  ".github/workflows/rust-tests.yml": [
    "name: rust-tests",
    "",
    "on:",
    "  pull_request:",
    "    paths:",
    '      - "apps/desktop/src-tauri/**"',
    "  merge_group:",
    "    types: [checks_requested]",
    "",
    "jobs:",
    "  test:",
    "    name: cargo nextest run",
    "",
  ].join("\n"),
};
const read = (file) => workflows[file];
const listFiles = (dir, predicate) =>
  Object.keys(workflows).filter((file) => file.startsWith(`${dir}/`) && predicate(file));

const liveClean = () => ({
  privateVulnerabilityReporting: true,
  securityAndAnalysis: {
    secret_scanning: { status: "enabled" },
    secret_scanning_push_protection: { status: "enabled" },
    secret_scanning_non_provider_patterns: { status: "enabled" },
  },
  rulesets: [
    {
      name: "protect-main",
      target: "branch",
      conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
      enforcement: "active",
      bypass_actors: [],
      rules: [
        { type: "deletion" },
        { type: "non_fast_forward" },
        { type: "required_linear_history" },
        { type: "pull_request" },
        {
          type: "required_status_checks",
          parameters: {
            required_status_checks: [
              { context: "Repository guardrails" },
              { context: "Analyze rust" },
            ],
          },
        },
      ],
    },
    {
      name: "protect-release-tags",
      target: "tag",
      conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
      enforcement: "active",
      bypass_actors: [],
      rules: [{ type: "deletion" }, { type: "non_fast_forward" }, { type: "update" }],
    },
  ],
});

describe("requiredCheckWorkflowFailures", () => {
  it("accepts checks that every pull request reports", () => {
    expect(requiredCheckWorkflowFailures(contract, read, listFiles)).toEqual([]);
  });

  it("rejects a check no workflow job produces", () => {
    const failures = requiredCheckWorkflowFailures(
      {
        ...contract,
        branchRuleset: { ...contract.branchRuleset, requiredStatusChecks: ["Frontend gates"] },
      },
      read,
      listFiles,
    );
    expect(failures.join("\n")).toContain('"Frontend gates" names no job');
  });

  it("rejects a check from a path-filtered workflow", () => {
    const failures = requiredCheckWorkflowFailures(
      {
        ...contract,
        branchRuleset: { ...contract.branchRuleset, requiredStatusChecks: ["cargo nextest run"] },
      },
      read,
      listFiles,
    );
    expect(failures.join("\n")).toContain("filtered pull_request trigger");
  });

  it("rejects a check from a branch-filtered workflow", () => {
    const failures = requiredCheckWorkflowFailures(
      {
        ...contract,
        branchRuleset: { ...contract.branchRuleset, requiredStatusChecks: ["Frontend quality"] },
      },
      read,
      listFiles,
    );
    expect(failures.join("\n")).toContain("filtered pull_request trigger");
  });

  it("rejects a check whose trigger types omit synchronize", () => {
    const failures = requiredCheckWorkflowFailures(
      {
        ...contract,
        branchRuleset: { ...contract.branchRuleset, requiredStatusChecks: ["Bundle size"] },
      },
      read,
      listFiles,
    );
    expect(failures.join("\n")).toContain("filtered pull_request trigger");
  });
});

describe("liveRepositoryProtectionFailures", () => {
  it("accepts the configured repository", () => {
    expect(liveRepositoryProtectionFailures(contract, liveClean())).toEqual([]);
  });

  it("reports private vulnerability reporting switched off", () => {
    const live = liveClean();
    live.privateVulnerabilityReporting = false;
    expect(liveRepositoryProtectionFailures(contract, live).join("\n")).toContain(
      "Private vulnerability reporting is disabled",
    );
  });

  it("reports a secret-scanning setting that drifted", () => {
    const live = liveClean();
    live.securityAndAnalysis.secret_scanning_push_protection.status = "disabled";
    expect(liveRepositoryProtectionFailures(contract, live).join("\n")).toContain(
      "secret_scanning_push_protection is disabled",
    );
  });

  it("reports a branch ruleset retargeted at tags", () => {
    const live = liveClean();
    live.rulesets[0].target = "tag";
    expect(liveRepositoryProtectionFailures(contract, live).join("\n")).toContain(
      'ruleset "protect-main" targets tag, not branch',
    );
  });

  it("reports a ruleset pointed at a branch the contract does not name", () => {
    const live = liveClean();
    live.rulesets[0].conditions.ref_name.include = ["refs/heads/retired"];
    expect(liveRepositoryProtectionFailures(contract, live).join("\n")).toContain(
      "ref_name.include is [refs/heads/retired]",
    );
  });

  it("reports a ruleset that excludes refs the contract does not", () => {
    const live = liveClean();
    live.rulesets[1].conditions.ref_name.exclude = ["refs/tags/v9*"];
    expect(liveRepositoryProtectionFailures(contract, live).join("\n")).toContain(
      "ref_name.exclude is [refs/tags/v9*]",
    );
  });

  it("reports a missing ruleset, a missing rule, a bypass actor, and a dropped check", () => {
    const live = liveClean();
    live.rulesets[0].rules = live.rulesets[0].rules.filter((rule) => rule.type !== "deletion");
    live.rulesets[0].bypass_actors = [{ actor_id: 5, actor_type: "RepositoryRole" }];
    live.rulesets[0].rules[3].parameters.required_status_checks.pop();
    live.rulesets.pop();
    const failures = liveRepositoryProtectionFailures(contract, live).join("\n");
    expect(failures).toContain('ruleset "protect-release-tags" does not exist');
    expect(failures).toContain('ruleset "protect-main" is missing the deletion rule');
    expect(failures).toContain("grants bypass actors");
    expect(failures).toContain('does not require "Analyze rust"');
  });
});

describe("references to our own repositories", () => {
  it("reads a link, an action ref, and an npm manifest url, with their lines", () => {
    const references = ownedRepositoryReferences("brambleworks", [
      {
        file: "README.md",
        source: [
          "# SiteCMD",
          "Report it at https://github.com/brambleworks/SiteCMD-Local/issues/new.",
          "",
          "      - uses: brambleworks/SiteCMD-Local/.github/actions/setup-sitecmd@abc123",
        ].join("\n"),
      },
      {
        file: "packaging/npm/cli/package.json",
        source: '    "url": "git+https://github.com/brambleworks/SiteCMD-Local.git"',
      },
    ]);
    expect(references).toEqual([
      { file: "README.md", line: 2, slug: "brambleworks/SiteCMD-Local" },
      { file: "README.md", line: 4, slug: "brambleworks/SiteCMD-Local" },
      {
        file: "packaging/npm/cli/package.json",
        line: 1,
        slug: "brambleworks/SiteCMD-Local",
      },
    ]);
  });

  // A neutral owner on purpose: this file is itself scanned by the rule these
  // references feed, and a fixture naming our own owner would read as a
  // reference left behind by a rename.
  it("reads both references on one line and ignores other owners", () => {
    const references = ownedRepositoryReferences("acme", [
      {
        file: "README.md",
        source:
          "[badge](https://github.com/acme/One/actions) and https://github.com/acme/Two " +
          "next to https://github.com/actions/checkout",
      },
    ]);
    expect(references.map(({ slug }) => slug)).toEqual(["acme/One", "acme/Two"]);
  });

  it("sees a reference a regex literal wrote with escaped slashes and dots", () => {
    const references = ownedRepositoryReferences("acme", [
      {
        file: "tools/scripts/lib/guard.mjs",
        source: String.raw`    !/\(https:\/\/github\.com\/acme\/Widget\/security\/advisories\/new\)/.test(text)`,
      },
    ]);
    expect(references).toEqual([
      { file: "tools/scripts/lib/guard.mjs", line: 1, slug: "acme/Widget" },
    ]);
  });
});

describe("the repository the contract names", () => {
  const clean = () => ({
    checkoutRepository: "brambleworks/SiteCMD-Local",
    labelsRepository: "brambleworks/SiteCMD-Local",
    references: [
      { file: "README.md", line: 3, slug: "brambleworks/SiteCMD-Local" },
      { file: "SECURITY.md", line: 18, slug: "brambleworks/SiteCMD-Local" },
    ],
  });

  it("passes when the checkout, the label contract, and every reference agree", () => {
    expect(repositoryNameFailures(contract, clean())).toEqual([]);
  });

  it("reports a checkout the contract has not caught up with", () => {
    const failures = repositoryNameFailures(contract, {
      ...clean(),
      checkoutRepository: "brambleworks/SiteCMD-app",
    });
    expect(failures.join("\n")).toContain(
      "this checkout belongs to brambleworks/SiteCMD-app but .github/repository-protection.json names brambleworks/SiteCMD-Local",
    );
  });

  it("says nothing about a fork, which owns neither the contract nor the name", () => {
    expect(
      repositoryNameFailures(contract, {
        ...clean(),
        checkoutRepository: "contributor/SiteCMD-Local",
      }),
    ).toEqual([]);
  });

  it("checks nothing about the checkout when nothing names it", () => {
    expect(repositoryNameFailures(contract, { ...clean(), checkoutRepository: null })).toEqual([]);
  });

  it("reports the two contracts disagreeing", () => {
    const failures = repositoryNameFailures(contract, {
      ...clean(),
      labelsRepository: "brambleworks/SiteCMD-app",
    });
    expect(failures.join("\n")).toContain(
      ".github/repository-labels.json names brambleworks/SiteCMD-app",
    );
  });

  it("reports a reference left behind by a rename, with its line", () => {
    const observed = clean();
    observed.references.push({
      file: "packaging/npm/cli/package.json",
      line: 8,
      slug: "brambleworks/SiteCMD-app",
    });
    const failures = repositoryNameFailures(contract, observed);
    expect(failures.join("\n")).toContain(
      "packaging/npm/cli/package.json:8 references brambleworks/SiteCMD-app",
    );
  });

  it("allows a sibling repository the contract declares", () => {
    const observed = clean();
    observed.references.push({
      file: "CONTRIBUTING.md",
      line: 11,
      slug: "brambleworks/SiteCMD-Web",
    });
    expect(
      repositoryNameFailures(
        { ...contract, referencedRepositories: ["brambleworks/SiteCMD-Web"] },
        observed,
      ),
    ).toEqual([]);
  });
});
