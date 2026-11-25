import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  liveRepositoryProtectionFailures,
  ownedRepositoryReferences,
  readLiveRepositoryProtection,
  repositoryNameFailures,
  requiredCheckWorkflowFailures,
  selectRepositoryProtectionContract,
} from "./lib/repository-protection-rules.mjs";

const configured = JSON.parse(
  readFileSync(new URL("../../.github/repository-protection.json", import.meta.url), "utf8"),
);
const publicSlug = "brambleworks/SiteCMD-Local";
const engineSlug = "brambleworks/SiteCMD-Engine";
const publicChecks = [{ context: "CI", integration_id: 15368 }];
const queueParameters = {
  merge_method: "SQUASH",
  grouping_strategy: "ALLGREEN",
  max_entries_to_build: 5,
  min_entries_to_merge: 1,
  max_entries_to_merge: 5,
  min_entries_to_merge_wait_minutes: 0,
  check_response_timeout_minutes: 60,
};
const branchRules = [
  "deletion",
  "non_fast_forward",
  "required_linear_history",
  "required_signatures",
  "pull_request",
  "required_status_checks",
  "merge_queue",
];

it.each([
  [publicSlug, publicChecks],
  [engineSlug, [{ context: "CI", integration_id: 15368 }]],
  ["contributor/SiteCMD-Local", publicChecks],
])("selects %s's required checks", (checkout, checks) => {
  expect(selectRepositoryProtectionContract(configured, checkout)).toMatchObject({
    repository: checkout === engineSlug ? engineSlug : publicSlug,
    branchRuleset: { requiredStatusChecks: checks },
  });
});

it.each([
  [publicSlug, true],
  [engineSlug, false],
])("reads live settings only for %s", (slug, reportsVulnerabilities) => {
  const endpoints = [];
  const prefix = `repos/${slug}`;
  const payloads = {
    [prefix]: { allow_squash_merge: true, allow_merge_commit: false, allow_rebase_merge: false },
    [`${prefix}/rulesets`]: [{ id: 14 }],
    [`${prefix}/rulesets/14`]: { name: "protect-main" },
    [`${prefix}/private-vulnerability-reporting`]: { enabled: true },
  };
  const contract = selectRepositoryProtectionContract(configured, slug);
  const settings = readLiveRepositoryProtection(contract, (endpoint) => {
    endpoints.push(endpoint);
    return payloads[endpoint];
  });
  expect(endpoints).toEqual([
    prefix,
    `${prefix}/rulesets`,
    `${prefix}/rulesets/14`,
    ...(reportsVulnerabilities ? [`${prefix}/private-vulnerability-reporting`] : []),
  ]);
  expect(settings).toMatchObject({
    mergeMethods: ["squash"],
    rulesets: [{ name: "protect-main" }],
  });
});

function liveEngine() {
  return {
    privateVulnerabilityReporting: true,
    mergeMethods: ["squash"],
    rulesets: [
      {
        name: "protect-main",
        target: "branch",
        enforcement: "active",
        bypass_actors: [],
        conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
        rules: [
          ...branchRules.slice(0, 4).map((type) => ({ type })),
          {
            type: "pull_request",
            parameters: {
              allowed_merge_methods: ["squash"],
              required_approving_review_count: 0,
              required_review_thread_resolution: true,
            },
          },
          {
            type: "required_status_checks",
            parameters: { required_status_checks: [{ context: "CI", integration_id: 15368 }] },
          },
          { type: "merge_queue", parameters: { ...queueParameters } },
        ],
      },
    ],
  };
}

function engineFailures(change = () => {}) {
  const live = liveEngine();
  change(live, live.rulesets[0]);
  const engine = selectRepositoryProtectionContract(configured, engineSlug);
  return liveRepositoryProtectionFailures(engine, live);
}

it("accepts the engine ruleset target", () => {
  expect(engineFailures()).toEqual([]);
});

it.each(branchRules)("requires the engine %s rule", (type) => {
  expect(
    engineFailures((_, branch) => {
      branch.rules = branch.rules.filter((rule) => rule.type !== type);
    }),
  ).toContain(`ruleset "protect-main" is missing the ${type} rule.`);
});

it.each(
  Object.entries({
    merge_method: "MERGE",
    grouping_strategy: "HEADGREEN",
    max_entries_to_build: 4,
    min_entries_to_merge: 2,
    max_entries_to_merge: 6,
    min_entries_to_merge_wait_minutes: 1,
    check_response_timeout_minutes: 59,
  }),
)("rejects a changed engine queue parameter %s", (field, value) => {
  expect(
    engineFailures((_, branch) => {
      branch.rules.find(({ type }) => type === "merge_queue").parameters[field] = value;
    }),
  ).toContainEqual(expect.stringContaining(`merge_queue.${field}`));
});

it.each([
  ["allowed_merge_methods", ["squash", "merge"]],
  ["required_approving_review_count", 1],
  ["required_review_thread_resolution", false],
])("rejects a changed engine pull request parameter %s", (field, value) => {
  expect(
    engineFailures((_, branch) => {
      branch.rules.find(({ type }) => type === "pull_request").parameters[field] = value;
    }),
  ).toContainEqual(expect.stringContaining(`pull_request.${field}`));
});

it("rejects extra engine status checks and repository merge methods", () => {
  const failures = engineFailures((live, branch) => {
    live.mergeMethods.push("merge");
    branch.rules
      .find(({ type }) => type === "required_status_checks")
      .parameters.required_status_checks.push({ context: "Audit" });
  });
  expect(failures).toContain('ruleset "protect-main" also requires "Audit".');
  expect(failures).toContain("Repository merge methods are [merge, squash]; expected [squash].");
});

it.each([
  [42, "42"],
  [undefined, "unrestricted"],
])("rejects a live CI check with integration %s", (integrationId, label) => {
  expect(
    engineFailures((_, branch) => {
      const checks = branch.rules.find(({ type }) => type === "required_status_checks");
      checks.parameters.required_status_checks[0].integration_id = integrationId;
    }),
  ).toContain(`ruleset "protect-main" requires "CI" from integration ${label}; expected 15368.`);
});

it("rejects engine bypass actors", () => {
  expect(engineFailures((_, branch) => branch.bypass_actors.push({ actor_id: 1 }))).toContainEqual(
    expect.stringContaining("grants bypass actors"),
  );
});

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
  ".github/workflows/tooling-quality.yml": [
    "name: tooling-quality",
    "",
    "on:",
    "  pull_request:",
    "    branches: [main]",
    "  merge_group:",
    "    types: [checks_requested]",
    "",
    "jobs:",
    "  check:",
    "    name: Tooling quality gates",
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

  it.each([
    [{ context: "CI", integration_id: 42 }, "42"],
    ["CI", "none"],
  ])("rejects an engine check without the GitHub Actions pin (%j)", (check, actual) => {
    const engine = selectRepositoryProtectionContract(configured, engineSlug);
    engine.branchRuleset = { ...engine.branchRuleset, requiredStatusChecks: [check] };
    const source = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
    expect(
      requiredCheckWorkflowFailures(
        engine,
        () => source,
        () => [".github/workflows/ci.yml"],
      ),
    ).toContain(
      `required check "CI" must pin integration_id 15368 for GitHub Actions; found ${actual}.`,
    );
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
        branchRuleset: {
          ...contract.branchRuleset,
          requiredStatusChecks: ["Tooling quality gates"],
        },
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
    expect(repositoryNameFailures(configured, clean())).toEqual([]);
  });

  it("reports a checkout the contract has not caught up with", () => {
    const failures = repositoryNameFailures(configured, {
      ...clean(),
      checkoutRepository: "brambleworks/SiteCMD-app",
    });
    expect(failures.join("\n")).toContain(
      "this checkout belongs to brambleworks/SiteCMD-app but .github/repository-protection.json names brambleworks/SiteCMD-Local",
    );
  });

  it("accepts a checkout of the private source the public tree is exported from", () => {
    // Bug: the engine checkout fails every gate because its origin names the private source.
    expect(
      repositoryNameFailures(configured, {
        ...clean(),
        checkoutRepository: "brambleworks/SiteCMD-Engine",
      }),
    ).toEqual([]);
    expect(
      repositoryNameFailures(configured, {
        ...clean(),
        checkoutRepository: "brambleworks/SiteCMD-app",
      }),
    ).toHaveLength(1);
  });

  it("says nothing about a fork, which owns neither the contract nor the name", () => {
    expect(
      repositoryNameFailures(configured, {
        ...clean(),
        checkoutRepository: "contributor/SiteCMD-Local",
      }),
    ).toEqual([]);
  });

  it("checks nothing about the checkout when nothing names it", () => {
    expect(repositoryNameFailures(configured, { ...clean(), checkoutRepository: null })).toEqual(
      [],
    );
  });

  it("reports the two contracts disagreeing", () => {
    const failures = repositoryNameFailures(configured, {
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
    const failures = repositoryNameFailures(configured, observed);
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
        { ...configured, referencedRepositories: ["brambleworks/SiteCMD-Web"] },
        observed,
      ),
    ).toEqual([]);
  });
});
