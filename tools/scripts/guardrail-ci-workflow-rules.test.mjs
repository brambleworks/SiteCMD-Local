import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { describe, expect, it } from "vitest";

import { ciWorkflowFailures } from "./lib/guardrail-ci-workflow-rules.mjs";
import { ENGINE_PATHS } from "./lib/publication-history-rules.mjs";
import { mustMutate } from "./guardrail-test-support.mjs";

import {
  children,
  readWorkflow,
  scalar,
  sequence,
  workflowFields,
  workflowSteps,
} from "./lib/guardrail-workflow-yaml.mjs";

const directory = ".github/workflows";
const ci = `${directory}/ci.yml`;
const enginePin = `${directory}/module-pin.yml`;
const read = (file) => readFileSync(file, "utf8");
const list = (dir, filter) =>
  readdirSync(dir)
    .map((file) => `${dir}/${file}`)
    .filter(filter);

describe("CI workflow guardrails", () => {
  it("requires ci.yml in this repository", () => {
    expect(
      ciWorkflowFailures(
        (file) => (file === ci ? "" : read(file)),
        (dir, filter) => list(dir, filter).filter((file) => file !== ci),
        { exported: true },
      ),
    ).toContain("Missing .github/workflows/ci.yml.");
  });

  it("requires release.yml in the public repository", () => {
    const release = `${directory}/release.yml`;
    expect(
      ciWorkflowFailures(
        read,
        (dir, filter) => list(dir, filter).filter((file) => file !== release),
        { exported: true },
      ),
    ).toContain("Missing .github/workflows/release.yml.");
  });

  it("requires module-pin.yml in the public repository", () => {
    expect(
      ciWorkflowFailures(
        read,
        (dir, filter) => list(dir, filter).filter((file) => file !== enginePin),
        { exported: true },
      ),
    ).toContain("Missing .github/workflows/module-pin.yml.");
  });
});

const inventory = ".github/ci-inventory.json";

function fixture(changes = {}) {
  const files = new Set([
    ...list(directory, (file) => /\.ya?ml$/.test(file)),
    ...Object.keys(changes).filter((file) => file.startsWith(directory)),
  ]);
  return ciWorkflowFailures(
    (file) => (Object.hasOwn(changes, file) ? changes[file] : read(file)),
    (_, filter) => [...files].filter(filter),
    { exported: true },
  );
}

function changeJson(file, change) {
  const data = JSON.parse(read(file));
  change(data);
  return fixture({ [file]: JSON.stringify(data) });
}

it("accepts the repository workflows and inventory", () => {
  expect(fixture()).toEqual([]);
});

it("checks the profiles an additional workflow passes to nextest", () => {
  const config = "apps/desktop/src-tauri/.config/nextest.toml";
  const workflow = [
    "on: workflow_dispatch",
    "jobs:",
    "  test:",
    "    steps:",
    "      - run: |",
    "          cargo +stable nextest run \\",
    "            --profile 'ci'",
    "          cargo llvm-cov nextest --profile=coverage",
    "          cargo build --profile release",
    "          cargo nextest run -- --profile test-argument",
  ].join("\n");
  const failures = fixture({
    [`${directory}/example.yml`]: workflow,
    [config]: '[profile."ci"]\n# [profile.coverage]\n[profile.coverage.junit]\n',
  });
  expect(failures).toEqual([
    `example.yml uses nextest profile coverage, but ${config} has no [profile.coverage] table.`,
  ]);
});

it.each([
  [
    "branches: [main]",
    "branches: [other]",
    "must run on pull requests and engine.lock pushes to main",
  ],
  [
    "github.event.pull_request.head.repo.full_name == github.repository",
    "true",
    "must skip fork pull requests",
  ],
  [
    "prefix-key: ${{ matrix.prefix }}",
    "prefix-key: different",
    "must restore the warm-engine-pin caches",
  ],
  [
    "run: pnpm engine:fetch",
    "run: echo skipped",
    "must fetch the pinned engine, build the CLI, and verify the embedded pin in order",
  ],
])("rejects engine pin workflow drift from %s", (before, after, diagnostic) => {
  expect(fixture({ [enginePin]: mustMutate(read(enginePin), before, after) }).join("\n")).toContain(
    `module-pin.yml ${diagnostic}`,
  );
});

it.each([
  [
    "workflow",
    "CARGO_PROFILE_TEST_DEBUG",
    (source, name) => source.replace(`  ${name}: "0"`, `  ${name}: "2"`),
  ],
  [
    "job",
    "CARGO_INCREMENTAL",
    (source, name) => source.replace("    steps:\n", `    env:\n      ${name}: "0"\n    steps:\n`),
  ],
  [
    "cache step",
    "CARGO_NET_OFFLINE",
    (source, name) =>
      source.replace(
        "          save-if: false\n",
        `          save-if: false\n        env:\n          ${name}: "true"\n`,
      ),
  ],
  [
    "environment file before restore",
    "CARGO_BUILD_JOBS",
    (source, name) =>
      source.replace(
        "      - name: Rust cache\n",
        `      - run: echo "${name}=8" >> "$GITHUB_ENV"\n      - name: Rust cache\n`,
      ),
  ],
])("rejects %s environment drift in the shared Rust cache", (_, name, change) => {
  const manual = `${directory}/manual.yml`;
  expect(fixture({ [manual]: change(read(manual), name) })).toContainEqual(
    expect.stringMatching(new RegExp(`rust-cache.*ci-dependencies.*${name}`)),
  );
});

it.each(["cargo-audit", "cargo-audit@latest", "cargo-audit@0.19"])(
  "rejects the tool version %s in another workflow",
  (tool) => {
    const file = directory + "/dependency-audit.yml";
    const source = [
      "on: workflow_dispatch",
      "jobs:",
      "  advisories:",
      "    steps:",
      "      - uses: taiki-e/install-action@68a389c788b2cd04016ce8c80ee23b80d2ab3d68 # v2.88.1",
      "        with:",
      `          tool: ${tool}`,
    ].join("\n");
    expect(fixture({ [file]: source })).toContain(
      `${file} job advisories must pin each taiki-e/install-action tool to an exact version: ${tool}.`,
    );
  },
);

it.each([
  ["rust", "install the pinned Rust toolchain"],
  ["fetch", "run cargo fetch --locked for apps/desktop/src-tauri"],
])("requires guardrail test setup when %s comes later", (lateStep, expected) => {
  const file = directory + "/tooling-quality.yml";
  const rust = [
    "      - working-directory: apps/desktop/src-tauri",
    "        run: |",
    "          rustc --version",
    "          rustup default \"$(rustup show active-toolchain | cut -d ' ' -f 1)\"",
  ];
  const fetch = [
    "      - working-directory: apps/desktop/src-tauri",
    "        run: cargo fetch --locked",
  ];
  const test = [
    "      - run: |",
    "          pnpm guardrails:repo",
    "          pnpm guardrails:repo:test",
  ];
  const steps = lateStep === "rust" ? [...fetch, ...test, ...rust] : [...rust, ...test, ...fetch];
  const source = ["on: workflow_dispatch", "jobs:", "  check:", "    steps:", ...steps].join("\n");
  expect(fixture({ [file]: source })).toContain(
    `${file} job check must ${expected} before running guardrail tests.`,
  );
});

const rustSetup = [
  "      - working-directory: apps/desktop/src-tauri",
  "        run: |",
  "          rustc --version",
  "          rustup default \"$(rustup show active-toolchain | cut -d ' ' -f 1)\"",
];
const lockedFetch = [
  "      - working-directory: apps/desktop/src-tauri",
  "        run: cargo fetch --locked",
];
const rustCache = [
  "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3",
];
const nodeBuild = ["      - run: node tools/scripts/build-standin.mjs"];

function rustJob(steps, changes = {}) {
  const source = [
    "on: workflow_dispatch",
    "jobs:",
    "  hosted-checks:",
    "    steps:",
    ...steps,
  ].join("\n");
  return fixture({ ...changes, [ci]: source }).filter((failure) =>
    failure.startsWith(`${ci} job hosted-checks must`),
  );
}

it.each([
  "cargo check --locked",
  "rustc --print cfg",
  "if cargo check --locked; then echo ok; fi",
  "node tools/scripts/build-standin.mjs",
  "env CI=true pnpm exec node tools/scripts/build-standin.mjs",
  "npx --yes node tools/scripts/build-standin.mjs",
  "node tools/scripts/cli-smoke.mjs",
  "node tools/scripts/audit/check-rust-toolchain.mjs",
  "pnpm run legal:check",
  "pnpm --filter example run legal:check",
  "pnpm run --silent legal:check",
  "npm run-script legal:check",
  "pnpm run build:rust",
  "pnpm run build-rust",
  "output=`env CI=true cargo metadata`",
])("requires pinned Rust setup and fetch for %s", (command) => {
  const run = `      - run: ${command}`;
  expect(rustJob([run])).toContainEqual(
    expect.stringContaining("install the pinned Rust toolchain"),
  );
  expect(rustJob([...rustSetup, ...rustCache, ...lockedFetch, run])).toEqual([]);
});

function spawnsRust(file, source) {
  const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  function visit(node) {
    if (ts.isCallExpression(node)) {
      const callee = ts.isPropertyAccessExpression(node.expression)
        ? node.expression.name
        : node.expression;
      const command = node.arguments[0];
      if (
        ts.isIdentifier(callee) &&
        /^(?:execFileSync|spawnSync|spawn|execSync)$/.test(callee.text) &&
        command &&
        ts.isStringLiteralLike(command) &&
        (callee.text === "execSync" ? /^(?:cargo|rustc)(?:\s|$)/ : /^(?:cargo|rustc)$/).test(
          command.text,
        )
      ) {
        return true;
      }
    }
    return ts.forEachChild(node, visit);
  }
  return Boolean(visit(tree));
}

function unlistedRustScripts(sources) {
  return [...sources]
    .filter(([file, source]) => spawnsRust(file, source))
    .map(([file]) => file)
    .filter((file) => rustJob([`      - run: node ${file}`]).length === 0);
}

it("requires a Rust setup entry for every tracked tools script that spawns Cargo or rustc", () => {
  const files = execFileSync("git", ["ls-files", "-z", "--", "tools/*.mjs"], {
    encoding: "utf8",
  })
    .split("\0")
    .filter((file) => file && existsSync(file));
  expect.soft(unlistedRustScripts(files.map((file) => [file, read(file)]))).toEqual([]);

  const missing = "tools/unlisted-rust-builder.mjs";
  const harmless = "tools/javascript-only.mjs";
  for (const source of [
    'execFileSync("rustc", ["--version"]);',
    "spawnSync('cargo', ['metadata']);",
    'childProcess.spawn("cargo", ["test"]);',
    "execSync(`cargo build`);",
  ]) {
    expect(
      unlistedRustScripts([
        [missing, source],
        [harmless, `const example = 'spawn("cargo")'; spawn("echo", ["cargo"]);`],
      ]),
    ).toEqual([missing]);
  }
});

it("requires Rust setup for a package alias that delegates to a Rust builder", () => {
  const packages = JSON.parse(read("package.json"));
  packages.scripts["check:engine"] = "pnpm run build:engine";
  packages.scripts["build:engine"] = "node tools/scripts/build-standin.mjs";
  const changes = { "package.json": JSON.stringify(packages) };
  const run = "      - run: pnpm run check:engine";
  expect(rustJob([run], changes)).toContainEqual(
    expect.stringContaining("install the pinned Rust toolchain"),
  );
  expect(rustJob([...rustSetup, ...lockedFetch, run], changes)).toEqual([]);
});

it("allows a JavaScript-only job without Rust setup", () => {
  expect(
    rustJob(["      - run: pnpm run lint", "      - run: node tools/scripts/pr-title.mjs"]),
  ).toEqual([]);
});

it.each([
  ["missing", [...rustSetup, ...nodeBuild]],
  ["before Rust", [...lockedFetch, ...rustSetup, ...nodeBuild]],
  ["before cache restore", [...rustSetup, ...lockedFetch, ...rustCache, ...nodeBuild]],
  ["after Node", [...rustSetup, ...nodeBuild, ...lockedFetch]],
  [
    "after a Node substitution",
    [...rustSetup, "      - run: cpus=$(node capacity.mjs)", ...lockedFetch],
  ],
  ["after Cargo", [...rustSetup, "      - run: cargo check --locked", ...lockedFetch]],
  ["after pnpm", [...rustSetup, "      - run: pnpm install --frozen-lockfile", ...lockedFetch]],
  ["after npx", [...rustSetup, "      - run: npx prettier --check .", ...lockedFetch]],
  [
    "after an env-prefixed command",
    [...rustSetup, "      - run: env CI=true node check.mjs", ...lockedFetch],
  ],
  [
    "after a command in backticks",
    [...rustSetup, "      - run: result=`node capacity.mjs`", ...lockedFetch],
  ],
  ["in the wrong directory", [...rustSetup, "      - run: cargo fetch --locked", ...nodeBuild]],
  ["conditional", [...rustSetup, ...lockedFetch, "        if: false", ...nodeBuild]],
  [
    "allowed to fail",
    [...rustSetup, ...lockedFetch, "        continue-on-error: true", ...nodeBuild],
  ],
])("rejects a Rust job whose locked fetch is %s", (_, steps) => {
  const source = [
    "on: workflow_dispatch",
    "jobs:",
    "  hosted-checks:",
    "    steps:",
    ...steps,
  ].join("\n");
  expect(fixture({ [ci]: source })).toContain(
    `${ci} job hosted-checks must run cargo fetch --locked for apps/desktop/src-tauri after toolchain and Rust cache setup and before other Cargo or Node commands.`,
  );
});

it("requires one inventory row for each pinned verify-push step", () => {
  expect(
    changeJson(inventory, (rows) =>
      rows.splice(
        rows.findIndex(({ check }) => check === "lint"),
        1,
      ),
    ),
  ).toContain("verify-push step lint has no inventory row.");
});

it("rejects inventory references to jobs that no longer exist", () => {
  expect(
    changeJson(inventory, (rows) => {
      rows.find(({ check }) => check === "ci-verdict").job = "retired";
    }),
  ).toEqual(
    expect.arrayContaining([
      expect.stringContaining("names unknown ci.yml job retired"),
      expect.stringContaining("ci.yml job CI has no inventory row"),
    ]),
  );
});

it("requires an inventory row for the public CodeQL job", () => {
  expect(
    changeJson(inventory, (rows) => {
      rows.find(({ check }) => check === "codeql").job = "retired";
    }),
  ).toContain("ci.yml job codeql has no inventory row.");
  expect(
    changeJson(inventory, (rows) => {
      rows.find(({ check }) => check === "lint").job = "none";
    }),
  ).toEqual(expect.arrayContaining([expect.stringContaining("unknown ci.yml job none")]));
});

it("requires PR and merge-group triggers without paths", () => {
  const source = read(ci);
  expect(
    fixture({ [ci]: source.replace("  merge_group:\n    types: [checks_requested]\n", "") }),
  ).toContain("ci.yml must trigger on merge_group.");
  for (const key of ["paths", "paths-ignore"]) {
    expect(
      fixture({
        [ci]: source.replace("  pull_request:\n", `  pull_request:\n    ${key}: [docs/**]\n`),
      }),
    ).toContain("ci.yml must not use trigger path filters.");
  }
});

it("has CI wait for every job and pass every result to an unconditional verdict", () => {
  const source = read(ci);
  expect(fixture({ [ci]: source.replace(/^ {6}- static\n/m, "") })).toContain(
    "CI needs every other job in ci.yml exactly once.",
  );
  expect(fixture({ [ci]: source.replace("if: always()", "if: success()") })).toEqual(
    expect.arrayContaining([expect.stringContaining("CI must run with if: always()")]),
  );
  expect(fixture({ [ci]: source.replace("toJSON(needs)", "toJSON(needs.static)") })).toEqual(
    expect.arrayContaining([expect.stringContaining("with the results of every needed job")]),
  );
  expect(
    fixture({
      [ci]: source.replace(
        "allowed-skips: >-",
        "allowed-failures: static\n          allowed-skips: >-",
      ),
    }),
  ).toEqual(expect.arrayContaining([expect.stringContaining("without allowed-failures")]));
});

it("requires actual skip conditions and rejects ungated queue jobs", () => {
  const source = read(ci);
  expect(
    fixture({ [ci]: source.replace("    if: github.event_name == 'pull_request'\n", "") }),
  ).toContain("CI allowed skip pr-title must be gated on pull_request.");
  expect(
    fixture({
      [ci]: source.replace(
        "    if: github.event_name == 'merge_group' || github.event_name == 'workflow_dispatch'\n",
        "",
      ),
    }),
  ).toContain("CI allowed skips must match the event and engine pin path result.");
});

it.each(["pull_request", "pull_request_target", "merge_group", "push"])(
  "rejects an unlisted workflow with a %s trigger",
  (event) => {
    const file = `${directory}/other.yml`;
    expect(fixture({ [file]: `"on": ["${event}"]\n` })).toContain(
      `other.yml must not trigger on ${event}.`,
    );
  },
);

it.each(["cargo test --workspace", "pnpm --filter example run test"])(
  "rejects %s in the caching workflow",
  (command) => {
    const file = `${directory}/cache.yml`;
    expect(
      fixture({ [file]: read(file).replace("pnpm install --frozen-lockfile", command) }),
    ).toContain("cache.yml must not run tests.");
  },
);

it("rejects Cargo tests in both single-line and block list-item steps in cache.yml", () => {
  const file = `${directory}/cache.yml`;
  const setup = "      - name: Install dependencies\n        run: pnpm install --frozen-lockfile";
  const mutations = ["      - run: cargo test", "      - run: |\n          cargo test --workspace"];
  const failures = mutations.map((step) => fixture({ [file]: read(file).replace(setup, step) }));
  expect(failures).toEqual(
    mutations.map(() => expect.arrayContaining(["cache.yml must not run tests."])),
  );
});

it.each([
  ["pr-title.mjs", "03627b5e5fb12780a1426dbe023de53f10fb02bd1d9cb003d0fe727fc0edb895"],
  ["pr-title.test.mjs", "c2695dd41b93f0b5c4961088c08a4b9804dcc014175740c1ed25411c6721839c"],
])("keeps the shared %s byte-for-byte", (file, digest) => {
  const source = readFileSync(new URL(`../scripts/${file}`, import.meta.url));
  expect(createHash("sha256").update(source).digest("hex")).toBe(digest);
});

const publicRepository = "brambleworks/SiteCMD-Local";
const skipCases = [
  ["pull_request", "false"],
  ["pull_request", "true"],
  ["pull_request", ""],
  ["workflow_dispatch", "false"],
  ["workflow_dispatch", ""],
  ["merge_group", "false"],
  ["merge_group", "true"],
  ["merge_group", ""],
];
it.each(
  [publicRepository, "example/cli-fork"].flatMap((repository) =>
    skipCases.map((scenario) => [repository, ...scenario]),
  ),
)(
  "evaluates %s allowed skips for %s with dependencies %j",
  (repository, event_name, dependencies) => {
    const jobs = children(workflowFields(read(ci)).get("jobs"));
    const aggregator = children(jobs.get("CI"));
    const input = scalar(
      children(workflowSteps(aggregator.get("steps"))[0].get("with")).get("allowed-skips"),
    );
    const resolved = input.replace(/\$\{\{(.*?)\}\}/gs, (_, condition) =>
      runInNewContext(
        condition.replaceAll("needs.dependency-paths", 'needs["dependency-paths"]'),
        {
          github: { event_name, repository },
          needs: {
            "dependency-paths": { outputs: { dependencies } },
          },
        },
        { timeout: 100 },
      ),
    );
    const allowed = resolved
      .split(",")
      .map((job) => job.trim())
      .filter(Boolean);
    for (const job of sequence(aggregator.get("needs"))) {
      const condition = scalar(children(jobs.get(job)).get("if"));
      let maySkip = condition?.includes("merge_group") && event_name === "pull_request";
      if (job === "pr-title") maySkip = event_name !== "pull_request";
      if (job === "public-tree")
        maySkip = event_name !== "pull_request" || repository !== publicRepository;
      if (job === "dependency-audit")
        maySkip = event_name !== "workflow_dispatch" && dependencies !== "true";
      expect(allowed.includes(job), job).toBe(Boolean(maySkip));
      for (const result of ["failure", "cancelled", "skipped"]) {
        const verdict = result === "skipped" && allowed.includes(job);
        expect(verdict, job + ": " + result).toBe(result === "skipped" && Boolean(maySkip));
      }
    }
  },
);

it("requires a repository-wide online workflow audit", () => {
  const source = read(ci).replace(
    "run: zizmor --no-progress .\n",
    "run: zizmor --no-progress .github/workflows\n",
  );
  expect(fixture({ [ci]: source })).toContain("ci.yml must run zizmor online against .");
});

it("resolves references to anchored workflow steps across jobs", () => {
  const source = [
    "jobs:",
    "  first:",
    "    steps:",
    "      - &check",
    "        run: pnpm run lint",
    "  second:",
    "    steps:",
    "      - *check",
  ].join("\n");
  expect(readWorkflow(source).jobs.second.steps).toEqual([{ run: "pnpm run lint" }]);
  expect(() => readWorkflow(source.replace("*check", "*unknown"))).toThrow("unknown");
});

it("rejects repeated inventory checks", () => {
  expect(
    changeJson(inventory, (rows) => {
      rows.push(rows.find((row) => row.check === "lint"));
    }),
  ).toContain(".github/ci-inventory.json repeats check lint.");
});

it("requires the inventory command to run in the associated job", () => {
  expect(
    changeJson(inventory, (rows) => {
      rows.find((row) => row.check === "lint").command = "pnpm run format:check";
    }),
  ).toContain("Inventory check lint is missing a command in ci.yml job static.");
});

it("rejects secret references in an open job, including an aliased step", () => {
  // The first checkout step in the text: its uses line and the more deeply
  // indented lines under it. Read by lines, since a nested-quantifier regex
  // fails the repository's regex audit.
  const checkout = (text) => {
    const lines = text.split("\n");
    const start = lines.findIndex((line) => line.startsWith("      - uses: actions/checkout@"));
    if (start === -1) throw new Error("no checkout step");
    let end = start + 1;
    while (end < lines.length && lines[end].startsWith("        ")) end += 1;
    return `${lines.slice(start, end).join("\n")}\n`;
  };
  const workflow = read(ci);
  const step = checkout(workflow);
  const source = workflow.replace(
    step,
    step.replace("      - uses:", "      - &checkout\n        uses:") +
      "        env:\n          TEST_TOKEN: ${{ secrets.TEST_TOKEN }}\n",
  );
  const prTitle = source.indexOf("\n  pr-title:\n");
  const prJob = source.slice(prTitle);
  expect(
    fixture({
      [ci]: source.slice(0, prTitle) + prJob.replace(checkout(prJob), "      - *checkout\n"),
    }),
  ).toContain("Open CI job pr-title must not reference secrets or engine paths.");
});

it("dispatches queue jobs and does not allow CI to overlook them", () => {
  const source = read(ci);
  expect(source).toContain(
    "if: github.event_name == 'merge_group' || github.event_name == 'workflow_dispatch'",
  );
  expect(
    fixture({
      [ci]: source.replace(
        "if: github.event_name == 'merge_group' || github.event_name == 'workflow_dispatch'",
        "if: github.event_name == 'merge_group'",
      ),
    }),
  ).toEqual(expect.arrayContaining([expect.stringContaining("allowed skips")]));
});

it.each([
  ENGINE_PATHS.find((path) => path.startsWith("tools/")),
  ENGINE_PATHS.find((path) => path.includes("/crates/")),
])("rejects engine paths in an open job: %s", (path) => {
  const source = read(ci).replace(
    "    name: PR title and body",
    "    name: PR title and body\n    env:\n      INPUT_PATH: ./" + path + "example",
  );
  expect(fixture({ [ci]: source })).toContain(
    "Open CI job pr-title must not reference secrets or engine paths.",
  );
});

it("rejects the Rust toolchain action in a retained workflow", () => {
  const file = directory + "/example.yml";
  const source = [
    "on: workflow_dispatch",
    "jobs:",
    "  example:",
    "    steps:",
    "      - uses: dtolnay/rust-toolchain@39008827e6b4319a349e9a42dfc90579dd25f1ca # v1.0.0",
  ].join("\n");
  expect(fixture({ [file]: source })).toContain(
    file + " must install Rust with rustup instead of dtolnay/rust-toolchain.",
  );
});

it.each(["", " # v7", " # stable"])(
  "rejects a retained action pin without an exact release tag%j",
  (comment) => {
    const file = directory + "/example.yml";
    const source = [
      "on: workflow_dispatch",
      "jobs:",
      "  example:",
      "    steps:",
      '      - "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"' + comment,
    ].join("\n");
    expect(fixture({ [file]: source })).toContain(
      file + " must pin actions/checkout to a commit with an exact vX.Y.Z release tag comment.",
    );
  },
);

it("requires the checks_requested merge group type", () => {
  expect(
    fixture({
      [ci]: read(ci).replace("types: [checks_requested]", "types: [completed]"),
    }),
  ).toContain("ci.yml must run on merge_group checks_requested.");
});

it("forbids pull_request_target in ci.yml", () => {
  expect(fixture({ [ci]: read(ci).replace("on:\n", "on:\n  pull_request_target:\n") })).toContain(
    "ci.yml must not use pull_request_target.",
  );
});

it.each(["init", "analyze"])("requires CodeQL %s in public CI", (action) => {
  const source = read(ci).replace(`github/codeql-action/${action}@`, "example/action@");
  expect(fixture({ [ci]: source })).toContain(`Public CI must run CodeQL ${action}.`);
});

it("rejects a CodeQL action in another workflow", () => {
  const file = `${directory}/example.yml`;
  const source = [
    "on: workflow_dispatch",
    "jobs:",
    "  scan:",
    "    steps:",
    "      - uses: github/codeql-action/analyze@0123456789012345678901234567890123456789 # v4.1.0",
  ].join("\n");
  expect(fixture({ [file]: source })).toContain("example.yml must run CodeQL in ci.yml.");
});

it.each([
  ["manual.yml", "rust-coverage", "coverage"],
  ["module-pin.yml", "embedded-engine-pin", "verify-pin"],
  ["lefthook.yml", "public-tree", "public-tree"],
])("checks inventory rows against the %s home", (home, check, job) => {
  const indexOfCheck = (rows) => rows.findIndex((row) => row.check === check);
  expect(
    changeJson(inventory, (rows) => {
      rows[indexOfCheck(rows)].job = "retired";
    }),
  ).toContain(`${inventory} names unknown ${home} job retired.`);
  expect(changeJson(inventory, (rows) => rows.splice(indexOfCheck(rows), 1))).toContain(
    `${home} job ${job} has no inventory row.`,
  );
  expect(
    changeJson(inventory, (rows) => {
      rows[indexOfCheck(rows)].command = "echo skipped";
    }),
  ).toContain(`Inventory check ${check} is missing a command in ${home} job ${job}.`);
});

it.each([
  ["use_stdin: true", "use_stdin: false"],
  [".lefthook/pre-push/public-tree.sh", ".lefthook/pre-push/other.sh"],
])("rejects a changed public pre-push hook setting %s", (before, after) => {
  expect(fixture({ "lefthook.yml": read("lefthook.yml").replace(before, after) })).toContain(
    "Inventory check public-tree is missing a command in lefthook.yml job public-tree.",
  );
});

it.each([
  "pnpm-workspace.yaml",
  "THIRD_PARTY_DEPENDENCIES.json",
  "tools/scripts/audit-rust-deps.mjs",
])("requires %s in the dependency paths filter", (file) => {
  const source = read(ci);
  const removed = source.replace(`              - "${file}"\n`, "");
  expect(fixture({ [ci]: removed })).toContain(`CI dependency paths must include ${file}.`);
});

it.each([
  [
    "without a public tree job",
    (source) => source.replace(/^ {2}public-tree:[\s\S]*?(?=^ {2}workflow-lint:)/m, ""),
  ],
  [
    "with a widened public tree condition",
    (source) =>
      source.replace(
        "if: github.event_name == 'pull_request' && github.repository == 'brambleworks/SiteCMD-Local'",
        "if: github.event_name == 'pull_request'",
      ),
  ],
])("rejects CI %s", (_, change) => {
  expect(fixture({ [ci]: change(read(ci)) })).toContain(
    "CI public-tree must run only for SiteCMD-Local pull requests.",
  );
});

it("records the public-tree CI job separately from its pre-push counterpart", () => {
  expect(JSON.parse(read(inventory))).toContainEqual(
    expect.objectContaining({
      check: "public-tree-pr",
      job: "public-tree",
      stages: ["pr"],
      was: "repository-guardrails.yml",
    }),
  );
});

it("keeps the removed cargo-machete job out of CI", () => {
  expect(readWorkflow(read(`${directory}/manual.yml`)).jobs).not.toHaveProperty("cargo-machete");
  expect(
    JSON.parse(read(inventory)).some(({ check }) => check === "unused-rust-dependencies-manual"),
  ).toBe(false);
});

it("keeps CodeQL in CI", () => {
  const { scripts } = JSON.parse(read("package.json"));
  expect(Object.keys(scripts).filter((script) => /codeql/i.test(script))).toEqual([]);
  expect(readdirSync("tools/scripts/audit").filter((file) => /codeql/i.test(file))).toEqual([]);
  expect(read("tools/scripts/verify-push.mjs")).not.toMatch(/codeql/i);
});

it("rejects allowing public-tree to skip on SiteCMD-Local pull requests", () => {
  const source = read(ci).replace(
    /\$\{\{ [^\n]*&& 'public-tree' \|\| '' \}\}/,
    "${{ 'public-tree' }}",
  );
  expect(fixture({ [ci]: source })).toContain(
    "CI allowed skips must match the event and engine pin path result.",
  );
});
