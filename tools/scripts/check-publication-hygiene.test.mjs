import { describe, expect, it } from "vitest";

import { publicationHygieneFailures } from "./lib/publication-hygiene-rules.mjs";

const REQUIRED = [
  ".env.example",
  ".gitattributes",
  ".github/CODEOWNERS",
  ".github/ISSUE_TEMPLATE/bug_report.yml",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/feature_request.yml",
  ".github/pull_request_template.md",
  ".gitignore",
  ".gitleaks.toml",
  "CHANGELOG.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "install.sh",
  "LICENSE",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "SUPPORT.md",
  "THIRD_PARTY_DEPENDENCIES.json",
  "THIRD_PARTY_LICENSES.txt",
  "THIRD_PARTY_NOTICES",
  "tools/scripts/check-publication-hygiene.mjs",
  "tools/scripts/check-publication-hygiene.test.mjs",
  "tools/scripts/check-publication-history.mjs",
  "tools/scripts/check-publication-history.test.mjs",
  "tools/scripts/prepare-public-history.mjs",
  "tools/scripts/prepare-public-history.test.mjs",
  "tools/scripts/lib/publication-hygiene-rules.mjs",
  "tools/scripts/lib/publication-history-rules.mjs",
];

function fixture(extra = {}, omitted = []) {
  const contents = Object.fromEntries(REQUIRED.map((path) => [path, `${path}\n`]));
  contents[".github/CODEOWNERS"] = "* @brambleworks\n";
  contents["package.json"] = '{"license": "Apache-2.0"}\n';
  contents["apps/mcp-server/package.json"] = '{"license": "Apache-2.0"}\n';
  contents["apps/desktop/src-tauri/Cargo.toml"] = 'license = "Apache-2.0"\n';
  contents["renovate.json"] = JSON.stringify(
    {
      automergeType: "pr",
      platformCommit: "enabled",
      vulnerabilityAlerts: { automerge: false },
      packageRules: [
        {
          description: "Safe tooling updates",
          matchUpdateTypes: ["minor", "patch"],
          automerge: true,
        },
        { matchCurrentVersion: "/^0\\./", automerge: false },
      ],
    },
    null,
    2,
  );
  contents["apps/desktop/src/main.tsx"] = "export {};\n";

  for (const path of omitted) delete contents[path];
  Object.assign(contents, extra);

  const files = Object.entries(contents).map(([path, source]) => ({
    path,
    size: Buffer.byteLength(source),
  }));
  const read = (path) => {
    if (!Object.hasOwn(contents, path)) throw new Error(`missing fixture: ${path}`);
    return contents[path];
  };
  return { files, read };
}

describe("publicationHygieneFailures", () => {
  it("accepts a small professional public snapshot", () => {
    const { files, read } = fixture();
    expect(publicationHygieneFailures(files, read)).toEqual([]);
  });

  it("accepts the committed release tag-signers review mirror", () => {
    const { files, read } = fixture({
      ".github/allowed-signers":
        "admin@brambleworks.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestingOnly sitecmd-release-signing\n",
    });
    expect(publicationHygieneFailures(files, read)).toEqual([]);
  });

  it("rejects generated and private working directories", () => {
    const { files, read } = fixture({
      "planning/superpowers/brainstorm/session.html": "<html></html>\n",
      "artifacts/browser/page.png": "not really a png",
    });
    const failures = publicationHygieneFailures(files, read).join("\n");
    expect(failures).toContain("planning/superpowers/brainstorm/session.html");
    expect(failures).toContain("artifacts/browser/page.png");
  });

  it("rejects agent session directories nested inside an app, not just at the root", () => {
    const { files, read } = fixture({
      "apps/example-worker/.gsd/runtime/write-gate-state.json": "{}\n",
      "apps/desktop/.impeccable/design.json": '{"schemaVersion": 2}\n',
    });
    const failures = publicationHygieneFailures(files, read).join("\n");
    expect(failures).toContain("apps/example-worker/.gsd/runtime/write-gate-state.json");
    expect(failures).toContain("apps/desktop/.impeccable/design.json");
  });

  it("rejects a real home directory in source while allowing fixture placeholders", () => {
    const realHome = `/Users/${"jsmith"}/Projects/app/.env`;
    const { files, read } = fixture({
      "apps/desktop/src/lib/logger.test.ts": `expect(redact("${realHome}"));\n`,
      "apps/desktop/src/lib/paths.test.ts": 'expect(redact("/Users/dev/Projects/app/.env"));\n',
      "tools/benchmark/guest/runtime.mjs":
        'const desktopHome = "/home/sitecmd/projects/session";\n',
    });
    const failures = publicationHygieneFailures(files, read).join("\n");
    expect(failures).toContain(
      "real home directory appears in source: apps/desktop/src/lib/logger.test.ts (jsmith)",
    );
    expect(failures).not.toContain("paths.test.ts");
  });

  it("does not mistake a lowercase /users/ URL path for a home directory", () => {
    const { files, read } = fixture({
      "apps/desktop/src-tauri/src/core/code_scan/route_helpers_tests.rs":
        'let body = "api.patch(\\"/users/profile\\", data)";\n',
      "apps/desktop/src/lib/api.ts": 'export const ME = "/users/settings";\n',
    });
    expect(publicationHygieneFailures(files, read)).toEqual([]);
  });

  it("still rejects a capitalized real home directory beside a /users/ path", () => {
    const realHome = `/Users/${"jsmith"}/Projects/app/.env`;
    const { files, read } = fixture({
      "apps/desktop/src/lib/logger.test.ts": `const url = "/users/profile";\nexpect(redact("${realHome}"));\n`,
    });
    const failures = publicationHygieneFailures(files, read).join("\n");
    expect(failures).toContain(
      "real home directory appears in source: apps/desktop/src/lib/logger.test.ts (jsmith)",
    );
    expect(failures).not.toContain("profile");
  });

  it("does not mistake an ordinary home/ source directory for a home directory", () => {
    const { files, read } = fixture({
      "apps/sitecmd.com/src/styles/pages/home/hero.css": ".hero { color: red; }\n",
      "apps/sitecmd.com/src/lib/routes.ts": 'export const HOME = "src/pages/home/index.astro";\n',
    });
    expect(publicationHygieneFailures(files, read)).toEqual([]);
  });

  it("rejects unexpected root residue", () => {
    const { files, read } = fixture({ "conversation-export.txt": "private notes\n" });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      "unexpected file at repository root: conversation-export.txt",
    );
  });

  it("rejects machine-specific paths in public documentation", () => {
    const { files, read } = fixture({
      "docs/operations/local.md": "Run /Users/example/Projects/tool/script.sh\n",
    });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      "machine-specific absolute path appears in public text: docs/operations/local.md",
    );
  });

  it("rejects a missing repository policy file", () => {
    const { files, read } = fixture({}, ["SECURITY.md"]);
    expect(publicationHygieneFailures(files, read)).toContain(
      "missing required public-repository file: SECURITY.md",
    );
  });

  it("rejects conflicting package license metadata", () => {
    const { files, read } = fixture({ "apps/mcp-server/package.json": '{"license": "MIT"}\n' });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      'open-source package metadata must contain "license": "Apache-2.0": apps/mcp-server/package.json',
    );
  });

  it("rejects a CODEOWNERS file assigned to the wrong account", () => {
    const { files, read } = fixture({ ".github/CODEOWNERS": "* @unavailable-owner\n" });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      "repository ownership must contain @brambleworks: .github/CODEOWNERS",
    );
  });

  it("rejects dependency automation that bypasses pull requests", () => {
    const { files, read } = fixture({
      "renovate.json":
        '{"automergeType": "branch", "platformCommit": "enabled", "automerge": true}\n',
    });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      'dependency automation must not bypass pull requests with "automergeType": "branch": renovate.json',
    );
  });

  it("rejects an auto-merge rule that can match major updates", () => {
    const { read } = fixture();
    const renovate = JSON.parse(read("renovate.json"));
    renovate.packageRules[0].matchUpdateTypes = ["minor", "major"];
    const changed = fixture({ "renovate.json": JSON.stringify(renovate) });
    expect(publicationHygieneFailures(changed.files, changed.read).join("\n")).toContain(
      "must explicitly limit matchUpdateTypes",
    );
  });

  it("rejects globally enabled auto-merge", () => {
    const { read } = fixture();
    const renovate = JSON.parse(read("renovate.json"));
    renovate.automerge = true;
    const changed = fixture({ "renovate.json": JSON.stringify(renovate) });
    expect(publicationHygieneFailures(changed.files, changed.read).join("\n")).toContain(
      "must be scoped to explicit package rules",
    );
  });

  it("rejects auto-merge without a pre-1.0 manual-review rule", () => {
    const { read } = fixture();
    const renovate = JSON.parse(read("renovate.json"));
    renovate.packageRules = renovate.packageRules.filter(
      (rule) => rule.matchCurrentVersion !== "/^0\\./",
    );
    const changed = fixture({ "renovate.json": JSON.stringify(renovate) });
    expect(publicationHygieneFailures(changed.files, changed.read).join("\n")).toContain(
      "must disable auto-merge for pre-1.0 packages",
    );
  });

  it("rejects an SBOM claim without a release generator", () => {
    const { files, read } = fixture({
      THIRD_PARTY_NOTICES: "Every release includes a software bill of materials.\n",
    });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain("claims a release SBOM");
  });

  it("rejects a notice for vendored material that is not present", () => {
    const { files, read } = fixture({
      THIRD_PARTY_NOTICES: "Vendored file: assets/fonts/missing.woff2\n",
    });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      "lists missing vendored material",
    );
  });
});
