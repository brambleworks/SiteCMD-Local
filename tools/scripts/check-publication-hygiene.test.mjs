import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { publicationHygieneFailures } from "./lib/publication-hygiene-rules.mjs";

it("pins_the_owner_approved_publication_moves", () => {
  const source = readFileSync(new URL("./published-engine-moves.json", import.meta.url), "utf8");
  expect(JSON.parse(source)).toEqual({
    approved:
      "Owner-approved 2026-11-25: moved out of the engine on purpose for the first public export.",
    moves: [
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/authorization_tests.rs",
        blob: "a990679596916f6b6e2ec1ade5957935fcc011a6",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/bearer_encoding_tests.rs",
        blob: "8ca529de39480d9f101ad84c38c3b436ab6fb74f",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/login_mask_tests.rs",
        blob: "7ebee45b2a5c3441922916317734c440cf3cb665",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/test_support.rs",
        blob: "e27dd180a89b9e00c976bfa56e0d00ebbe98d809",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/unicode_boundary_tests.rs",
        blob: "f89bb74d9d1c6e5f78a2ed0b5966e442d2e54377",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/log_sanitizer/url_encoding_tests.rs",
        blob: "002992cf4653c379145a91e2d1ab6dc5e07ec779",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/sync/mod.rs",
        blob: "bdafcfbbb01f5fdfdc2c8119b7cecc3e46b0bd7d",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/sync/payload.rs",
        blob: "d32e33f58e1d7ae4769392fba60d50ec37130177",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/sync/payload_tests.rs",
        blob: "d686b0a528a2a685f2baf7478fe9c903da2c7f2c",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/time/date.rs",
        blob: "bdb24bb6751e9b745e5251274e7e169d514a5c10",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/time/format.rs",
        blob: "9768c98a11285fa012e4fd7b83e87ca22029388f",
      },
      {
        path: "apps/desktop/src-tauri/crates/protocol/src/time/parse.rs",
        blob: "ac86539be78db243391840c4e09b1a9072606500",
      },
      {
        path: "apps/desktop/src-tauri/src/core/audit/fingerprints.rs",
        blob: "b9b58145413a3a33ccf0e3bfbc6649016a0b1086",
      },
      {
        path: "apps/desktop/src-tauri/src/core/audit/metadata_offer_tests.rs",
        blob: "9ac134698d5da1d1e651a539309e8f2c0c78f267",
      },
      {
        path: "apps/desktop/src-tauri/src/core/audit/session_host/tests.rs",
        blob: "c66d9bba1e118d35453f2a0125e53098e546df2d",
      },
    ],
  });
});

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
  "tools/scripts/published-engine-moves.json",
  "tools/scripts/lib/publication-hygiene-rules.mjs",
  "tools/scripts/lib/publication-history-rules.mjs",
  "tools/scripts/lib/publication-root-files.mjs",
];

function fixture(extra = {}, omitted = []) {
  const contents = Object.fromEntries(REQUIRED.map((path) => [path, `${path}\n`]));
  contents[".github/CODEOWNERS"] = "* @brambleworks\n";
  contents["package.json"] = '{"license": "Apache-2.0"}\n';
  contents["apps/desktop/src-tauri/crates/runtime/Cargo.toml"] = 'license = "Apache-2.0"\n';
  contents["apps/desktop/src-tauri/crates/cli/Cargo.toml"] = 'license = "Apache-2.0"\n';
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
      "tools/scripts/lib/runtime-paths.mjs":
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
      "apps/desktop/src-tauri/src/core/project_listing_tests.rs":
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

  it("accepts the engine pin at the repository root", () => {
    // Bug: the first engine pin failed publication hygiene because engine.lock was missing from the root allowlist (2026-11-24).
    const { files, read } = fixture({
      "engine.lock": '{ "version": "0.1.0" }\n',
      "engine/local-engine.wasm.LICENSES.txt": "Third-party licenses for local-engine.wasm\n",
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
    const { files, read } = fixture({
      "apps/desktop/src-tauri/crates/runtime/Cargo.toml": 'license = "MIT"\n',
    });
    expect(publicationHygieneFailures(files, read).join("\n")).toContain(
      'open-source package metadata must contain license = "Apache-2.0": apps/desktop/src-tauri/crates/runtime/Cargo.toml',
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
