import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { commitMessageFailures } from "./lib/commit-message-rules.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCRIPT = path.join(ROOT, "tools/scripts/check-commit-message.mjs");

describe("commitMessageFailures", () => {
  it.each([
    "Add verified site baselines",
    "Preserve RDAP facts through WASM",
    "Reject unsupported database targets",
    "Update GitHub Actions dependencies",
    "Document the scanner privacy boundary",
    "Publish SiteCMD 1.6.0",
  ])("accepts '%s'", (message) => {
    expect(commitMessageFailures(message)).toEqual([]);
  });

  it.each([
    ["feat: add verified site baselines", "Conventional Commit prefix"],
    ["docs(scanner): update privacy details", "Conventional Commit prefix"],
    ["SC-42: Add verified site baselines", "ticket references"],
    ["Add: verified site baselines", "without a prefix or colon"],
    ["add verified site baselines", "capitalized imperative verb"],
    ["Added verified site baselines", "imperative form"],
    ["Adding verified site baselines", "imperative form"],
    ["Fix issues", "specific behavior or component"],
    ["Address feedback", "specific behavior or component"],
    ["Release readiness", "specific behavior or component"],
    ["Update", "both an action and the thing"],
    ["Add verified site baselines.", "punctuation"],
  ])("rejects '%s'", (message, expected) => {
    expect(commitMessageFailures(message).join("\n")).toContain(expected);
  });

  it("limits the subject length and word count", () => {
    const failures = commitMessageFailures(
      "Document every individual implementation detail across all connected service modules today",
    ).join("\n");
    expect(failures).toContain("60 characters");
    expect(failures).toContain("10 words");
  });

  it("accepts a short rationale and audit trailers", () => {
    expect(
      commitMessageFailures(
        "Split the scanner scheduler\n\nKeep scan admission separate from execution.\n\n[budget-raised: platform constraint (#123)]\nCo-authored-by: Dev <dev@example.com>",
      ),
    ).toEqual([]);
  });

  it("requires a blank line before the body", () => {
    expect(commitMessageFailures("Split the scanner scheduler\nExplain why.").join("\n")).toContain(
      "blank line",
    );
  });

  it("rejects essay-length bodies", () => {
    const message = [
      "Split the scanner scheduler",
      "",
      "First implementation detail.",
      "Second implementation detail.",
      "Third implementation detail.",
      "Fourth implementation detail.",
      "Fifth implementation detail.",
    ].join("\n");
    expect(commitMessageFailures(message).join("\n")).toContain("4 non-empty lines");
  });

  it("ignores Git's comment template", () => {
    expect(
      commitMessageFailures(
        "Add verified site baselines\n\n# Please enter the commit message.\n# Changes to be committed:",
      ),
    ).toEqual([]);
  });
});

describe("check-commit-message CLI", () => {
  it("reads the commit-msg hook file", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-commit-message-"));
    const messageFile = path.join(directory, "message");
    try {
      fs.writeFileSync(messageFile, "Add verified site baselines\n");
      expect(() => execFileSync(process.execPath, [SCRIPT, "--file", messageFile])).not.toThrow();
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("reads a pull request title without shell interpolation", () => {
    const result = spawnSync(process.execPath, [SCRIPT, "--env", "PR_TITLE"], {
      env: { ...process.env, PR_TITLE: "fix: run arbitrary shell" },
      encoding: "utf8",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Remove the Conventional Commit prefix");
  });
});

describe("commit-message policy wiring", () => {
  it("checks local commits and pull request titles", () => {
    const hook = fs.readFileSync(path.join(ROOT, "lefthook.yml"), "utf8");
    const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
    expect(hook).toContain('check-commit-message.mjs --file "{1}"');
    expect(workflow).toContain(
      'node tools/scripts/pr-title.mjs --title="$PR_TITLE" --body-file "$body_file"',
    );
    expect(workflow).toContain("types: [opened, edited, reopened, synchronize, ready_for_review]");
  });

  it("keeps dependency pull requests compatible with plain-English titles", () => {
    const contributing = fs.readFileSync(path.join(ROOT, "CONTRIBUTING.md"), "utf8");
    const dependabot = fs.readFileSync(path.join(ROOT, ".github/dependabot.yml"), "utf8");
    const renovateSource = fs.readFileSync(path.join(ROOT, "renovate.json"), "utf8");
    const renovate = JSON.parse(renovateSource);
    expect(contributing).toContain("capitalized imperative verb");
    expect(contributing).not.toContain("Conventional Commits");
    expect(dependabot).not.toContain("commit-message:");
    expect(renovate.extends).not.toContain(":semanticCommits");
    expect(renovate.semanticCommits).toBe("disabled");
    expect(renovate.commitMessageAction).toBe("Update");
    expect(renovate.commitMessageLowerCase).toBe("never");
    expect(renovateSource).not.toMatch(/"(?:commitMessagePrefix|fileMatch|matchPackagePatterns)"/);

    const actionsRule = renovate.packageRules.find((rule) =>
      rule.matchManagers?.includes("github-actions"),
    );
    expect(actionsRule?.enabled).toBe(false);
    expect(renovate.packageRules).toContainEqual(
      expect.objectContaining({ matchManagers: ["rust-toolchain"] }),
    );
  });
});

describe("dependency bot titles", () => {
  // The title that failed the guardrail on pull request 47. Dependabot appends
  // "in the <group> group" when a grouped update carries a single dependency,
  // and offers no way to shorten it.
  const GROUPED_SINGLE =
    "Bump taiki-e/install-action from 2.87.0 to 2.87.5 in the github-actions group";

  it.each([
    GROUPED_SINGLE,
    "Bump actions/checkout from 4.2.2 to 5.0.0",
    "Bump the github-actions group with 5 updates",
    "Bump the github-actions group with 1 update",
    "Bump the github-actions group across 1 directory with 5 updates",
  ])("accepts the machine-written title %s", (subject) => {
    expect(commitMessageFailures(subject, { subjectOnly: true })).toEqual([]);
  });

  it("relaxes the length allowance only, and only for these shapes", () => {
    expect(GROUPED_SINGLE.length).toBeGreaterThan(60);
    // A human subject of the same length is still held to the cap.
    const human = "Bump the release manifest and the updater signature together again";
    expect(human.length).toBeGreaterThan(60);
    expect(commitMessageFailures(human, { subjectOnly: true })).toContain(
      "Keep the subject at 60 characters or fewer.",
    );
  });

  it.each([
    [
      "bump taiki-e/install-action from 2.87.0 to 2.87.5",
      "Start the subject with a capitalized imperative verb.",
    ],
    [
      "chore(deps): Bump actions/checkout from 4.2.2 to 5.0.0",
      "Remove the Conventional Commit prefix.",
    ],
    ["Bump actions/checkout from 4.2.2 to 5.0.0.", "Do not end the subject with punctuation."],
  ])("still applies every other rule to %s", (subject, failure) => {
    expect(commitMessageFailures(subject, { subjectOnly: true })).toContain(failure);
  });
});
