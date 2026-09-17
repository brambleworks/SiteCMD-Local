#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  liveRepositoryProtectionFailures,
  ownedRepositoryReferences,
  repositoryNameFailures,
  requiredCheckWorkflowFailures,
} from "./lib/repository-protection-rules.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const live = process.argv.slice(2).includes("--live");
const unknown = process.argv.slice(2).filter((argument) => argument !== "--live");
if (unknown.length > 0) {
  process.stderr.write(`Unknown argument: ${unknown[0]}\n`);
  process.exit(2);
}

const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");
const listFiles = (dir, predicate) =>
  fs
    .readdirSync(path.join(ROOT, dir))
    .map((entry) => `${dir}/${entry}`)
    .filter(predicate);
const contract = JSON.parse(read(".github/repository-protection.json"));

const git = (...args) => {
  try {
    return execFileSync("git", args, {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    // No remote, no git, or a grep that matched nothing: absence is not a
    // failure here, it only narrows what can be checked.
    return "";
  }
};

/** The repository this checkout belongs to: what Actions says it is, or what
 *  the origin remote names locally. */
const checkoutRepository = () => {
  if (process.env.GITHUB_REPOSITORY) return process.env.GITHUB_REPOSITORY;
  const remote = git("remote", "get-url", "origin");
  return /github\.com[/:]([^/]+\/[^/]+?)(?:\.git)?$/.exec(remote)?.[1] ?? null;
};

const gh = (endpoint) =>
  JSON.parse(
    execFileSync("gh", ["api", endpoint], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }),
  );

const failures = requiredCheckWorkflowFailures(contract, read, listFiles);

const owner = contract.repository.split("/")[0];
const referencing = git(
  "grep",
  "-lI",
  "-e",
  `github.com/${owner}/`,
  "-e",
  `uses: ${owner}/`,
  "--",
  ".",
)
  .split("\n")
  .filter(Boolean);
failures.push(
  ...repositoryNameFailures(contract, {
    checkoutRepository: checkoutRepository(),
    labelsRepository: JSON.parse(read(".github/repository-labels.json")).repository,
    references: ownedRepositoryReferences(
      owner,
      referencing.map((file) => ({ file, source: read(file) })),
    ),
  }),
);
if (live && failures.length === 0) {
  try {
    const repository = gh(`repos/${contract.repository}`);
    const rulesets = gh(`repos/${contract.repository}/rulesets`).map((ruleset) =>
      gh(`repos/${contract.repository}/rulesets/${ruleset.id}`),
    );
    failures.push(
      ...liveRepositoryProtectionFailures(contract, {
        privateVulnerabilityReporting: gh(
          `repos/${contract.repository}/private-vulnerability-reporting`,
        ).enabled,
        securityAndAnalysis: repository.security_and_analysis,
        rulesets,
      }),
    );
  } catch (error) {
    failures.push(`Could not read live GitHub protection settings: ${error.message}`);
  }
}

if (failures.length > 0) {
  process.stderr.write("Repository protection check failed:\n");
  for (const failure of failures) process.stderr.write(`- ${failure}\n`);
  process.exit(1);
}

process.stdout.write(
  live
    ? `Repository protection matches ${contract.repository}.\n`
    : "Repository protection contract names checks that run on every pull request.\n",
);
