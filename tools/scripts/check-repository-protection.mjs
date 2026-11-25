#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  liveRepositoryProtectionFailures,
  ownedRepositoryReferences,
  readLiveRepositoryProtection,
  repositoryNameFailures,
  requiredCheckWorkflowFailures,
  selectRepositoryProtectionContract,
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
const config = JSON.parse(read(".github/repository-protection.json"));

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

const githubSlug = (url) => /github\.com[/:]([^/]+\/[^/]+?)(?:\.git)?$/.exec(url)?.[1];
const origin = githubSlug(git("remote", "get-url", "origin"));
const checkout = process.env.GITHUB_REPOSITORY || origin;
const contract = selectRepositoryProtectionContract(config, checkout);

function publishedWorkflows(repository) {
  const remote = git("remote")
    .split("\n")
    .find((name) => name && githubSlug(git("remote", "get-url", name)) === repository);
  const branch = contract.branchRuleset.refNameInclude[0].replace(/^refs\/heads\//, "");
  const ref = remote && `refs/remotes/${remote}/${branch}`;
  return {
    read: (file) => git("show", `${ref}:${file}`),
    listFiles: (dir, predicate) =>
      ref ? git("ls-tree", "-r", "--name-only", ref, "--", dir).split("\n").filter(predicate) : [],
  };
}

const gh = (endpoint) =>
  JSON.parse(
    execFileSync("gh", ["api", endpoint], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }),
  );

// A cross-repository check uses that repository's tracked published workflows.
const workflows =
  Object.hasOwn(config.repositories, origin) && contract.repository !== origin
    ? publishedWorkflows(contract.repository)
    : { read, listFiles };
const failures = requiredCheckWorkflowFailures(contract, workflows.read, workflows.listFiles);

const owner = config.publicRepository.split("/")[0];
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
  ...repositoryNameFailures(config, {
    checkoutRepository: checkout,
    labelsRepository: JSON.parse(read(".github/repository-labels.json")).repository,
    references: ownedRepositoryReferences(
      owner,
      referencing.map((file) => ({ file, source: read(file) })),
    ),
  }),
);
if (live && failures.length === 0) {
  try {
    failures.push(
      ...liveRepositoryProtectionFailures(contract, readLiveRepositoryProtection(contract, gh)),
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
