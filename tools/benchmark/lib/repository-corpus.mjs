import { readFileSync } from "node:fs";
import { requireCondition, requireSlug, requireText } from "./workflow-contract.mjs";

export const repositoryCorpusPolicy = JSON.parse(
  readFileSync(new URL("../repository-corpus-policy.json", import.meta.url), "utf8"),
);

const COMMIT = /^[a-f0-9]{40}$/;
const FINDING_FINGERPRINT = /^sha256:[a-f0-9]{64}$/;
const CHECK_ID = /^code_scan\.[a-z0-9][a-z0-9._-]*$/;

function isHttpsUrl(value) {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    value.split("/").every((part) => part && part !== "." && part !== "..")
  );
}

function pathContains(parent, child) {
  return parent === child || child.startsWith(`${parent}/`);
}

function validateCase(item, { confirmatory }) {
  requireSlug(item?.id, "case id");
  requireSlug(item.repository?.id, `case ${item.id} repository id`);
  requireCondition(isHttpsUrl(item.repository?.url), `case ${item.id} repository URL is invalid`);
  requireText(item.repository?.license, `case ${item.id} repository license`);
  requireCondition(
    isSafeRelativePath(item.repository?.licenseFile),
    `case ${item.id} repository license file is invalid`,
  );
  requireCondition(
    ["repair", "negative_control"].includes(item.kind),
    `case ${item.id} kind is invalid`,
  );
  requireSlug(item.category, `case ${item.id} category`);
  requireSlug(item.runtime, `case ${item.id} runtime`);
  requireCondition(item.surface === "code", `case ${item.id} must use Code Scan`);
  requireCondition(
    COMMIT.test(item.baselineCommit ?? ""),
    `case ${item.id} baseline pin is invalid`,
  );
  requireCondition(
    COMMIT.test(item.upstreamCommit ?? ""),
    `case ${item.id} upstream pin is invalid`,
  );
  requireCondition(isHttpsUrl(item.upstreamFix), `case ${item.id} provenance URL is invalid`);
  if (item.kind === "repair") {
    requireCondition(
      item.baselineCommit !== item.upstreamCommit,
      `case ${item.id} baseline and upstream pins must differ`,
    );
    if (item.upstreamAdvisory !== undefined) {
      requireCondition(
        isHttpsUrl(item.upstreamAdvisory),
        `case ${item.id} upstream advisory URL is invalid`,
      );
    }
    requireCondition(
      ["implementation-only", "implementation-regions"].includes(item.referenceStrategy),
      `case ${item.id} reference strategy is invalid`,
    );
  } else {
    requireCondition(
      item.baselineCommit === item.upstreamCommit,
      `case ${item.id} negative control pins must match`,
    );
    requireText(item.safetyRationale, `case ${item.id} safety rationale`);
  }
  for (const [field, label] of [
    ["task", "task"],
    ["requirements", "requirements"],
    ["selectionReason", "selection reason"],
  ])
    requireText(item[field], `case ${item.id} ${label}`);
  requireCondition(
    Array.isArray(item.editableFiles) &&
      item.editableFiles.length > 0 &&
      item.editableFiles.length <= 100 &&
      new Set(item.editableFiles).size === item.editableFiles.length &&
      item.editableFiles.every(isSafeRelativePath),
    `case ${item.id} editable files are invalid`,
  );
  if (item.sourceExclusions !== undefined) {
    requireCondition(
      Array.isArray(item.sourceExclusions) &&
        item.sourceExclusions.length > 0 &&
        item.sourceExclusions.length <= 100 &&
        new Set(item.sourceExclusions.map((entry) => entry?.path)).size ===
          item.sourceExclusions.length,
      `case ${item.id} source exclusions are invalid`,
    );
    for (const exclusion of item.sourceExclusions) {
      requireCondition(
        isSafeRelativePath(exclusion?.path) &&
          !item.editableFiles.some((name) => pathContains(exclusion.path, name)) &&
          !pathContains(exclusion.path, item.repository.licenseFile),
        `case ${item.id} source exclusion hides a protected path`,
      );
      requireText(exclusion.reason, `case ${item.id} source exclusion reason`);
    }
  }
  if (confirmatory) {
    requireCondition(
      CHECK_ID.test(item.targetFinding?.checkId ?? "") &&
        isSafeRelativePath(item.targetFinding?.relativePath) &&
        FINDING_FINGERPRINT.test(item.targetFinding?.fingerprint ?? "") &&
        item.editableFiles.includes(item.targetFinding.relativePath),
      `case ${item.id} confirmatory target finding is invalid`,
    );
    requireText(
      item.targetFinding.sourceAnchor,
      `case ${item.id} confirmatory target semantic source anchor`,
    );
  }
}

function validateRepositoryCorpus(corpus, { confirmatory }) {
  requireCondition(corpus?.schemaVersion === 1, "corpus schemaVersion must be 1");
  requireSlug(corpus.id, "corpus id");
  requireCondition(corpus.status !== "invalidated", "invalidated corpus cannot seed another study");
  requireText(corpus.selectionMethod, "corpus selection method");
  requireCondition(
    typeof corpus.selectedAt === "string" &&
      !Number.isNaN(Date.parse(corpus.selectedAt)) &&
      new Date(corpus.selectedAt).toISOString() === corpus.selectedAt,
    "corpus selectedAt must be an ISO timestamp",
  );
  requireCondition(Array.isArray(corpus.cases), "corpus cases are required");
  if (confirmatory) {
    requireCondition(
      corpus.scannerObservedAtSelection === true && corpus.repairTrialsObservedAtSelection === 0,
      "confirmatory corpus must be scanner-enriched and frozen before repair-agent trials",
    );
    requireText(corpus.selectionPopulation, "confirmatory selection population");
    requireText(corpus.estimand, "confirmatory estimand");
  } else {
    requireCondition(
      corpus.scannerObservedAtSelection === false && corpus.repairTrialsObservedAtSelection === 0,
      "corpus must be selected before scanner or agent observation",
    );
  }
  requireCondition(
    corpus.cases.every((item) => item?.heldOut === true),
    "corpus cases must remain held out",
  );
  const caseIds = corpus.cases.map((item) => item?.id);
  requireCondition(new Set(caseIds).size === caseIds.length, "case ids must be unique");
  corpus.cases.forEach((item) => validateCase(item, { confirmatory }));
  const repositoryById = new Map();
  const repositoryByUrl = new Map();
  for (const item of corpus.cases) {
    const metadata = `${item.repository.url}\n${item.repository.license}\n${item.repository.licenseFile}`;
    requireCondition(
      !repositoryById.has(item.repository.id) ||
        repositoryById.get(item.repository.id) === metadata,
      `repository ${item.repository.id} has inconsistent provenance`,
    );
    requireCondition(
      !repositoryByUrl.has(item.repository.url) ||
        repositoryByUrl.get(item.repository.url) === item.repository.id,
      `repository ${item.repository.url} has multiple ids`,
    );
    repositoryById.set(item.repository.id, metadata);
    repositoryByUrl.set(item.repository.url, item.repository.id);
  }
  const policy = repositoryCorpusPolicy;
  requireCondition(
    corpus.cases.length >= policy.minimumCases && corpus.cases.length <= policy.maximumCases,
    "corpus case count is outside the approved range",
  );
  const repositories = corpus.cases.map((item) => item.repository?.id);
  requireCondition(
    new Set(repositories).size >= policy.minimumRepositories,
    "corpus must span enough repositories",
  );
  const perRepository = new Map();
  for (const repository of repositories)
    perRepository.set(repository, (perRepository.get(repository) ?? 0) + 1);
  requireCondition(
    [...perRepository.values()].every((count) => count <= policy.maximumCasesPerRepository),
    "corpus is too concentrated in one repository",
  );
  requireCondition(
    corpus.cases.filter((item) => item.kind === "repair").length >= policy.minimumRepairs,
    "corpus needs more repair cases",
  );
  requireCondition(
    corpus.cases.filter((item) => item.kind === "negative_control").length >=
      policy.minimumNegativeControls,
    "corpus needs more negative controls",
  );
  requireCondition(
    new Set(corpus.cases.map((item) => item.category)).size >= policy.minimumCategories,
    "corpus needs more issue categories",
  );
  requireCondition(
    new Set(corpus.cases.map((item) => item.runtime)).size >= policy.minimumRuntimes,
    "corpus needs more runtimes",
  );
  return corpus;
}

export function validateRepositoryCorpusIntake(corpus) {
  return validateRepositoryCorpus(corpus, { confirmatory: false });
}

export function validateRepositoryConfirmatoryCorpus(corpus) {
  return validateRepositoryCorpus(corpus, { confirmatory: true });
}

export function validateRepositoryCorpusDefinition(corpus) {
  return corpus?.scannerObservedAtSelection === true
    ? validateRepositoryConfirmatoryCorpus(corpus)
    : validateRepositoryCorpusIntake(corpus);
}
