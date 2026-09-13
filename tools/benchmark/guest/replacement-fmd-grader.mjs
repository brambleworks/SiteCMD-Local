import { isDeepStrictEqual } from "node:util";
import { digest } from "../lib/workflow-plan.mjs";
import { executeCandidate } from "./candidate-sandbox.mjs";

export const fmdCaseId = "fmd-device-text";
const locationIndexes = Object.freeze([3, 2, 1, 0, 1, 2, 3]);
const frameChecks = (frame) => [
  `early details frame ${frame}`,
  `render frame ${frame}`,
  `transient markup frame ${frame}`,
  `pending action frames ${frame}`,
];
const locationChecks = (location, index) =>
  [
    "provider text",
    "no interpreted input elements",
    "fields visible",
    "device fields",
    "timestamp",
    "map center",
    "cached markers",
    "connecting line",
    "help link",
  ].map((suffix) => `location ${location} index ${index} ${suffix}`);

export const fmdCheckNames = Object.freeze([
  ...frameChecks(0),
  "initial fields hidden",
  "initial placeholders",
  "initial help link",
  ...locationIndexes.flatMap((index, location) => [
    ...frameChecks(location + 1),
    ...locationChecks(location, index),
  ]),
  ...frameChecks(8),
  "empty visible",
  "empty metadata",
  ...frameChecks(9),
  "corrupt visible",
  "corrupt metadata",
  "actual encrypted navigation requests",
  "fixture expectations are not served",
]);

export const fmdAcceptanceCheckNames = Object.freeze(
  locationIndexes.flatMap((index, location) => [
    ...frameChecks(location + 1),
    `location ${location} index ${index} provider text`,
    `location ${location} index ${index} no interpreted input elements`,
  ]),
);
const acceptanceSet = new Set(fmdAcceptanceCheckNames);
const regressionNames = Object.freeze(fmdCheckNames.filter((name) => !acceptanceSet.has(name)));

if (fmdCheckNames.length !== 112 || new Set(fmdCheckNames).size !== 112) {
  throw new Error("FMD grader check contract is invalid");
}

function failed(message) {
  const check = { name: "FMD browser probe returned valid evidence", pass: false };
  return {
    acceptance: [check],
    regressions: [check],
    acceptancePass: false,
    regressionsPass: false,
    probeError: message,
  };
}

function validateRun(run, expectedChecks, expectedPassed) {
  if (
    run?.exitCode !== 0 ||
    run.error !== null ||
    run.result?.setupError !== null ||
    run.result.passed !== expectedPassed ||
    !Array.isArray(run.result.checks) ||
    run.result.checks.length !== expectedChecks ||
    !Array.isArray(run.result.observations) ||
    run.result.observations.length !== 10 ||
    run.result.observations.some((observation) => observation.pageOverrideInstalled !== false) ||
    !Array.isArray(run.result.pendingActionSamples) ||
    run.result.pendingActionSamples.length !== 10 ||
    run.result.pendingActionSamples.some(
      (record) =>
        record.completed !== true || !Number.isInteger(record.samples) || record.samples < 1,
    ) ||
    !Array.isArray(run.result.earlyRenderSamples) ||
    run.result.earlyRenderSamples.length !== 10 ||
    run.result.earlyRenderSamples.some(
      (record) =>
        !Number.isInteger(record.samples) ||
        record.samples < 3 ||
        !Number.isInteger(record.settleSamples) ||
        record.settleSamples < 3,
    )
  ) {
    throw new Error("FMD browser run structure is invalid");
  }
}

function validateReferences(references) {
  if (
    !Array.isArray(references?.primary) ||
    references.primary.length !== 3 ||
    !Array.isArray(references.details) ||
    references.details.length !== 3 ||
    !Array.isArray(references.retries?.primary) ||
    references.retries.primary.length > 3 ||
    !Array.isArray(references.retries.details) ||
    references.retries.details.length > 3 ||
    !/^[a-f0-9]{64}$/.test(references.fixtureSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(references.transitionSha256 ?? "")
  ) {
    throw new Error("FMD reference evidence is invalid");
  }
  for (const run of [...references.primary, ...references.details]) {
    validateRun(run, 82, true);
    if (
      run.result.checks.some(
        (check) => !check || typeof check.name !== "string" || check.passed !== true,
      ) ||
      new Set(run.result.checks.map((check) => check.name)).size !== 82
    ) {
      throw new Error("FMD reference checks are invalid");
    }
  }
  for (const source of ["primary", "details"]) {
    const seen = new Set();
    for (const retry of references.retries[source]) {
      if (
        !Number.isInteger(retry?.index) ||
        retry.index < 0 ||
        retry.index >= 3 ||
        seen.has(retry.index) ||
        retry.initial?.result?.passed === true ||
        !isDeepStrictEqual(retry.retry, references[source][retry.index])
      ) {
        throw new Error("FMD reference retry evidence is invalid");
      }
      seen.add(retry.index);
    }
  }
}

export function normalizeFmdGrade(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("FMD browser result must be an object");
    }
    if (value.error) throw new Error(`${value.error}: ${value.message ?? "unknown error"}`);
    validateReferences(value.references);
    const run = value.candidate;
    if (typeof run?.result?.passed !== "boolean") {
      throw new Error("FMD candidate verdict is missing");
    }
    validateRun(run, fmdCheckNames.length, run.result.passed);
    const checks = new Map();
    for (const check of run.result.checks) {
      if (
        !check ||
        typeof check.name !== "string" ||
        typeof check.passed !== "boolean" ||
        checks.has(check.name) ||
        !fmdCheckNames.includes(check.name)
      ) {
        throw new Error("FMD candidate returned an invalid or duplicate check");
      }
      checks.set(check.name, { name: check.name, pass: check.passed });
    }
    const select = (names) =>
      names.map((name) => {
        const check = checks.get(name);
        if (!check) throw new Error(`FMD candidate omitted check: ${name}`);
        return check;
      });
    const acceptance = select(fmdAcceptanceCheckNames);
    const regressions = select(regressionNames);
    const allPassed = [...acceptance, ...regressions].every((check) => check.pass);
    if (run.result.passed !== allPassed) {
      throw new Error("FMD candidate verdict conflicts with its checks");
    }
    return {
      acceptance,
      regressions,
      acceptancePass: acceptance.every((check) => check.pass),
      regressionsPass: regressions.every((check) => check.pass),
      observed: {
        fixtureSha256: value.references.fixtureSha256,
        transitionSha256: value.references.transitionSha256,
        referenceRetries: {
          primary: value.references.retries.primary.length,
          details: value.references.retries.details.length,
          sha256: digest(value.references.retries),
        },
      },
    };
  } catch (error) {
    return failed(error instanceof Error ? error.message : String(error));
  }
}

export function gradeFmdRepository(item, candidate, execute = executeCandidate) {
  if (item.id !== fmdCaseId) throw new Error("Unsupported FMD grader");
  return {
    ...normalizeFmdGrade(
      execute({ ...item, fmdAdapter: true }, candidate, { operation: fmdCaseId }),
    ),
    browserRuntimeSha256: digest(item.browserRuntime),
  };
}
