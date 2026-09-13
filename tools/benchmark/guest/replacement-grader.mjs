import { executeCandidate } from "./candidate-sandbox.mjs";
import {
  isReplacementCase,
  replacementCaseDefinition,
  replacementCaseIds,
} from "./replacement-cases.mjs";

export { isReplacementCase, replacementCaseDefinition, replacementCaseIds };

function failure(message) {
  const check = {
    name: "Isolated replacement grader returned valid evidence",
    actual: false,
    pass: false,
  };
  return {
    observed: {},
    acceptance: [check],
    regressions: [check],
    acceptancePass: false,
    regressionsPass: false,
    probeError: message,
  };
}

function normalizeChecks(value, label) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} checks must be a non-empty array`);
  }
  return value.map((check) => {
    if (
      !check ||
      typeof check !== "object" ||
      Array.isArray(check) ||
      typeof check.name !== "string" ||
      check.name.length === 0 ||
      typeof check.pass !== "boolean"
    ) {
      throw new Error(`${label} contains an invalid check`);
    }
    return {
      name: check.name,
      ...(typeof check.actual === "boolean" ? { actual: check.actual } : {}),
      pass: check.pass,
    };
  });
}

export function normalizeReplacementGrade(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("grader result must be an object");
    }
    if (value.error) throw new Error(`${value.error}: ${value.message ?? "unknown adapter error"}`);
    const acceptance = normalizeChecks(value.acceptance, "acceptance");
    const regressions = normalizeChecks(value.regressions, "regressions");
    const acceptancePass = acceptance.every((check) => check.pass);
    const regressionsPass = regressions.every((check) => check.pass);
    if (value.acceptancePass !== acceptancePass || value.regressionsPass !== regressionsPass) {
      throw new Error("grader pass flags do not match their checks");
    }
    return {
      observed:
        value.observed && typeof value.observed === "object" && !Array.isArray(value.observed)
          ? value.observed
          : {},
      acceptance,
      regressions,
      acceptancePass,
      regressionsPass,
      ...(typeof value.probeError === "string" ? { probeError: value.probeError } : {}),
    };
  } catch (error) {
    return failure(error instanceof Error ? error.message : String(error));
  }
}

export function gradeReplacementRepository(item, candidate, execute = executeCandidate) {
  const definition = replacementCaseDefinition(item.id);
  const grade = execute({ ...item, replacementAdapter: true }, candidate, {
    operation: item.id,
    files: definition.files,
  });
  return normalizeReplacementGrade(grade);
}
