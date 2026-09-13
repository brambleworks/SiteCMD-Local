import { executeCandidate } from "./candidate-sandbox.mjs";
import { digest } from "../lib/workflow-plan.mjs";

export const onekeyCaseId = "onekey-http-client-tls-verification";

const acceptanceNames = Object.freeze(
  ["untrusted", "wrong-host", "expired"].flatMap((server) => [
    `${server} get attempt 1 rejects the certificate`,
    `${server} get attempt 2 rejects the certificate`,
    `${server} post attempt 3 rejects the certificate`,
    `${server} post attempt 4 rejects the certificate`,
  ]),
);

const regressionNames = Object.freeze([
  "context manager preserves client identity",
  "trusted get preserves request and binary response",
  "trusted get preserves timeout contract",
  "plain get preserves request and binary response",
  "plain get preserves timeout contract",
  "trusted post preserves request and binary response",
  "trusted post preserves timeout contract",
  "plain post preserves request and binary response",
  "plain post preserves timeout contract",
  "HTTP error status remains a response",
  "concurrent requests preserve binary responses",
  "ordinary delayed responses remain usable",
  "context manager closes the production transport",
  "context manager propagates body exceptions",
  "exceptional context closes the production transport",
  "explicit close is idempotent and closes the production transport",
  "lifecycle operations complete without errors",
]);

function failed(message) {
  const check = { name: "OneKey behavioral probe returned valid evidence", pass: false };
  return {
    acceptance: [check],
    regressions: [check],
    acceptancePass: false,
    regressionsPass: false,
    probeError: message,
  };
}

export function normalizeOnekeyGrade(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("OneKey probe result must be an object");
    }
    if (value.error) throw new Error(`${value.error}: ${value.message ?? "unknown probe error"}`);
    if (
      value.setupError !== null ||
      value.judgeIsolation?.judgeUid !== 0 ||
      value.judgeIsolation?.candidateUid !== 65534 ||
      value.judgeIsolation?.candidateSuppliesVerdict !== false ||
      !Array.isArray(value.checks) ||
      value.checks.length !== acceptanceNames.length + regressionNames.length
    ) {
      throw new Error("OneKey probe isolation or check count is invalid");
    }
    const checks = new Map();
    for (const check of value.checks) {
      if (
        !check ||
        typeof check.name !== "string" ||
        typeof check.passed !== "boolean" ||
        checks.has(check.name)
      ) {
        throw new Error("OneKey probe contains an invalid or duplicate check");
      }
      checks.set(check.name, { name: check.name, pass: check.passed });
    }
    const select = (names) =>
      names.map((name) => {
        const check = checks.get(name);
        if (!check) throw new Error(`OneKey probe omitted check: ${name}`);
        return check;
      });
    const acceptance = select(acceptanceNames);
    const regressions = select(regressionNames);
    if (checks.size !== acceptance.length + regressions.length) {
      throw new Error("OneKey probe returned an unexpected check");
    }
    return {
      acceptance,
      regressions,
      acceptancePass: acceptance.every((check) => check.pass),
      regressionsPass: regressions.every((check) => check.pass),
      observed: { judgeIsolation: value.judgeIsolation },
    };
  } catch (error) {
    return failed(error instanceof Error ? error.message : String(error));
  }
}

export function gradeOnekeyRepository(item, candidate, execute = executeCandidate) {
  if (item.id !== onekeyCaseId) throw new Error("Unsupported OneKey grader");
  return {
    ...normalizeOnekeyGrade(
      execute({ ...item, onekeyAdapter: true }, candidate, { operation: item.id }),
    ),
    runtimeSha256: digest(item.repositoryRuntime),
  };
}
