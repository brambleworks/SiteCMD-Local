import { digest } from "./workflow-plan.mjs";

const runtimePolicies = Object.freeze({
  "fmd-device-text": {
    source: "browserRuntime",
    gradeField: "browserRuntimeSha256",
  },
  "onekey-http-client-tls-verification": {
    source: "repositoryRuntime",
    gradeField: "runtimeSha256",
  },
});

function policyFor(caseId) {
  return runtimePolicies[caseId];
}

export function repositoryQualificationRuntime(caseId, runtimes, variants) {
  const policy = policyFor(caseId);
  if (!policy) return undefined;
  const runtime = runtimes?.[policy.source];
  if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) {
    throw new Error(`Qualification runtime for ${caseId} is missing`);
  }
  const grades = ["baseline", "reference"].flatMap((variant) => {
    const value = variants?.[variant]?.grades;
    if (!Array.isArray(value)) {
      throw new Error(`Qualification grades for ${caseId} are missing`);
    }
    return value;
  });
  const runtimeSha256 = digest(runtime);
  return {
    runtime,
    runtimeSha256,
    runtimePassed: grades.every((grade) => grade?.[policy.gradeField] === runtimeSha256),
  };
}

export function validateRepositoryQualificationRuntime(caseId, receipt) {
  const policy = policyFor(caseId);
  if (!policy) return true;
  const evidence = repositoryQualificationRuntime(
    caseId,
    { [policy.source]: receipt?.runtime },
    receipt?.variants,
  );
  return (
    receipt.runtimeSha256 === evidence.runtimeSha256 &&
    receipt.runtimePassed === true &&
    evidence.runtimePassed
  );
}

export function repositoryQualificationRuntimeBinding(caseId, receipt) {
  const policy = policyFor(caseId);
  if (!policy) return undefined;
  if (!validateRepositoryQualificationRuntime(caseId, receipt)) {
    throw new Error(`Qualification runtime evidence for ${caseId} is invalid`);
  }
  return {
    runtimeField: policy.source,
    digestField: policy.source === "browserRuntime" ? "browserRuntimeSha256" : "runtimeSha256",
    runtime: receipt.runtime,
    sha256: receipt.runtimeSha256,
  };
}
