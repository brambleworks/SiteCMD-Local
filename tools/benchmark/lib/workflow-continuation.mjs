import path from "node:path";
import { readArtifact } from "./workflow-artifacts.mjs";
import { requireCondition, requireText } from "./workflow-contract.mjs";
import { digest } from "./workflow-plan.mjs";
import { loadPlan, loadResults } from "./workflow-store.mjs";

function comparableStudy(study) {
  const { runnerSha256: _runner, continuation: _continuation, ...contract } = study;
  return {
    ...contract,
    configurations: contract.configurations.map((configuration) => ({
      ...configuration,
      environment: configuration.environment.replace(/; controller [a-f0-9]{64}$/, ""),
    })),
  };
}

function supplementalContract(study) {
  const {
    id: _id,
    phase: _phase,
    billing: _billing,
    runnerSha256: _runner,
    continuation: _continuation,
    ...contract
  } = study;
  return {
    ...contract,
    configurations: contract.configurations.map((configuration) => ({
      ...configuration,
      environment: configuration.environment.replace(/; controller [a-f0-9]{64}$/, ""),
    })),
  };
}

function retainedEvidence(directory, source) {
  const records = new Map(loadResults(directory, source).map((record) => [record.trialId, record]));
  requireCondition(
    records.size > 0 && records.size < source.plannedTrials,
    "Continuation requires a partially executed source study",
  );
  const inherited = source.study.continuation;
  const prefix =
    inherited?.retained.map((record) => ({
      ...record,
      studySha256: record.studySha256 ?? inherited.sourceStudySha256,
    })) ?? [];
  const local = source.assignments.slice(0, records.size).map(({ id, ...assignment }) => {
    requireCondition(records.has(id), "Continuation must preserve the complete executed prefix");
    const stored = JSON.parse(readArtifact(directory, `trials/${id}/record.json`));
    return {
      ...assignment,
      trialId: id,
      recordSha256: stored.recordSha256,
      ...(inherited ? { studySha256: source.studySha256 } : {}),
    };
  });
  return [...prefix, ...local];
}

export function describeContinuation(sourceRun, study, reason, ancestors = new Set()) {
  const directory = path.resolve(sourceRun);
  requireCondition(
    !ancestors.has(directory) && ancestors.size < 16,
    "Invalid continuation ancestry",
  );
  const source = loadPlan(directory);
  requireText(reason, "continuation reason");
  verifyContinuation(directory, source, ancestors);
  requireCondition(
    digest(comparableStudy(source.study)) === digest(comparableStudy(study)),
    "Continuation changed the cases, models, protocol, environment or limits",
  );
  const baselineSha256 = digest(JSON.parse(readArtifact(directory, "quota-baseline.json")));
  requireCondition(
    readArtifact(directory, "quota-baseline.sha256").toString() === baselineSha256,
    "The original allowance baseline changed",
  );
  return {
    sourceRun: directory,
    sourceStudySha256: source.studySha256,
    baselineSha256,
    reason,
    retained: retainedEvidence(directory, source),
  };
}

export function describeSupplementalContinuation(
  sourceRun,
  study,
  baseline,
  authorization,
  ancestors = new Set(),
) {
  const directory = path.resolve(sourceRun);
  requireCondition(
    !ancestors.has(directory) && ancestors.size < 16,
    "Invalid continuation ancestry",
  );
  const source = loadPlan(directory);
  verifyContinuation(directory, source, ancestors);
  requireCondition(
    source.study.phase === "confirmatory" &&
      study.id === `${source.study.id}-supplemental` &&
      study.phase === "calibration",
    "Supplemental completion must be clearly labeled",
  );
  requireCondition(
    digest(supplementalContract(source.study)) === digest(supplementalContract(study)),
    "Supplemental completion changed the cases, models, protocol, environment or limits",
  );
  requireCondition(
    authorization?.schemaVersion === 1 &&
      authorization.kind === "supplemental-completion" &&
      authorization.sourceStudySha256 === source.studySha256 &&
      digest(authorization.billing) === digest(study.billing) &&
      Number.isFinite(Date.parse(authorization.approvedAt)),
    "Supplemental completion authorization is invalid",
  );
  requireText(authorization.approvedBy, "supplemental completion approver");
  requireText(authorization.reason, "supplemental completion reason");
  requireCondition(
    source.study.billing?.mode === "subscription" && study.billing?.mode === "subscription",
    "Supplemental completion requires subscription billing",
  );
  requireCondition(
    study.billing.automaticResets === false,
    "Supplemental completion cannot enable automatic quota resets",
  );
  requireCondition(
    study.billing.paidFallback === false &&
      study.limits.trialCostUsd === 0 &&
      study.limits.studyCostUsd === 0,
    "Supplemental completion cannot enable paid usage",
  );
  const sourceBaselineSha256 = digest(JSON.parse(readArtifact(directory, "quota-baseline.json")));
  requireCondition(
    readArtifact(directory, "quota-baseline.sha256").toString() === sourceBaselineSha256,
    "Supplemental source allowance baseline changed",
  );
  return {
    kind: "supplemental-completion",
    sourceRun: directory,
    sourceStudySha256: source.studySha256,
    sourceBaselineSha256,
    baselineSha256: digest(baseline),
    authorizationSha256: digest(authorization),
    reason: authorization.reason,
    retained: retainedEvidence(directory, source),
  };
}

export function verifyContinuation(run, plan, ancestors = new Set()) {
  const continuation = plan.study.continuation;
  if (!continuation) return 0;
  const directory = path.resolve(run);
  requireCondition(
    !ancestors.has(directory) && ancestors.size < 16,
    "Invalid continuation ancestry",
  );
  const lineage = new Set([...ancestors, directory]);
  const supplemental = continuation.kind === "supplemental-completion";
  const baseline = JSON.parse(readArtifact(run, "quota-baseline.json"));
  const expected = supplemental
    ? describeSupplementalContinuation(
        continuation.sourceRun,
        plan.study,
        baseline,
        JSON.parse(readArtifact(run, "supplemental-authorization.json")),
        lineage,
      )
    : describeContinuation(continuation.sourceRun, plan.study, continuation.reason, lineage);
  requireCondition(
    digest(expected) === digest(continuation),
    "Retained continuation evidence changed",
  );
  requireCondition(
    digest(baseline) === expected.baselineSha256,
    supplemental
      ? "Supplemental allowance baseline changed"
      : "Continuation must preserve the original allowance",
  );
  if (supplemental) {
    requireCondition(
      readArtifact(run, "quota-baseline.sha256").toString() === expected.baselineSha256,
      "Supplemental allowance baseline changed",
    );
    requireCondition(
      readArtifact(run, "supplemental-authorization.sha256").toString() ===
        expected.authorizationSha256,
      "Supplemental completion authorization changed",
    );
  }
  return expected.retained.length;
}
