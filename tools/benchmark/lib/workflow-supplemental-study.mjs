import { readFileSync } from "node:fs";
import { requireCondition, requireHash, requireText, validateStudy } from "./workflow-contract.mjs";
import { canonicalJson } from "./workflow-plan.mjs";
import {
  confirmatoryStudyPolicy,
  validateConfirmatoryStudy,
} from "./workflow-confirmatory-study.mjs";

const policy = JSON.parse(
  readFileSync(new URL("../supplemental-study-policy.json", import.meta.url), "utf8"),
);
export const supplementalStudyPolicy = policy;

export function normalizeSupplementalBaseline(snapshot) {
  const baseline = structuredClone(snapshot);
  for (const account of baseline.accounts ?? [])
    for (const window of account.windows ?? []) delete window.accountingEpochs;
  return baseline;
}

export function buildSupplementalStudy(source, continuation, runnerSha256) {
  requireCondition(
    source?.id === policy.sourceStudyId && source.phase === "confirmatory",
    "Supplemental completion requires the registered confirmatory source",
  );
  requireHash(runnerSha256, "supplemental runner");
  const study = structuredClone(source);
  study.id = policy.studyId;
  study.phase = policy.phase;
  study.billing = structuredClone(policy.billing);
  study.runnerSha256 = runnerSha256;
  study.configurations = study.configurations.map((configuration) => ({
    ...configuration,
    environment: `${configuration.environment.replace(
      /; controller [a-f0-9]{64}$/,
      "",
    )}; controller ${runnerSha256}`,
  }));
  study.continuation = continuation;
  return study;
}

export function validateSupplementalStudy(study) {
  const same = (actual, expected, label) =>
    requireCondition(
      canonicalJson(actual) === canonicalJson(expected),
      `supplemental study ${label} differs from the registered policy`,
    );
  same(study?.id, policy.studyId, "id");
  same(study?.phase, policy.phase, "phase");
  same(study?.billing, policy.billing, "billing");
  same(study?.continuation?.kind, policy.continuationKind, "continuation kind");
  same(study?.continuation?.retained?.length, policy.retainedAssignments, "retained assignments");
  requireHash(study?.continuation?.sourceStudySha256, "source study");
  requireText(study?.continuation?.sourceRun, "supplemental source run");
  requireText(study?.continuation?.reason, "supplemental reason");
  for (const [value, label] of [
    [study?.continuation?.sourceBaselineSha256, "source allowance"],
    [study?.continuation?.baselineSha256, "supplemental allowance"],
    [study?.continuation?.authorizationSha256, "supplemental authorization"],
  ])
    requireHash(value, label);

  const { continuation: _continuation, ...registered } = structuredClone(study);
  registered.id = confirmatoryStudyPolicy.studyId;
  registered.phase = confirmatoryStudyPolicy.phase;
  registered.billing = structuredClone(confirmatoryStudyPolicy.billing);
  validateConfirmatoryStudy(registered);
  return validateStudy(study);
}
