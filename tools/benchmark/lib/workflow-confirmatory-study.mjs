import { readFileSync } from "node:fs";
import { requireCondition, validateStudy } from "./workflow-contract.mjs";
import { canonicalJson } from "./workflow-plan.mjs";

const v2Policy = JSON.parse(
  readFileSync(new URL("../confirmatory-study-policy.json", import.meta.url), "utf8"),
);
const v3Policy = JSON.parse(
  readFileSync(new URL("../confirmatory-v3-study-policy.json", import.meta.url), "utf8"),
);
export const confirmatoryStudyPolicy = v2Policy;
export const confirmatoryV3StudyPolicy = v3Policy;
export const confirmatoryStudyPolicies = Object.freeze([v2Policy, v3Policy]);

const designs = Object.freeze({
  [v2Policy.studyId]: {
    corpusId: "sitecmd-confirmatory-v2",
    repairs: 6,
    controls: 2,
    repositories: 7,
  },
  [v3Policy.studyId]: {
    corpusId: "sitecmd-confirmatory-v3",
    repairs: 24,
    controls: 8,
    repositories: 28,
  },
});

export function confirmatoryStudyPolicyForCorpus(corpusId) {
  const policy = confirmatoryStudyPolicies.find(
    (candidate) => designs[candidate.studyId]?.corpusId === corpusId,
  );
  requireCondition(policy, `confirmatory corpus ${corpusId} has no registered study policy`);
  return policy;
}

function selections(items) {
  return items
    .map(({ agent, model }) => ({ agent, model }))
    .sort(
      (left, right) =>
        left.agent.localeCompare(right.agent) || left.model.localeCompare(right.model),
    );
}

export function validateConfirmatoryStudy(study) {
  const policy = confirmatoryStudyPolicies.find((candidate) => candidate.studyId === study?.id);
  requireCondition(policy, "confirmatory study has no registered policy");
  const design = designs[policy.studyId];
  const same = (actual, expected, label) =>
    requireCondition(
      canonicalJson(actual) === canonicalJson(expected),
      `confirmatory study ${label} differs from the registered policy`,
    );
  same(study?.id, policy.studyId, "id");
  for (const key of [
    "phase",
    "repeats",
    "arms",
    "limits",
    "billing",
    "registration",
    "sampleSizeRationale",
    "analysis",
  ])
    same(study?.[key], policy[key], key);
  same(study?.tasks?.map(({ id }) => id).sort(), [...policy.caseIds].sort(), "cases");
  same(selections(study?.configurations ?? []), selections(policy.models), "models");
  requireCondition(
    study.tasks.filter((task) => task.kind === "repair").length === design.repairs &&
      study.tasks.filter((task) => task.kind === "negative_control").length === design.controls &&
      new Set(study.tasks.map((task) => task.repository)).size === design.repositories &&
      study.tasks.every(
        (task) =>
          task.confirmatory === true &&
          task.scannerObservedAtSelection === true &&
          task.holdout === true &&
          task.surface === "code" &&
          task.sourceFormat === "git-tree-v1" &&
          /^code_scan\.[a-z0-9.-]+$/.test(task.targetFinding?.checkId ?? "") &&
          typeof task.targetFinding?.relativePath === "string" &&
          /^sha256:[a-f0-9]{64}$/.test(task.targetFinding?.fingerprint ?? "") &&
          typeof task.targetFinding?.sourceAnchor === "string" &&
          task.targetFinding.sourceAnchor.length > 0,
      ),
    "confirmatory study tasks differ from the registered scanner-enriched design",
  );
  return validateStudy(study);
}
