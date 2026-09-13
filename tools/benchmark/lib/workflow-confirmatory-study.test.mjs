import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fixtureStudy } from "./workflow-fixture.mjs";
import { createPlan, digest } from "./workflow-plan.mjs";
import {
  confirmatoryStudyPolicy,
  confirmatoryStudyPolicyForCorpus,
  confirmatoryV3StudyPolicy,
  validateConfirmatoryStudy,
} from "./workflow-confirmatory-study.mjs";
import { validateRunnableStudy } from "./workflow-runnable-study.mjs";
import {
  supplementalStudyPolicy,
  validateSupplementalStudy,
} from "./workflow-supplemental-study.mjs";
import { agentVersions, reasoning } from "./trial-invocation.mjs";

function confirmatoryStudy() {
  const fixture = fixtureStudy();
  const template = fixture.tasks[0];
  const controlIds = new Set([
    "claude-code-templates-loopback-control",
    "liveatlas-entity-decoder-control",
  ]);
  return {
    ...fixture,
    id: confirmatoryStudyPolicy.studyId,
    phase: confirmatoryStudyPolicy.phase,
    repeats: confirmatoryStudyPolicy.repeats,
    arms: structuredClone(confirmatoryStudyPolicy.arms),
    limits: structuredClone(confirmatoryStudyPolicy.limits),
    billing: structuredClone(confirmatoryStudyPolicy.billing),
    registration: confirmatoryStudyPolicy.registration,
    sampleSizeRationale: confirmatoryStudyPolicy.sampleSizeRationale,
    analysis: structuredClone(confirmatoryStudyPolicy.analysis),
    sitecmd: { ...fixture.sitecmd, dirty: false },
    configurations: confirmatoryStudyPolicy.models.map(({ agent, model }) => ({
      id: `${agent}-${model.replaceAll(".", "-")}-${reasoning}`,
      agent,
      model,
      agentVersion: agentVersions[agent],
      reasoning,
      environment: "isolated confirmatory fixture",
    })),
    tasks: confirmatoryStudyPolicy.caseIds.map((id, index) => ({
      ...template,
      id,
      repository: id.startsWith("claude-code-templates-")
        ? "claude-code-templates"
        : `repository-${index}`,
      kind: controlIds.has(id) ? "negative_control" : "repair",
      holdout: true,
      confirmatory: true,
      scannerObservedAtSelection: true,
      sourceFormat: "git-tree-v1",
      editableFiles: ["src/entry.ts"],
      targetFinding: {
        checkId: "code_scan.unsafe-html",
        relativePath: "src/entry.ts",
        fingerprint: `sha256:${String(index).padStart(64, "0")}`,
        sourceAnchor: "unsafe assignment",
      },
      baseline: controlIds.has(id)
        ? { acceptancePass: true, regressionsPass: true }
        : template.baseline,
    })),
  };
}

function confirmatoryV3Study() {
  const fixture = fixtureStudy();
  const template = fixture.tasks[0];
  const corpus = JSON.parse(
    readFileSync(new URL("../cases/repository-confirmatory-v3.json", import.meta.url)),
  );
  return {
    ...fixture,
    id: confirmatoryV3StudyPolicy.studyId,
    phase: confirmatoryV3StudyPolicy.phase,
    repeats: confirmatoryV3StudyPolicy.repeats,
    arms: structuredClone(confirmatoryV3StudyPolicy.arms),
    limits: structuredClone(confirmatoryV3StudyPolicy.limits),
    billing: structuredClone(confirmatoryV3StudyPolicy.billing),
    registration: confirmatoryV3StudyPolicy.registration,
    sampleSizeRationale: confirmatoryV3StudyPolicy.sampleSizeRationale,
    analysis: structuredClone(confirmatoryV3StudyPolicy.analysis),
    sitecmd: { ...fixture.sitecmd, dirty: false },
    configurations: confirmatoryV3StudyPolicy.models.map(({ agent, model }) => ({
      id: `${agent}-${model.replaceAll(".", "-")}-${reasoning}`,
      agent,
      model,
      agentVersion: agentVersions[agent],
      reasoning,
      environment: "isolated confirmatory fixture",
    })),
    tasks: corpus.cases.map((item) => ({
      ...template,
      id: item.id,
      repository: item.repository.id,
      kind: item.kind,
      holdout: true,
      confirmatory: true,
      scannerObservedAtSelection: true,
      sourceFormat: "git-tree-v1",
      editableFiles: item.editableFiles,
      targetFinding: item.targetFinding,
      baseline:
        item.kind === "negative_control"
          ? { acceptancePass: true, regressionsPass: true }
          : template.baseline,
    })),
  };
}

test("invalidated v2 preserves its 96-assignment design but cannot run again", () => {
  const study = validateConfirmatoryStudy(confirmatoryStudy());
  const plan = createPlan(study);
  assert.equal(plan.plannedTrials, 96);
  assert.equal(study.tasks.filter((task) => task.kind === "repair").length, 6);
  assert.equal(study.tasks.filter((task) => task.kind === "negative_control").length, 2);
  assert.ok(study.configurations.some(({ model }) => model === "gpt-daybreak-blue-latest"));
  assert.throws(() => validateRunnableStudy(study), /invalidated.*diagnostic/);
});

test("v3 registers the complete 384-assignment replacement study", () => {
  const study = validateConfirmatoryStudy(confirmatoryV3Study());
  const plan = createPlan(study);
  assert.equal(
    confirmatoryStudyPolicyForCorpus("sitecmd-confirmatory-v3"),
    confirmatoryV3StudyPolicy,
  );
  assert.equal(plan.plannedTrials, 384);
  assert.equal(study.tasks.filter((task) => task.kind === "repair").length, 24);
  assert.equal(study.tasks.filter((task) => task.kind === "negative_control").length, 8);
  assert.equal(new Set(study.tasks.map((task) => task.repository)).size, 28);
  assert.equal(validateRunnableStudy(study), study);
});

test("confirmatory policy rejects post-registration changes", () => {
  for (const change of [
    (study) => study.tasks.pop(),
    (study) => {
      study.configurations[0].model = "latest";
    },
    (study) => {
      study.analysis.primaryEndpoint = "final-acceptance";
    },
    (study) => {
      study.limits.trialSeconds = 2400;
    },
    (study) => {
      study.tasks[0].scannerObservedAtSelection = false;
    },
    (study) => {
      study.tasks[0].holdout = false;
    },
  ]) {
    const study = confirmatoryStudy();
    change(study);
    assert.throws(() => validateConfirmatoryStudy(study), /confirmatory study|confirmatory tasks/);
  }
});

test("supplemental policy registers only a labeled suffix of the v2 study", () => {
  const source = confirmatoryStudy();
  const sourcePlan = createPlan(source);
  const study = structuredClone(source);
  study.id = supplementalStudyPolicy.studyId;
  study.phase = supplementalStudyPolicy.phase;
  study.billing = structuredClone(supplementalStudyPolicy.billing);
  study.continuation = {
    kind: "supplemental-completion",
    sourceRun: "/frozen/confirmatory-v2",
    sourceStudySha256: sourcePlan.studySha256,
    sourceBaselineSha256: digest("source allowance"),
    baselineSha256: digest("fresh allowance"),
    authorizationSha256: digest("operator authorization"),
    reason: "Operator authorized completing the unrun suffix as supplemental evidence",
    retained: sourcePlan.assignments.slice(0, 75).map(({ id, ...assignment }) => ({
      ...assignment,
      trialId: id,
      recordSha256: digest(`record:${id}`),
    })),
  };

  assert.equal(validateSupplementalStudy(study), study);
  assert.throws(() => validateRunnableStudy(study), /invalidated.*diagnostic/);

  const changed = structuredClone(study);
  changed.tasks.pop();
  assert.throws(() => validateSupplementalStudy(changed), /supplemental study|confirmatory study/);

  const shortened = structuredClone(study);
  shortened.continuation.retained.pop();
  assert.throws(() => validateSupplementalStudy(shortened), /retained assignments/);
});
