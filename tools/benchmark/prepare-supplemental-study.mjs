import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { artifactPath } from "./lib/workflow-artifacts.mjs";
import {
  describeSupplementalContinuation,
  verifyContinuation,
} from "./lib/workflow-continuation.mjs";
import { requireCondition, requireText } from "./lib/workflow-contract.mjs";
import { digest } from "./lib/workflow-plan.mjs";
import { evaluateQuota } from "./lib/workflow-quota.mjs";
import { validateRunnableStudy } from "./lib/workflow-runnable-study.mjs";
import { createStudyRun, loadPlan, writeNewJson } from "./lib/workflow-store.mjs";
import {
  buildSupplementalStudy,
  normalizeSupplementalBaseline,
  supplementalStudyPolicy,
} from "./lib/workflow-supplemental-study.mjs";
import { deployHarness } from "./lib/vm-harness.mjs";

const { positionals, values } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: {
    "approved-at": { type: "string" },
    "approved-by": { type: "string" },
    reason: { type: "string" },
  },
});
const [sourceInput, outputInput, quotaInput, ...extra] = positionals;
if (!sourceInput || !outputInput || !quotaInput || extra.length)
  throw new Error(
    "Usage: prepare-supplemental-study.mjs SOURCE_RUN NEW_RUN FRESH_QUOTA_JSON --approved-at ISO_TIMESTAMP --approved-by NAME --reason TEXT",
  );
for (const [value, label] of [
  [values["approved-at"], "approval timestamp"],
  [values["approved-by"], "approver"],
  [values.reason, "authorization reason"],
])
  requireText(value, label);

const sourceRun = path.resolve(sourceInput);
const output = path.resolve(outputInput);
requireCondition(!existsSync(output), "Supplemental run directory must be new");
const source = loadPlan(sourceRun);
validateRunnableStudy(source.study);
requireCondition(
  source.study.id === supplementalStudyPolicy.sourceStudyId,
  "Supplemental source is not the registered v2 study",
);
const approvedAt = Date.parse(values["approved-at"]);
requireCondition(
  Number.isFinite(approvedAt) && approvedAt <= Date.now(),
  "Supplemental approval timestamp is invalid or in the future",
);
const baseline = normalizeSupplementalBaseline(
  JSON.parse(readFileSync(path.resolve(quotaInput), "utf8")),
);
const quota = evaluateQuota(baseline, baseline, supplementalStudyPolicy.billing);
requireCondition(quota.quotaAllowed, quota.blockers.join("; "));
const authorization = {
  schemaVersion: 1,
  kind: supplementalStudyPolicy.continuationKind,
  sourceStudySha256: source.studySha256,
  approvedAt: new Date(approvedAt).toISOString(),
  approvedBy: values["approved-by"],
  reason: values.reason,
  billing: structuredClone(supplementalStudyPolicy.billing),
};
const harness = deployHarness();
const draft = buildSupplementalStudy(source.study, undefined, harness.id);
const continuation = describeSupplementalContinuation(sourceRun, draft, baseline, authorization);
const study = buildSupplementalStudy(source.study, continuation, harness.id);
validateRunnableStudy(study);

const sourceInputs = artifactPath(sourceRun, "inputs", { directory: true });
const inputs = new Map();
for (const entry of readdirSync(sourceInputs, { withFileTypes: true })) {
  if (entry.isDirectory()) {
    requireCondition(
      /^[a-f0-9]{24}$/.test(entry.name),
      "Supplemental source contains an unknown input directory",
    );
    continue;
  }
  requireCondition(entry.isFile(), "Supplemental source inputs must be regular files");
  if (entry.name !== "runner.json")
    inputs.set(entry.name, readFileSync(path.join(sourceInputs, entry.name)));
}
const plan = createStudyRun(study, output);
requireCondition(
  plan.plannedTrials === supplementalStudyPolicy.supplementalAssignments,
  "Supplemental assignment count differs from the registered policy",
);
mkdirSync(path.join(output, "inputs"), { mode: 0o700 });
for (const [name, bytes] of inputs)
  writeFileSync(path.join(output, "inputs", name), bytes, { flag: "wx", mode: 0o600 });
writeNewJson(path.join(output, "inputs", "runner.json"), harness.files);
for (const name of ["quota-baseline.json", "quota-current.json"])
  writeNewJson(path.join(output, name), baseline);
writeFileSync(path.join(output, "quota-baseline.sha256"), digest(baseline), {
  flag: "wx",
  mode: 0o600,
});
writeNewJson(path.join(output, "supplemental-authorization.json"), authorization);
writeFileSync(path.join(output, "supplemental-authorization.sha256"), digest(authorization), {
  flag: "wx",
  mode: 0o600,
});
verifyContinuation(output, plan);
console.log(
  `Frozen ${plan.plannedTrials} supplemental assignments at ${output}. The original run remains unchanged and incomplete; these results cannot be reported as confirmatory evidence.`,
);
