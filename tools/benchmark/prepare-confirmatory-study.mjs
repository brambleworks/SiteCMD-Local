import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { validateConfirmatoryWorkflowCase } from "./lib/confirmatory-workflow.mjs";
import { validateRepositoryConfirmatoryCorpus } from "./lib/repository-corpus.mjs";
import { repositoryGraderIdentity } from "./lib/repository-grader-identity.mjs";
import {
  confirmatoryRegistrationFilename,
  validateRepositoryConfirmatoryRegistration,
} from "./lib/repository-confirmatory-registration.mjs";
import {
  repositoryQualificationRuntimeBinding,
  validateRepositoryQualificationRuntime,
} from "./lib/repository-qualification-runtime.mjs";
import { deriveRepositoryReference } from "./lib/repository-reference.mjs";
import { validateRepositorySnapshot } from "./lib/repository-snapshot.mjs";
import { repositoryScannerTargetIssue } from "./lib/repository-scanner-eligibility.mjs";
import { artifactPath, readArtifact } from "./lib/workflow-artifacts.mjs";
import { confirmatoryStudyPolicyForCorpus } from "./lib/workflow-confirmatory-study.mjs";
import { validateRunnableStudy } from "./lib/workflow-runnable-study.mjs";
import { requireCondition } from "./lib/workflow-contract.mjs";
import { digest } from "./lib/workflow-plan.mjs";
import { createStudyRun, writeNewJson } from "./lib/workflow-store.mjs";
import { trialConfigurations } from "./lib/trial-invocation.mjs";
import { deployHarness } from "./lib/vm-harness.mjs";

const [
  screeningDirectory,
  eligibilityDirectory,
  qualificationDirectory,
  workflowDirectory,
  output,
  productFile,
  ...extra
] = process.argv.slice(2);
if (
  !screeningDirectory ||
  !eligibilityDirectory ||
  !qualificationDirectory ||
  !workflowDirectory ||
  !output ||
  !productFile ||
  extra.length
)
  throw new Error(
    "Usage: prepare-confirmatory-study.mjs SCREENING_DIRECTORY ELIGIBILITY_DIRECTORY QUALIFICATION_DIRECTORY WORKFLOW_DIRECTORY NEW_RUN_DIRECTORY PRODUCT_RECEIPT",
  );
const run = path.resolve(output);
requireCondition(!existsSync(run), "Confirmatory run directory must be new");
const rootFor = (directory, receipt) =>
  path.dirname(artifactPath(path.resolve(directory), receipt));
const screeningRoot = rootFor(screeningDirectory, "screening.json");
const eligibilityRoot = rootFor(eligibilityDirectory, "eligibility.json");
const qualificationRoot = rootFor(qualificationDirectory, "qualification.json");
const workflowRoot = rootFor(workflowDirectory, "workflow.json");
const readJson = (root, name) => JSON.parse(readArtifact(root, name).toString("utf8"));
const corpusDefinition = validateRepositoryConfirmatoryCorpus(
  readJson(screeningRoot, "intake.json"),
);
const studyPolicy = confirmatoryStudyPolicyForCorpus(corpusDefinition.id);
const screening = readJson(screeningRoot, "screening.json");
const eligibility = readJson(eligibilityRoot, "eligibility.json");
const qualification = readJson(qualificationRoot, "qualification.json");
const workflow = readJson(workflowRoot, "workflow.json");
const registration = JSON.parse(
  readFileSync(
    new URL(`./cases/${confirmatoryRegistrationFilename(corpusDefinition.id)}`, import.meta.url),
  ),
);
const product = JSON.parse(readFileSync(path.resolve(productFile), "utf8"));
const same = (left, right, label) =>
  requireCondition(digest(left) === digest(right), `${label} identity differs`);
requireCondition(
  screening.corpusId === corpusDefinition.id &&
    screening.intakeSha256 === digest(corpusDefinition) &&
    screening.passed === true &&
    screening.modelCalls === 0 &&
    eligibility.corpusId === corpusDefinition.id &&
    eligibility.corpusSha256 === digest(corpusDefinition) &&
    eligibility.sourceScreeningSha256 === digest(screening) &&
    eligibility.passed === true &&
    eligibility.modelCalls === 0 &&
    qualification.corpusId === corpusDefinition.id &&
    qualification.corpusSha256 === digest(corpusDefinition) &&
    qualification.eligibilitySha256 === digest(eligibility) &&
    qualification.registrationSha256 === digest(registration) &&
    qualification.passed === true &&
    qualification.modelCalls === 0 &&
    workflow.corpusId === corpusDefinition.id &&
    workflow.corpusSha256 === digest(corpusDefinition) &&
    workflow.eligibilitySha256 === digest(eligibility) &&
    workflow.qualificationSha256 === digest(qualification) &&
    workflow.registrationSha256 === digest(registration) &&
    workflow.passed === true &&
    workflow.modelCalls === 0 &&
    product.commit === eligibility.product.commit &&
    product.sourceSha256 === eligibility.product.sourceSha256 &&
    product.cliSha256 === eligibility.product.cliSha256,
  "Confirmatory screening, eligibility, qualification, workflow, registration, or product differs",
);
validateRepositoryConfirmatoryRegistration(registration, corpusDefinition, eligibility);

const harness = deployHarness();
const qualificationHarness = readJson(qualificationRoot, "harness.json");
const workflowHarness = readJson(workflowRoot, "harness.json");
requireCondition(
  qualificationHarness.id === qualification.harnessSha256 &&
    workflowHarness.id === workflow.harnessSha256,
  "Stored qualification or workflow harness identity is invalid",
);
const protocol = readFileSync(
  new URL("../../docs/qa/agent-workflow-benchmark.md", import.meta.url),
);
const frozenCorpus = [];
const tasks = [];
const reports = new Map();
for (const item of corpusDefinition.cases) {
  const registered = registration.cases.find((candidate) => candidate.id === item.id);
  const source = screening.cases.find((candidate) => candidate.id === item.id);
  const scanner = eligibility.cases.find((candidate) => candidate.id === item.id);
  const qualificationIndex = qualification.cases.find((candidate) => candidate.id === item.id);
  const workflowIndex = workflow.cases.find((candidate) => candidate.id === item.id);
  requireCondition(
    registered &&
      source?.sourceCompatible &&
      source.originVerified &&
      scanner?.eligible &&
      qualificationIndex?.passed &&
      workflowIndex?.passed,
    `Case ${item.id} is missing required pretrial evidence`,
  );
  const baseline = validateRepositorySnapshot(readJson(screeningRoot, source.baselineSource));
  const upstream = validateRepositorySnapshot(readJson(screeningRoot, source.upstreamSource));
  const reference =
    item.kind === "negative_control"
      ? baseline
      : deriveRepositoryReference(
          baseline,
          upstream,
          item.editableFiles,
          registered.reference.regions,
        );
  requireCondition(
    baseline.commit === item.baselineCommit &&
      upstream.commit === item.upstreamCommit &&
      baseline.sha256 === registered.baselineSha256 &&
      upstream.sha256 === registered.upstreamSha256 &&
      reference.sha256 === registered.reference.sha256,
    `Case ${item.id} source or reference identity differs`,
  );
  const qualified = readJson(qualificationRoot, qualificationIndex.artifact);
  requireCondition(
    qualificationIndex.sha256 === digest(qualified) &&
      qualified.passed === true &&
      qualified.variants.baseline.sourceSha256 === baseline.sha256 &&
      qualified.variants.reference.sourceSha256 === reference.sha256 &&
      qualified.variants.baseline.grades.length === 3 &&
      qualified.variants.reference.grades.length === 3 &&
      qualified.variants.baseline.grades.every(
        (grade) =>
          grade.acceptancePass === registered.baselineAcceptancePass && grade.regressionsPass,
      ) &&
      qualified.variants.reference.grades.every(
        (grade) => grade.acceptancePass && grade.regressionsPass,
      ) &&
      validateRepositoryQualificationRuntime(item.id, qualified),
    `Case ${item.id} behavioral qualification is incomplete`,
  );
  const workflowCase = readJson(workflowRoot, workflowIndex.artifact);
  requireCondition(
    workflowIndex.sha256 === digest(workflowCase),
    `Case ${item.id} workflow changed`,
  );
  validateConfirmatoryWorkflowCase(item, workflowCase);
  const currentGrader = repositoryGraderIdentity(harness.files, item.id);
  const qualifiedGrader = repositoryGraderIdentity(qualificationHarness.files, item.id);
  same(currentGrader, qualifiedGrader, `${item.id} grader`);
  const rawReport = readArtifact(eligibilityRoot, scanner.baseline.artifact).toString("utf8");
  requireCondition(
    digest(Buffer.from(rawReport)) === scanner.baseline.sha256 &&
      qualified.scanner?.eligible === true &&
      qualified.scanner.baseline.targetFingerprintMatches === 1,
    `Case ${item.id} scanner qualification is incomplete`,
  );
  const targetIssue = repositoryScannerTargetIssue(item, scanner.baseline);
  const rule = item.targetFinding.checkId.replace(/^code_scan\./, "");
  const runtimeBinding = repositoryQualificationRuntimeBinding(item.id, qualified);
  frozenCorpus.push({
    id: item.id,
    repository: item.repository.id,
    kind: item.kind,
    runtime: item.runtime,
    entry: registered.entry,
    rule,
    confirmatory: true,
    targetFinding: item.targetFinding,
    targetIssue,
    ...(runtimeBinding ? { [runtimeBinding.runtimeField]: runtimeBinding.runtime } : {}),
    ...(registered.controlSourceSha256
      ? { controlSourceSha256: registered.controlSourceSha256 }
      : {}),
    baselineFiles: baseline,
    referenceFiles: reference,
  });
  reports.set(item.id, rawReport);
  tasks.push({
    id: item.id,
    repository: item.repository.id,
    kind: item.kind,
    runtime: item.runtime,
    entry: registered.entry,
    rule,
    confirmatory: true,
    scannerObservedAtSelection: true,
    targetFinding: item.targetFinding,
    surface: item.surface,
    category: item.category,
    prompt: item.task,
    requirements: item.requirements,
    provenance: `${item.repository.url}; ${item.kind === "repair" ? `historical public repair ${item.upstreamFix}` : "registered unchanged scanner false-positive control"}; selected before model trials from the frozen scanner-enriched population`,
    holdout: item.heldOut,
    sourceFormat: "git-tree-v1",
    editableFiles: item.editableFiles,
    sourceSha256: baseline.sha256,
    referenceSha256: reference.sha256,
    graderSha256: currentGrader,
    reportSha256: digest(rawReport),
    ...(runtimeBinding ? { [runtimeBinding.digestField]: runtimeBinding.sha256 } : {}),
    baseline: {
      acceptancePass: registered.baselineAcceptancePass,
      regressionsPass: true,
    },
    reference: { acceptancePass: true, regressionsPass: true },
    validatedBy:
      "Independent offline behavioral assertions repeated three times, exact scanner identity, source integrity checks, and real desktop, CLI, and MCP workflow qualification",
  });
}
const study = {
  schemaVersion: 1,
  id: studyPolicy.studyId,
  phase: studyPolicy.phase,
  seed: corpusDefinition.id === "sitecmd-confirmatory-v3" ? 20260912 : 20260909,
  repeats: studyPolicy.repeats,
  arms: studyPolicy.arms,
  limits: studyPolicy.limits,
  billing: studyPolicy.billing,
  protocol: "agent-workflow-v1-repository-confirmatory",
  protocolSha256: digest(protocol),
  registration: studyPolicy.registration,
  sampleSizeRationale: studyPolicy.sampleSizeRationale,
  analysis: studyPolicy.analysis,
  runnerSha256: harness.id,
  corpusSha256: digest(frozenCorpus),
  productSha256: digest(product),
  sitecmd: {
    version: product.version,
    commit: product.commit,
    dirty: false,
    mcpSha256: product.mcpSha256,
  },
  configurations: trialConfigurations(
    `${product.environment}; warm; controller ${harness.id}`,
    studyPolicy.models,
  ),
  tasks,
};
validateRunnableStudy(study);
const plan = createStudyRun(study, run);
mkdirSync(path.join(run, "inputs"), { mode: 0o700 });
for (const [name, value] of [
  ["corpus.json", frozenCorpus],
  ["intake.json", corpusDefinition],
  ["source-screening.json", screening],
  ["eligibility.json", eligibility],
  ["qualification.json", qualification],
  ["workflow.json", workflow],
  ["registration.json", registration],
  ["product.json", product],
  ["runner.json", harness.files],
])
  writeNewJson(path.join(run, "inputs", name), value);
for (const [id, report] of reports)
  writeFileSync(path.join(run, "inputs", `${id}-report.json`), report, {
    flag: "wx",
    mode: 0o600,
  });
writeFileSync(path.join(run, "inputs", "protocol.md"), protocol, {
  flag: "wx",
  mode: 0o600,
});
const emptyQuota = JSON.parse(readFileSync(new URL("./quota-template.json", import.meta.url)));
for (const name of ["quota-baseline.json", "quota-current.json"])
  writeNewJson(path.join(run, name), emptyQuota);
console.log(
  `Frozen ${plan.plannedTrials} confirmatory assignments at ${run}. No model calls made. Fresh quota evidence is required before execution.`,
);
