import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { validateConfirmatoryWorkflowCase } from "./lib/confirmatory-workflow.mjs";
import { validateRepositoryConfirmatoryCorpus } from "./lib/repository-corpus.mjs";
import {
  confirmatoryRegistrationFilename,
  validateRepositoryConfirmatoryRegistration,
} from "./lib/repository-confirmatory-registration.mjs";
import { validateRepositorySnapshot } from "./lib/repository-snapshot.mjs";
import { artifactPath, readArtifact } from "./lib/workflow-artifacts.mjs";
import { requireCondition } from "./lib/workflow-contract.mjs";
import { digest } from "./lib/workflow-plan.mjs";
import { deployHarness } from "./lib/vm-harness.mjs";
import { guestCommand, workRoot } from "./lib/vm-guest.mjs";
import { writeNewJson } from "./lib/workflow-store.mjs";

const [
  screeningDirectory,
  eligibilityDirectory,
  qualificationDirectory,
  destination,
  productFile,
  ...extra
] = process.argv.slice(2);
if (
  !screeningDirectory ||
  !eligibilityDirectory ||
  !qualificationDirectory ||
  !destination ||
  !productFile ||
  extra.length
)
  throw new Error(
    "Usage: qualify-confirmatory-workflows.mjs SCREENING_DIRECTORY ELIGIBILITY_DIRECTORY QUALIFICATION_DIRECTORY NEW_OUTPUT_DIRECTORY PRODUCT_RECEIPT",
  );
const output = path.resolve(destination);
requireCondition(
  path.dirname(output) === path.resolve(workRoot) &&
    /^[a-z0-9][a-z0-9.-]*$/.test(path.basename(output)) &&
    !existsSync(output),
  "Workflow output must be a new direct child of tools/benchmark/.work",
);
const screeningRoot = path.dirname(
  artifactPath(path.resolve(screeningDirectory), "screening.json"),
);
const eligibilityRoot = path.dirname(
  artifactPath(path.resolve(eligibilityDirectory), "eligibility.json"),
);
const qualificationRoot = path.dirname(
  artifactPath(path.resolve(qualificationDirectory), "qualification.json"),
);
const corpus = validateRepositoryConfirmatoryCorpus(
  JSON.parse(readArtifact(screeningRoot, "intake.json").toString("utf8")),
);
const screening = JSON.parse(readArtifact(screeningRoot, "screening.json").toString("utf8"));
const eligibility = JSON.parse(readArtifact(eligibilityRoot, "eligibility.json").toString("utf8"));
const qualification = JSON.parse(
  readArtifact(qualificationRoot, "qualification.json").toString("utf8"),
);
const registration = JSON.parse(
  readArtifact(
    path.dirname(new URL(import.meta.url).pathname),
    `cases/${confirmatoryRegistrationFilename(corpus.id)}`,
  ).toString("utf8"),
);
const productPath = path.resolve(productFile);
const product = JSON.parse(
  readArtifact(path.dirname(productPath), path.basename(productPath)).toString("utf8"),
);
requireCondition(
  screening.corpusId === corpus.id &&
    screening.intakeSha256 === digest(corpus) &&
    screening.passed === true &&
    eligibility.corpusId === corpus.id &&
    eligibility.corpusSha256 === digest(corpus) &&
    eligibility.sourceScreeningSha256 === digest(screening) &&
    eligibility.passed === true &&
    eligibility.modelCalls === 0 &&
    qualification.corpusId === corpus.id &&
    qualification.corpusSha256 === digest(corpus) &&
    qualification.eligibilitySha256 === digest(eligibility) &&
    qualification.registrationSha256 === digest(registration) &&
    qualification.passed === true &&
    qualification.modelCalls === 0 &&
    registration.corpusId === corpus.id &&
    registration.corpusSha256 === digest(corpus) &&
    registration.eligibilitySha256 === digest(eligibility) &&
    product.commit === eligibility.product.commit &&
    product.cliSha256 === eligibility.product.cliSha256,
  "Confirmatory workflow evidence identities differ",
);
validateRepositoryConfirmatoryRegistration(registration, corpus, eligibility);
for (const item of qualification.cases) {
  const evidence = JSON.parse(readArtifact(qualificationRoot, item.artifact).toString("utf8"));
  requireCondition(
    item.passed && evidence.passed && item.sha256 === digest(evidence),
    `Qualification evidence for ${item.id} is invalid`,
  );
}

mkdirSync(output, { mode: 0o700 });
mkdirSync(path.join(output, "cases"), { mode: 0o700 });
const harness = deployHarness();
for (const [name, value] of [
  ["intake.json", corpus],
  ["source-screening.json", screening],
  ["eligibility.json", eligibility],
  ["qualification.json", qualification],
  ["registration.json", registration],
  ["product.json", product],
  ["harness.json", harness],
])
  writeNewJson(path.join(output, name), value);

const runId = randomBytes(16).toString("hex");
const cases = [];
for (const item of corpus.cases) {
  const source = screening.cases.find((candidate) => candidate.id === item.id);
  requireCondition(source?.sourceCompatible, `Source for ${item.id} is not qualified`);
  const baseline = validateRepositorySnapshot(
    JSON.parse(readArtifact(screeningRoot, source.baselineSource).toString("utf8")),
  );
  process.stdout.write(`Checking ${item.id} across normal, report, and MCP workflows.\n`);
  const result = JSON.parse(
    guestCommand(
      [
        "sudo",
        "flock",
        "--nonblock",
        "/run/sitecmd-benchmark-execution.lock",
        "node",
        `${harness.directory}/confirmatory-workflow.mjs`,
      ],
      {
        input: JSON.stringify({
          runId,
          caseId: item.id,
          corpus,
          eligibility,
          qualification,
          registration,
          product,
          baseline,
        }),
        capture: true,
        timeout: 900000,
        maxBuffer: 64 * 1024 * 1024,
      },
    ),
  );
  if (result.passed) validateConfirmatoryWorkflowCase(item, result);
  writeNewJson(path.join(output, "cases", `${item.id}.json`), result);
  cases.push({
    id: item.id,
    artifact: `cases/${item.id}.json`,
    sha256: digest(result),
    passed: result.passed,
    error: result.validationError ?? result.results?.find((entry) => entry.error)?.error ?? null,
  });
  process.stdout.write(`${item.id}: ${result.passed ? "ready" : "failed"}\n`);
}
const receipt = {
  schemaVersion: 1,
  capturedAt: new Date().toISOString(),
  corpusId: corpus.id,
  corpusSha256: digest(corpus),
  eligibilitySha256: digest(eligibility),
  qualificationSha256: digest(qualification),
  registrationSha256: digest(registration),
  purpose: "confirmatory workflow qualification before repair-agent trials",
  modelCalls: 0,
  agentInvoked: false,
  product,
  harnessSha256: harness.id,
  cases,
  passed: cases.every((item) => item.passed),
};
writeNewJson(path.join(output, "workflow.json"), receipt);
process.stdout.write(`Evidence: ${path.join(output, "workflow.json")}\n`);
if (!receipt.passed) process.exitCode = 1;
