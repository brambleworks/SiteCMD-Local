import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { validateRepositoryConfirmatoryCorpus } from "./lib/repository-corpus.mjs";
import {
  confirmatoryRegistrationFilename,
  validateRepositoryConfirmatoryRegistration,
} from "./lib/repository-confirmatory-registration.mjs";
import { evaluateRepositoryScannerCase } from "./lib/repository-scanner-eligibility.mjs";
import { repositoryQualificationRuntime } from "./lib/repository-qualification-runtime.mjs";
import {
  deriveRepositoryReference,
  validateRepositoryReference,
} from "./lib/repository-reference.mjs";
import { validateRepositorySnapshot } from "./lib/repository-snapshot.mjs";
import { artifactPath, readArtifact } from "./lib/workflow-artifacts.mjs";
import { requireCondition } from "./lib/workflow-contract.mjs";
import { digest } from "./lib/workflow-plan.mjs";
import { deployHarness } from "./lib/vm-harness.mjs";
import { guestCommand, workRoot } from "./lib/vm-guest.mjs";
import { writeNewJson } from "./lib/workflow-store.mjs";

const fmdQualificationTimeoutMs = 30 * 60_000;

const [
  screeningDirectory,
  eligibilityDirectory,
  destination,
  productFile,
  referenceDirectory,
  ...extra
] = process.argv.slice(2);
if (!screeningDirectory || !eligibilityDirectory || !destination || !productFile || extra.length)
  throw new Error(
    "Usage: qualify-confirmatory-corpus.mjs SCREENING_DIRECTORY ELIGIBILITY_DIRECTORY NEW_OUTPUT_DIRECTORY PRODUCT_RECEIPT [REFERENCE_DIRECTORY]",
  );
const output = path.resolve(destination);
requireCondition(
  path.dirname(output) === path.resolve(workRoot) &&
    /^[a-z0-9][a-z0-9.-]*$/.test(path.basename(output)) &&
    !existsSync(output),
  "Qualification output must be a new direct child of tools/benchmark/.work",
);
const screeningRoot = path.dirname(
  artifactPath(path.resolve(screeningDirectory), "screening.json"),
);
const eligibilityRoot = path.dirname(
  artifactPath(path.resolve(eligibilityDirectory), "eligibility.json"),
);
const referenceRoot = referenceDirectory
  ? path.dirname(artifactPath(path.resolve(referenceDirectory), "reference-screening.json"))
  : null;
const corpus = validateRepositoryConfirmatoryCorpus(
  JSON.parse(readArtifact(screeningRoot, "intake.json").toString("utf8")),
);
const screening = JSON.parse(readArtifact(screeningRoot, "screening.json").toString("utf8"));
const eligibility = JSON.parse(readArtifact(eligibilityRoot, "eligibility.json").toString("utf8"));
const references = referenceRoot
  ? JSON.parse(readArtifact(referenceRoot, "reference-screening.json").toString("utf8"))
  : undefined;
const registration = JSON.parse(
  readArtifact(
    path.dirname(new URL(import.meta.url).pathname),
    `cases/${confirmatoryRegistrationFilename(corpus.id)}`,
  ).toString("utf8"),
);
const product = JSON.parse(
  readArtifact(path.dirname(path.resolve(productFile)), path.basename(productFile)),
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
    product.commit === eligibility.product.commit &&
    product.cliSha256 === eligibility.product.cliSha256 &&
    (registration.referenceScreeningSha256 === undefined || references !== undefined),
  "Confirmatory source, scanner, and registration identities differ",
);
validateRepositoryConfirmatoryRegistration(registration, corpus, eligibility, references);

mkdirSync(output, { mode: 0o700 });
mkdirSync(path.join(output, "cases"), { mode: 0o700 });
const harness = deployHarness();
for (const [name, value] of [
  ["intake.json", corpus],
  ["source-screening.json", screening],
  ["eligibility.json", eligibility],
  ...(references ? [["reference-screening.json", references]] : []),
  ["registration.json", registration],
  ["product.json", product],
  ["harness.json", harness],
])
  writeNewJson(path.join(output, name), value);

const runId = randomBytes(16).toString("hex");
const cases = [];
let onekeyRuntime;
if (corpus.cases.some((item) => item.id === "onekey-http-client-tls-verification")) {
  const manifest = JSON.parse(
    readFileSync(new URL("./cases/onekey-runtime.json", import.meta.url), "utf8"),
  );
  const registered = registration.cases.find(
    (item) => item.id === "onekey-http-client-tls-verification",
  );
  requireCondition(
    registered?.runtimeManifestSha256 === digest(manifest),
    "OneKey runtime manifest differs from its registration",
  );
  onekeyRuntime = JSON.parse(
    guestCommand(
      [
        "sudo",
        "node",
        "--input-type=module",
        "-e",
        `import { inspectOnekeyRuntime } from '${harness.directory}/replacement-onekey-runtime.mjs'; console.log(JSON.stringify(inspectOnekeyRuntime()));`,
      ],
      { capture: true, timeout: 60000 },
    ),
  );
}
for (const item of corpus.cases) {
  const source = screening.cases.find((candidate) => candidate.id === item.id);
  const baseline = validateRepositorySnapshot(
    JSON.parse(readArtifact(screeningRoot, source.baselineSource).toString("utf8")),
  );
  const upstream = validateRepositorySnapshot(
    JSON.parse(readArtifact(screeningRoot, source.upstreamSource).toString("utf8")),
  );
  const registered = registration.cases.find((candidate) => candidate.id === item.id);
  const referenceRecord = references?.cases.find((candidate) => candidate.id === item.id);
  const reference = referenceRecord
    ? item.kind === "negative_control"
      ? validateRepositorySnapshot(
          JSON.parse(readArtifact(referenceRoot, referenceRecord.artifact).toString("utf8")),
        )
      : validateRepositoryReference(
          JSON.parse(readArtifact(referenceRoot, referenceRecord.artifact).toString("utf8")),
        )
    : item.kind === "negative_control"
      ? baseline
      : deriveRepositoryReference(
          baseline,
          upstream,
          item.editableFiles,
          registered.reference.regions,
        );
  requireCondition(
    reference.sha256 === registered.reference.sha256,
    `Reference source for ${item.id} differs from its registration`,
  );
  let browserRuntime;
  if (item.id === "fmd-device-text") {
    const manifest = JSON.parse(
      readFileSync(new URL("./cases/fmd-runtime.json", import.meta.url), "utf8"),
    );
    requireCondition(
      registered.runtimeManifestSha256 === digest(manifest),
      "FMD runtime manifest differs from its registration",
    );
    browserRuntime = JSON.parse(
      guestCommand(["sudo", "node", `${harness.directory}/install-fmd-runtime.mjs`], {
        input: JSON.stringify({ baseline, reference }),
        capture: true,
        timeout: 120000,
        maxBuffer: 16 * 1024 * 1024,
      }),
    );
  }
  process.stdout.write(`Qualifying ${item.id} three times per variant.\n`);
  const result = JSON.parse(
    guestCommand(
      [
        "sudo",
        "flock",
        "--nonblock",
        "/run/sitecmd-benchmark-execution.lock",
        "node",
        `${harness.directory}/qualify-confirmatory-case.mjs`,
      ],
      {
        input: JSON.stringify({
          runId,
          caseId: item.id,
          corpus,
          screening,
          eligibility,
          registration,
          referenceScreening: references,
          product,
          baseline,
          upstream,
          reference,
          repositoryRuntime:
            item.id === "onekey-http-client-tls-verification" ? onekeyRuntime : undefined,
          browserRuntime,
        }),
        capture: true,
        timeout: item.id === "fmd-device-text" ? fmdQualificationTimeoutMs : 600_000,
        maxBuffer: 32 * 1024 * 1024,
      },
    ),
  );
  const scanner = evaluateRepositoryScannerCase(
    item,
    result.variants.baseline.scan.report,
    result.variants.reference.scan.report,
  );
  const baselinePassed = result.variants.baseline.grades.every(
    (grade) => grade.acceptancePass === registered.baselineAcceptancePass && grade.regressionsPass,
  );
  const referencePassed = result.variants.reference.grades.every(
    (grade) => grade.acceptancePass && grade.regressionsPass,
  );
  const runtimeEvidence = repositoryQualificationRuntime(
    item.id,
    { repositoryRuntime: onekeyRuntime, browserRuntime },
    result.variants,
  );
  const runtimePassed = runtimeEvidence?.runtimePassed ?? true;
  const passed = baselinePassed && referencePassed && runtimePassed && scanner.eligible;
  const receipt = {
    ...result,
    ...runtimeEvidence,
    scanner,
    baselinePassed,
    referencePassed,
    passed,
  };
  writeNewJson(path.join(output, "cases", `${item.id}.json`), receipt);
  cases.push(receipt);
  process.stdout.write(`${item.id}: ${passed ? "qualified" : "rejected"}\n`);
}
const receipt = {
  schemaVersion: 1,
  capturedAt: new Date().toISOString(),
  corpusId: corpus.id,
  corpusSha256: digest(corpus),
  eligibilitySha256: digest(eligibility),
  ...(references ? { referenceScreeningSha256: digest(references) } : {}),
  registrationSha256: digest(registration),
  purpose: "scanner-enriched confirmatory qualification before repair-agent trials",
  scannerObserved: true,
  modelCalls: 0,
  product: eligibility.product,
  harnessSha256: harness.id,
  cases: cases.map((item) => ({
    id: item.id,
    artifact: `cases/${item.id}.json`,
    sha256: digest(item),
    passed: item.passed,
  })),
  passed: cases.every((item) => item.passed),
};
writeNewJson(path.join(output, "qualification.json"), receipt);
process.stdout.write(`Evidence: ${path.join(output, "qualification.json")}\n`);
if (!receipt.passed) process.exitCode = 1;
