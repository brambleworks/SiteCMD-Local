import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  validateRepositoryFiles,
  validateRepositorySnapshot,
  materializeRepositoryFiles,
} from "../lib/repository-snapshot.mjs";
import { digest } from "../lib/workflow-plan.mjs";
import { replacementCaseDefinition } from "./replacement-cases.mjs";
import { gradeRepository } from "./repository-grader.mjs";

if (process.platform !== "linux" || process.getuid() !== 0) {
  throw new Error("Replacement qualification requires the isolated guest controller");
}

const request = JSON.parse(readFileSync(0, "utf8"));
if (!/^[a-f0-9]{32}$/.test(request.runId ?? "")) {
  throw new Error("Replacement qualification requires a unique run identity");
}

const definition = replacementCaseDefinition(request.caseId);
const baseline = validateRepositorySnapshot(request.baseline);
const reference = request.reference;
const { sha256: referenceSha256, ...referenceContent } = reference ?? {};
validateRepositoryFiles(reference?.files);
if (
  reference?.schemaVersion !== 1 ||
  reference.kind !== "implementation-only" ||
  reference.baselineSha256 !== baseline.sha256 ||
  referenceSha256 !== digest(referenceContent) ||
  JSON.stringify(reference.editableFiles) !== JSON.stringify(definition.files)
) {
  throw new Error("Replacement reference identity or scope differs from its manifest");
}

function selectFiles(files) {
  const byName = new Map(files.map((file) => [file.name, file]));
  const selected = definition.files.map((name) => byName.get(name));
  if (selected.some((file) => !file)) {
    throw new Error("Replacement candidate is missing a required source file");
  }
  return selected;
}

const output = path.join(
  "/srv/sitecmd-benchmark/replacement-qualification",
  request.runId,
  request.caseId,
);
mkdirSync(output, { recursive: true, mode: 0o700 });
const variants = {};
for (const [name, snapshot] of [
  ["baseline", baseline],
  ["reference", reference],
]) {
  const candidate = path.join(output, name);
  materializeRepositoryFiles(selectFiles(snapshot.files), candidate);
  variants[name] = {
    sourceSha256: snapshot.sha256,
    grades: Array.from({ length: 3 }, () =>
      gradeRepository(
        { id: request.caseId, repository: request.repository, runtime: request.runtime },
        candidate,
      ),
    ),
  };
}

const passed =
  variants.baseline.grades.every(
    (grade) => !grade.acceptancePass && grade.regressionsPass && !grade.probeError,
  ) &&
  variants.reference.grades.every(
    (grade) => grade.acceptancePass && grade.regressionsPass && !grade.probeError,
  );
const receipt = {
  schemaVersion: 1,
  capturedAt: new Date().toISOString(),
  caseId: request.caseId,
  repository: request.repository,
  family: definition.family,
  files: definition.files,
  output,
  variants,
  passed,
  modelCalls: 0,
  environment: {
    node: process.version,
    architecture: process.arch,
    platform: process.platform,
  },
};
writeFileSync(path.join(output, "qualification.json"), JSON.stringify(receipt), {
  flag: "wx",
  mode: 0o600,
});
console.log(JSON.stringify(receipt));
