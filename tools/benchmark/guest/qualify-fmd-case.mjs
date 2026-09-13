import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  materializeRepositoryFiles,
  validateRepositoryFiles,
  validateRepositorySnapshot,
} from "../lib/repository-snapshot.mjs";
import { digest } from "../lib/workflow-plan.mjs";
import { fmdCaseId } from "./replacement-fmd-grader.mjs";
import { fmdRuntimeManifest, verifyFmdBrowserRuntime } from "./replacement-fmd-runtime.mjs";
import { gradeRepository } from "./repository-grader.mjs";

if (process.platform !== "linux" || process.getuid() !== 0) {
  throw new Error("FMD qualification requires the isolated guest controller");
}
const request = JSON.parse(readFileSync(0, "utf8"));
if (!/^[a-f0-9]{32}$/.test(request.runId ?? "")) {
  throw new Error("FMD qualification requires a unique run identity");
}
const baseline = validateRepositorySnapshot(request.baseline);
const reference = request.reference;
const { sha256: referenceSha256, ...referenceContent } = reference ?? {};
const manifest = fmdRuntimeManifest();
validateRepositoryFiles(reference?.files);
if (
  baseline.sha256 !== manifest.baselineSha256 ||
  reference?.schemaVersion !== 1 ||
  reference.kind !== "implementation-regions" ||
  reference.baselineSha256 !== baseline.sha256 ||
  referenceSha256 !== manifest.referenceSha256 ||
  referenceSha256 !== digest(referenceContent) ||
  JSON.stringify(reference.editableFiles) !== JSON.stringify([manifest.entry])
) {
  throw new Error("FMD qualification source differs from its runtime manifest");
}
const runtime = verifyFmdBrowserRuntime(request.runtime);
const output = path.join(
  "/srv/sitecmd-benchmark/replacement-qualification",
  request.runId,
  fmdCaseId,
);
mkdirSync(output, { recursive: true, mode: 0o700 });
const variants = {};
for (const [name, source] of [
  ["baseline", baseline],
  ["reference", reference],
]) {
  const candidate = path.join(output, name);
  materializeRepositoryFiles(source.files, candidate);
  variants[name] = {
    sourceSha256: source.sha256,
    grades: Array.from({ length: 3 }, () =>
      gradeRepository(
        {
          id: fmdCaseId,
          repository: "peterhel/fmd-server",
          runtime: "node",
          browserRuntime: runtime,
        },
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
  caseId: fmdCaseId,
  output,
  runtime,
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
