import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  validateRepositorySnapshot,
  materializeRepositoryFiles,
} from "../lib/repository-snapshot.mjs";
import { verifyOnekeyRuntime } from "./replacement-onekey-runtime.mjs";
import { gradeRepository } from "./repository-grader.mjs";

if (process.platform !== "linux" || process.getuid() !== 0) {
  throw new Error("OneKey qualification requires the isolated guest controller");
}
const request = JSON.parse(readFileSync(0, "utf8"));
if (!/^[a-f0-9]{32}$/.test(request.runId ?? "")) {
  throw new Error("OneKey qualification requires a unique run identity");
}
const baseline = validateRepositorySnapshot(request.baseline);
const reference = validateRepositorySnapshot(request.reference);
const runtime = verifyOnekeyRuntime(request.runtime);
const output = path.join(
  "/srv/sitecmd-benchmark/replacement-qualification",
  request.runId,
  "onekey-http-client-tls-verification",
);
mkdirSync(output, { recursive: true, mode: 0o700 });
const variants = {};
for (const [name, snapshot] of [
  ["baseline", baseline],
  ["reference", reference],
]) {
  const candidate = path.join(output, name);
  materializeRepositoryFiles(snapshot.files, candidate);
  variants[name] = {
    sourceSha256: snapshot.sha256,
    grades: Array.from({ length: 3 }, () =>
      gradeRepository(
        {
          id: "onekey-http-client-tls-verification",
          repository: "onekey-sec/onekey",
          runtime: "python",
          repositoryRuntime: runtime,
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
  caseId: "onekey-http-client-tls-verification",
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
