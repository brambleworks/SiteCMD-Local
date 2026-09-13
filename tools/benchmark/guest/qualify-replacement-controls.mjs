import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  materializeRepositoryFiles,
  validateRepositorySnapshot,
} from "../lib/repository-snapshot.mjs";
import { controlFileSha256, controlTreeEvidence } from "./replacement-control-hash.mjs";
import {
  replacementControlCaseIds,
  replacementControlDefinition,
} from "./replacement-control-cases.mjs";
import { gradeRepository } from "./repository-grader.mjs";

if (process.platform !== "linux" || process.getuid() !== 0) {
  throw new Error("Control qualification requires the isolated guest controller");
}
const request = JSON.parse(readFileSync(0, "utf8"));
if (!/^[a-f0-9]{32}$/.test(request.runId ?? "")) {
  throw new Error("Control qualification requires a unique run identity");
}
if (
  !Array.isArray(request.controls) ||
  request.controls.length !== replacementControlCaseIds.length ||
  request.controls.some((control, index) => control.id !== replacementControlCaseIds[index])
) {
  throw new Error("Control qualification selection differs from its grader manifest");
}

function replace(files, name, update) {
  return files.map((file) => (file.name === name ? update({ ...file }) : { ...file }));
}

function mutateByte(base64) {
  const contents = Buffer.from(base64, "base64");
  if (!contents.length) throw new Error("Control target is unexpectedly empty");
  contents[0] ^= 1;
  return contents.toString("base64");
}

const output = path.join(
  "/srv/sitecmd-benchmark/replacement-qualification",
  request.runId,
  "negative-controls",
);
mkdirSync(output, { recursive: true, mode: 0o700 });
const rows = [];
for (const control of request.controls) {
  const definition = replacementControlDefinition(control.id);
  const source = validateRepositorySnapshot(control.source);
  const entries = source.files.map((file) => ({
    name: file.name,
    mode: file.mode,
    contents: Buffer.from(file.base64, "base64"),
  }));
  const target = entries.find((file) => file.name === definition.targetPath);
  const evidence = controlTreeEvidence(entries);
  if (
    source.sha256 !== definition.sourceSha256 ||
    evidence.treeSha256 !== definition.treeSha256 ||
    evidence.fileCount !== definition.fileCount ||
    evidence.bytes !== definition.bytes ||
    !target ||
    controlFileSha256(target.contents) !== definition.targetSha256
  ) {
    throw new Error(`Control source differs from its grader manifest: ${control.id}`);
  }
  const other = source.files.find((file) => file.name !== definition.targetPath);
  if (!other) throw new Error(`Control source has no non-target file: ${control.id}`);
  const addedFile = "sitecmd-benchmark-unexpected.txt";
  if (source.files.some((file) => file.name === addedFile)) {
    throw new Error(`Control source already contains its added-file mutation: ${control.id}`);
  }
  const variants = [
    { name: "unchanged", expected: true, files: source.files },
    { name: "unchanged-copy", expected: true, files: structuredClone(source.files) },
    {
      name: "target-comment-edit",
      expected: false,
      files: replace(source.files, definition.targetPath, (file) => ({
        ...file,
        base64: Buffer.concat([
          Buffer.from(file.base64, "base64"),
          Buffer.from("\n// benchmark mutation\n"),
        ]).toString("base64"),
      })),
    },
    {
      name: "target-single-byte-edit",
      expected: false,
      files: replace(source.files, definition.targetPath, (file) => ({
        ...file,
        base64: mutateByte(file.base64),
      })),
    },
    {
      name: "target-empty",
      expected: false,
      files: replace(source.files, definition.targetPath, (file) => ({ ...file, base64: "" })),
    },
    {
      name: "non-target-edit",
      expected: false,
      files: replace(source.files, other.name, (file) => ({
        ...file,
        base64: Buffer.concat([
          Buffer.from(file.base64, "base64"),
          Buffer.from("benchmark mutation"),
        ]).toString("base64"),
      })),
    },
    {
      name: "target-mode-change",
      expected: false,
      files: replace(source.files, definition.targetPath, (file) => ({
        ...file,
        mode: file.mode === "100755" ? "100644" : "100755",
      })),
    },
    {
      name: "target-deleted",
      expected: false,
      files: source.files.filter((file) => file.name !== definition.targetPath),
    },
    {
      name: "file-added",
      expected: false,
      files: [
        ...source.files,
        {
          name: addedFile,
          mode: "100644",
          base64: Buffer.from("unexpected").toString("base64"),
        },
      ],
    },
  ];
  const results = [];
  for (const variant of variants) {
    const candidate = path.join(output, control.id, variant.name);
    mkdirSync(path.dirname(candidate), { recursive: true, mode: 0o700 });
    materializeRepositoryFiles(variant.files, candidate);
    results.push({
      name: variant.name,
      expected: variant.expected,
      grades: Array.from({ length: 3 }, () =>
        gradeRepository(
          { id: control.id, repository: control.repository, runtime: "node" },
          candidate,
        ),
      ),
    });
  }
  rows.push({
    id: control.id,
    repository: control.repository,
    sourceSha256: source.sha256,
    results,
    passed: results.every((result) =>
      result.grades.every(
        (grade) =>
          grade.acceptancePass === result.expected &&
          grade.regressionsPass === result.expected &&
          !grade.probeError,
      ),
    ),
  });
}
const receipt = {
  schemaVersion: 1,
  capturedAt: new Date().toISOString(),
  output,
  controls: rows.length,
  variants: rows.reduce((total, row) => total + row.results.length, 0),
  repeatedCandidateRuns: rows.reduce(
    (total, row) => total + row.results.reduce((count, result) => count + result.grades.length, 0),
    0,
  ),
  rows,
  passed: rows.every((row) => row.passed),
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
