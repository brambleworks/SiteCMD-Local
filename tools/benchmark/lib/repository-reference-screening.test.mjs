import assert from "node:assert/strict";
import { test } from "node:test";
import { deriveRepositoryReference } from "./repository-reference.mjs";
import {
  createRepositoryReferenceScreening,
  resolveRepositoryReference,
} from "./repository-reference-screening.mjs";
import { digest } from "./workflow-plan.mjs";

function source(commit, value) {
  const content = {
    schemaVersion: 1,
    commit: commit.repeat(40),
    tree: commit.repeat(40),
    files: [
      { name: "app.js", mode: "100644", base64: Buffer.from(value).toString("base64") },
      { name: "LICENSE", mode: "100644", base64: Buffer.from("MIT").toString("base64") },
    ],
  };
  return { ...content, sha256: digest(content) };
}

test("packages scoped repair references against screened source identities", () => {
  const baseline = source("a", "unsafe");
  const upstream = source("b", "safe");
  const item = {
    id: "repair",
    kind: "repair",
    baselineCommit: baseline.commit,
    upstreamCommit: upstream.commit,
    editableFiles: ["app.js"],
    referenceStrategy: "implementation-only",
  };
  const corpus = { id: "corpus", cases: [item] };
  const screening = {
    corpusId: corpus.id,
    intakeSha256: digest(corpus),
    passed: true,
    modelCalls: 0,
    cases: [
      {
        id: item.id,
        sourceCompatible: true,
        originVerified: true,
        baseline: { sourceSha256: baseline.sha256 },
        upstream: { sourceSha256: upstream.sha256 },
      },
    ],
  };
  const reference = deriveRepositoryReference(baseline, upstream, item.editableFiles);
  const result = createRepositoryReferenceScreening(
    corpus,
    screening,
    [{ id: item.id, baseline, upstream, reference }],
    "2026-09-12T12:00:00.000Z",
  );
  assert.equal(result.receipt.passed, true);
  assert.deepEqual(result.receipt.cases[0].changedFiles, ["app.js"]);
  assert.equal(result.artifacts.get(result.receipt.cases[0].artifact), reference);
});

test("uses a screened repair instead of unrelated upstream changes", () => {
  const baseline = source("a", "unsafe\nkeep baseline");
  const upstream = source("b", "safe\nunrelated upstream");
  const item = {
    id: "repair",
    kind: "repair",
    baselineCommit: baseline.commit,
    upstreamCommit: upstream.commit,
    editableFiles: ["app.js"],
    referenceStrategy: "implementation-only",
  };
  const content = {
    schemaVersion: 1,
    kind: "implementation-only",
    baselineSha256: baseline.sha256,
    upstreamSha256: upstream.sha256,
    editableFiles: item.editableFiles,
    files: baseline.files.map((file) =>
      file.name === "app.js"
        ? { ...file, base64: Buffer.from("safe\nkeep baseline").toString("base64") }
        : file,
    ),
  };
  const reference = { ...content, sha256: digest(content) };
  const registered = {
    baselineSha256: baseline.sha256,
    upstreamSha256: upstream.sha256,
    reference: { kind: reference.kind, sha256: reference.sha256 },
  };
  const referenceRecord = {
    id: item.id,
    kind: reference.kind,
    baselineSha256: baseline.sha256,
    upstreamSha256: upstream.sha256,
    referenceSha256: reference.sha256,
    changedFiles: item.editableFiles,
    passed: true,
  };

  assert.notEqual(
    reference.sha256,
    deriveRepositoryReference(baseline, upstream, item.editableFiles).sha256,
  );
  assert.equal(
    resolveRepositoryReference({
      item,
      registered,
      baseline,
      upstream,
      referenceRecord,
      referenceArtifact: reference,
    }),
    reference,
  );
});

test("rejects out-of-scope changes and mismatched source receipts", () => {
  const baseline = source("a", "unsafe");
  const upstream = source("b", "safe");
  const item = {
    id: "repair",
    kind: "repair",
    baselineCommit: baseline.commit,
    upstreamCommit: upstream.commit,
    editableFiles: ["app.js"],
    referenceStrategy: "implementation-only",
  };
  const corpus = { id: "corpus", cases: [item] };
  const screening = {
    corpusId: corpus.id,
    intakeSha256: digest(corpus),
    passed: true,
    modelCalls: 0,
    cases: [
      {
        id: item.id,
        sourceCompatible: true,
        originVerified: true,
        baseline: { sourceSha256: baseline.sha256 },
        upstream: { sourceSha256: upstream.sha256 },
      },
    ],
  };
  const reference = deriveRepositoryReference(baseline, upstream, item.editableFiles);
  reference.files[1] = {
    ...reference.files[1],
    base64: Buffer.from("changed license").toString("base64"),
  };
  const { sha256: _sha256, ...content } = reference;
  reference.sha256 = digest(content);
  assert.throws(
    () =>
      createRepositoryReferenceScreening(
        corpus,
        screening,
        [{ id: item.id, baseline, upstream, reference }],
        "2026-09-12T12:00:00.000Z",
      ),
    /scope/i,
  );

  screening.cases[0].originVerified = false;
  assert.throws(
    () =>
      createRepositoryReferenceScreening(
        corpus,
        screening,
        [
          {
            id: item.id,
            baseline,
            upstream,
            reference: deriveRepositoryReference(baseline, upstream, item.editableFiles),
          },
        ],
        "2026-09-12T12:00:00.000Z",
      ),
    /source identity/i,
  );
});
