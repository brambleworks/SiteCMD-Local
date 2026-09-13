import { validateRepositoryReference } from "./repository-reference.mjs";
import { validateRepositorySnapshot } from "./repository-snapshot.mjs";
import { requireCondition } from "./workflow-contract.mjs";
import { canonicalJson, digest } from "./workflow-plan.mjs";

function captureTime(value) {
  requireCondition(
    typeof value === "string" &&
      !Number.isNaN(Date.parse(value)) &&
      new Date(value).toISOString() === value,
    "Reference screening capture time must be an ISO timestamp",
  );
  return value;
}

function changedFiles(baseline, reference) {
  const before = new Map(baseline.files.map((file) => [file.name, file]));
  const after = new Map(reference.files.map((file) => [file.name, file]));
  requireCondition(
    before.size === after.size && [...before.keys()].every((name) => after.has(name)),
    "Reference file set differs from the frozen baseline",
  );
  return [...before]
    .filter(([name, file]) => canonicalJson(file) !== canonicalJson(after.get(name)))
    .map(([name]) => name)
    .sort();
}

export function createRepositoryReferenceScreening(corpus, screening, screened, capturedAt) {
  requireCondition(
    screening?.corpusId === corpus.id &&
      screening.intakeSha256 === digest(corpus) &&
      screening.passed === true &&
      screening.modelCalls === 0 &&
      Array.isArray(screening.cases) &&
      screening.cases.length === corpus.cases.length,
    "Source screening does not match the reference corpus",
  );
  requireCondition(
    Array.isArray(screened) &&
      screened.length === corpus.cases.length &&
      screened.every((result, index) => result.id === corpus.cases[index].id),
    "Reference results must preserve corpus case order",
  );
  const artifacts = new Map();
  const cases = screened.map((result, index) => {
    const item = corpus.cases[index];
    const source = screening.cases[index];
    const baseline = validateRepositorySnapshot(result.baseline);
    const upstream = validateRepositorySnapshot(result.upstream);
    requireCondition(
      source.id === item.id &&
        source.sourceCompatible === true &&
        source.originVerified === true &&
        baseline.commit === item.baselineCommit &&
        upstream.commit === item.upstreamCommit &&
        baseline.sha256 === source.baseline.sourceSha256 &&
        upstream.sha256 === source.upstream.sourceSha256,
      `Frozen source identity differs for ${item.id}`,
    );

    let reference;
    let kind;
    if (item.kind === "negative_control") {
      reference = validateRepositorySnapshot(result.reference);
      kind = "unchanged";
      requireCondition(
        reference.sha256 === baseline.sha256 && upstream.sha256 === baseline.sha256,
        `Negative control ${item.id} does not preserve its source`,
      );
    } else {
      reference = validateRepositoryReference(result.reference);
      kind = reference.kind;
      requireCondition(
        reference.baselineSha256 === baseline.sha256 &&
          reference.upstreamSha256 === upstream.sha256 &&
          reference.kind === item.referenceStrategy &&
          canonicalJson(reference.editableFiles) === canonicalJson(item.editableFiles),
        `Repair reference identity differs for ${item.id}`,
      );
    }
    const changes = changedFiles(baseline, reference);
    const expectedChanges = item.kind === "negative_control" ? [] : [...item.editableFiles].sort();
    requireCondition(
      canonicalJson(changes) === canonicalJson(expectedChanges),
      `Reference edit scope differs for ${item.id}`,
    );
    const artifact = `references/${reference.sha256}.json`;
    artifacts.set(artifact, reference);
    return {
      id: item.id,
      kind,
      baselineSha256: baseline.sha256,
      upstreamSha256: upstream.sha256,
      referenceSha256: reference.sha256,
      artifact,
      changedFiles: changes,
      ...(result.evidence ? { evidence: result.evidence } : {}),
      passed: true,
    };
  });
  return {
    receipt: {
      schemaVersion: 1,
      corpusId: corpus.id,
      corpusSha256: digest(corpus),
      sourceScreeningSha256: digest(screening),
      capturedAt: captureTime(capturedAt),
      scannerObserved: true,
      repairTrialsObserved: 0,
      modelCalls: 0,
      cases,
      passed: true,
    },
    artifacts,
  };
}
