import { requireCondition, requireHash } from "./workflow-contract.mjs";
import { canonicalJson, digest } from "./workflow-plan.mjs";

const corpusFiles = Object.freeze({
  "sitecmd-confirmatory-v2": "repository-confirmatory-v2.json",
  "sitecmd-confirmatory-v3": "repository-confirmatory-v3.json",
});

const registrationFiles = Object.freeze({
  "sitecmd-confirmatory-v2": "repository-confirmatory-registration.json",
  "sitecmd-confirmatory-v3": "repository-confirmatory-v3-registration.json",
});

export function confirmatoryCorpusFilename(corpusId) {
  const name = corpusFiles[corpusId];
  if (!name) throw new Error(`Unsupported confirmatory corpus: ${corpusId}`);
  return name;
}

export function confirmatoryRegistrationFilename(corpusId) {
  const name = registrationFiles[corpusId];
  if (!name) throw new Error(`Unsupported confirmatory corpus: ${corpusId}`);
  return name;
}

export function validateRepositoryConfirmatoryRegistration(
  registration,
  corpus,
  eligibility,
  referenceScreening,
) {
  requireCondition(
    registration?.schemaVersion === 1 &&
      registration.corpusId === corpus.id &&
      registration.corpusSha256 === digest(corpus) &&
      registration.eligibilitySha256 === digest(eligibility) &&
      Number.isSafeInteger(registration.qualificationVersion) &&
      registration.qualificationVersion > 0 &&
      Array.isArray(registration.cases) &&
      registration.cases.length === corpus.cases.length,
    "Confirmatory registration identity differs",
  );
  if (referenceScreening !== undefined) {
    requireCondition(
      registration.referenceScreeningSha256 === digest(referenceScreening) &&
        referenceScreening.corpusId === corpus.id &&
        referenceScreening.corpusSha256 === digest(corpus) &&
        referenceScreening.passed === true &&
        referenceScreening.modelCalls === 0 &&
        Array.isArray(referenceScreening.cases) &&
        referenceScreening.cases.length === corpus.cases.length,
      "Confirmatory reference screening differs",
    );
  }
  for (const [index, item] of corpus.cases.entries()) {
    const registered = registration.cases[index];
    requireCondition(
      registered?.id === item.id &&
        registered.entry === item.targetFinding.relativePath &&
        registered.baselineAcceptancePass === (item.kind === "negative_control"),
      `Confirmatory registration differs for ${item.id}`,
    );
    requireHash(registered.baselineSha256, `${item.id} baseline source`);
    requireHash(registered.upstreamSha256, `${item.id} upstream source`);
    requireHash(registered.reference?.sha256, `${item.id} reference`);
    const expectedKind = item.kind === "negative_control" ? "unchanged" : item.referenceStrategy;
    requireCondition(
      registered.reference.kind === expectedKind &&
        (expectedKind === "implementation-regions"
          ? Array.isArray(registered.reference.regions) && registered.reference.regions.length > 0
          : registered.reference.regions === undefined),
      `Confirmatory reference strategy differs for ${item.id}`,
    );
    if (item.kind === "negative_control") {
      requireHash(registered.controlSourceSha256, `${item.id} negative-control source`);
      requireCondition(
        registered.reference.sha256 === registered.baselineSha256,
        `Negative-control registration differs for ${item.id}`,
      );
    }
    if (registered.runtimeManifestSha256 !== undefined)
      requireHash(registered.runtimeManifestSha256, `${item.id} runtime manifest`);
    if (referenceScreening !== undefined) {
      const reference = referenceScreening.cases[index];
      requireCondition(
        reference.id === item.id &&
          reference.baselineSha256 === registered.baselineSha256 &&
          reference.upstreamSha256 === registered.upstreamSha256 &&
          reference.referenceSha256 === registered.reference.sha256 &&
          reference.kind === registered.reference.kind &&
          reference.passed === true,
        `Registered reference evidence differs for ${item.id}`,
      );
    }
  }
  requireCondition(
    new Set(registration.cases.map((item) => item.id)).size === registration.cases.length &&
      canonicalJson(registration.cases.map((item) => item.id)) ===
        canonicalJson(corpus.cases.map((item) => item.id)),
    "Confirmatory registration case order differs",
  );
  return registration;
}
