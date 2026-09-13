import assert from "node:assert/strict";
import { test } from "node:test";
import {
  confirmatoryCorpusFilename,
  confirmatoryRegistrationFilename,
  validateRepositoryConfirmatoryRegistration,
} from "./repository-confirmatory-registration.mjs";
import { digest } from "./workflow-plan.mjs";

function fixture() {
  const corpus = {
    id: "sitecmd-confirmatory-v3",
    cases: [
      {
        id: "repair",
        kind: "repair",
        referenceStrategy: "implementation-only",
        targetFinding: { relativePath: "src/app.js" },
      },
    ],
  };
  const eligibility = { passed: true };
  const references = {
    corpusId: corpus.id,
    corpusSha256: digest(corpus),
    passed: true,
    modelCalls: 0,
    cases: [
      {
        id: "repair",
        kind: "implementation-only",
        baselineSha256: digest("baseline"),
        upstreamSha256: digest("upstream"),
        referenceSha256: digest("reference"),
        passed: true,
      },
    ],
  };
  const registration = {
    schemaVersion: 1,
    corpusId: corpus.id,
    corpusSha256: digest(corpus),
    eligibilitySha256: digest(eligibility),
    referenceScreeningSha256: digest(references),
    qualificationVersion: 1,
    cases: [
      {
        id: "repair",
        entry: "src/app.js",
        baselineSha256: digest("baseline"),
        upstreamSha256: digest("upstream"),
        reference: { kind: "implementation-only", sha256: digest("reference") },
        baselineAcceptancePass: false,
      },
    ],
  };
  return { corpus, eligibility, references, registration };
}

test("validates a registration against its pretrial evidence", () => {
  const { corpus, eligibility, references, registration } = fixture();
  assert.equal(
    validateRepositoryConfirmatoryRegistration(registration, corpus, eligibility, references),
    registration,
  );
  assert.equal(confirmatoryCorpusFilename(corpus.id), "repository-confirmatory-v3.json");
  assert.equal(
    confirmatoryRegistrationFilename(corpus.id),
    "repository-confirmatory-v3-registration.json",
  );
});

test("rejects changed registration evidence and unknown corpus ids", () => {
  const { corpus, eligibility, references, registration } = fixture();
  assert.throws(
    () =>
      validateRepositoryConfirmatoryRegistration(
        { ...registration, referenceScreeningSha256: "0".repeat(64) },
        corpus,
        eligibility,
        references,
      ),
    /reference screening/i,
  );
  assert.throws(() => confirmatoryCorpusFilename("unknown"), /unsupported/i);
  assert.throws(() => confirmatoryRegistrationFilename("unknown"), /unsupported/i);
});
