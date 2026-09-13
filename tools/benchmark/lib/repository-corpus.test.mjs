import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  validateRepositoryConfirmatoryCorpus,
  validateRepositoryCorpusIntake,
} from "./repository-corpus.mjs";
import { digest } from "./workflow-plan.mjs";

const commit = (value) => digest(value).slice(0, 40);

function caseDefinition(index) {
  const repositoryIndex = Math.floor(index / 2);
  const negativeControl = index >= 6;
  const baselineCommit = commit(`baseline-${index}`);
  return {
    id: `case-${index + 1}`,
    repository: {
      id: `application-${repositoryIndex + 1}`,
      url: `https://github.com/example/application-${repositoryIndex + 1}`,
      license: "MIT",
      licenseFile: "LICENSE",
    },
    kind: negativeControl ? "negative_control" : "repair",
    category: ["security", "data", "operations"][index % 3],
    runtime: index % 2 === 0 ? "node" : "python",
    surface: "code",
    heldOut: true,
    baselineCommit,
    upstreamCommit: negativeControl ? baselineCommit : commit(`upstream-${index}`),
    upstreamFix: `https://github.com/example/application-${repositoryIndex + 1}/commit/${commit(`reference-${index}`)}`,
    ...(negativeControl
      ? {}
      : {
          upstreamAdvisory: `https://github.com/example/application-${repositoryIndex + 1}/security/advisories/example-${index}`,
          referenceStrategy: "implementation-only",
        }),
    task: `Repair observable behavior for case ${index + 1}.`,
    requirements: `Preserve the existing contract for case ${index + 1}.`,
    selectionReason: "Historical application defect selected before product observation.",
    editableFiles: [`src/case-${index + 1}.js`],
    ...(negativeControl
      ? { safetyRationale: "A nearby implementation already enforces the same contract." }
      : {}),
  };
}

function corpus() {
  return {
    schemaVersion: 1,
    id: "sitecmd-held-out-v1",
    selectedAt: "2026-09-09T00:00:00.000Z",
    scannerObservedAtSelection: false,
    repairTrialsObservedAtSelection: 0,
    selectionMethod: "Preselected historical defects without SiteCMD or model outcomes.",
    cases: Array.from({ length: 8 }, (_, index) => caseDefinition(index)),
  };
}

function confirmatoryCorpus() {
  const value = corpus();
  value.id = "sitecmd-confirmatory-v1";
  value.scannerObservedAtSelection = true;
  value.selectionPopulation =
    "Pinned public repository findings emitted by SiteCMD Code Scan and frozen before repair-agent trials.";
  value.estimand =
    "Paired workflow differences for independently gradable issues that SiteCMD Code Scan detects.";
  for (const [index, item] of value.cases.entries()) {
    item.targetFinding = {
      checkId: `code_scan.fixture-${index + 1}`,
      relativePath: item.editableFiles[0],
      fingerprint: `sha256:${digest(`finding-${index + 1}`)}`,
      sourceAnchor: `repairCase${index + 1}`,
    };
  }
  return value;
}

test("accepts a diverse eight-case held-out repository intake", () => {
  assert.equal(validateRepositoryCorpusIntake(corpus()).id, "sitecmd-held-out-v1");
});

test("rejects a corpus selected after scanner or agent observation", () => {
  for (const change of [
    (value) => {
      value.scannerObservedAtSelection = true;
    },
    (value) => {
      value.repairTrialsObservedAtSelection = 1;
    },
    (value) => {
      value.cases[0].heldOut = false;
    },
  ]) {
    const value = corpus();
    change(value);
    assert.throws(() => validateRepositoryCorpusIntake(value), /selected|held out/i);
  }
});

test("accepts a scanner-enriched corpus frozen before repair-agent trials", () => {
  const value = confirmatoryCorpus();
  assert.equal(validateRepositoryConfirmatoryCorpus(value), value);
});

test("rejects the invalidated v1 corpus as a future trial source", () => {
  const retired = JSON.parse(
    readFileSync(new URL("../cases/repository-confirmatory-v1.json", import.meta.url), "utf8"),
  );
  assert.throws(() => validateRepositoryConfirmatoryCorpus(retired), /invalidated/i);
});

test("accepts the maintained v2 scanner-enriched corpus", () => {
  const maintained = JSON.parse(
    readFileSync(new URL("../cases/repository-confirmatory-v2.json", import.meta.url), "utf8"),
  );
  assert.equal(validateRepositoryConfirmatoryCorpus(maintained), maintained);
});

test("accepts the frozen 32-case v3 scanner-enriched corpus", () => {
  const maintained = JSON.parse(
    readFileSync(new URL("../cases/repository-confirmatory-v3.json", import.meta.url), "utf8"),
  );
  assert.equal(validateRepositoryConfirmatoryCorpus(maintained), maintained);
  assert.equal(maintained.cases.length, 32);
  assert.equal(maintained.cases.filter(({ kind }) => kind === "repair").length, 24);
  assert.equal(maintained.cases.filter(({ kind }) => kind === "negative_control").length, 8);
  assert.equal(new Set(maintained.cases.map(({ repository }) => repository.id)).size, 28);
});

test("rejects confirmatory corpora without an explicit estimand or target finding", () => {
  for (const change of [
    (value) => {
      value.scannerObservedAtSelection = false;
    },
    (value) => {
      value.repairTrialsObservedAtSelection = 1;
    },
    (value) => {
      delete value.selectionPopulation;
    },
    (value) => {
      delete value.estimand;
    },
    (value) => {
      delete value.cases[0].targetFinding;
    },
    (value) => {
      value.cases[0].targetFinding.relativePath = "../outside.ts";
    },
    (value) => {
      value.cases[0].targetFinding.fingerprint = "not-a-fingerprint";
    },
    (value) => {
      delete value.cases[0].targetFinding.sourceAnchor;
    },
  ]) {
    const value = confirmatoryCorpus();
    change(value);
    assert.throws(
      () => validateRepositoryConfirmatoryCorpus(value),
      /confirmatory|target|estimand|population/i,
    );
  }
});

test("validates explicit source exclusions without allowing hidden edit or license paths", () => {
  const value = confirmatoryCorpus();
  value.cases[0].sourceExclusions = [
    { path: "fixtures/screenshots", reason: "Large visual fixtures are outside this repair." },
  ];
  assert.equal(validateRepositoryConfirmatoryCorpus(value), value);
  for (const excludedPath of [value.cases[0].editableFiles[0], "LICENSE", "../fixtures"]) {
    const invalid = confirmatoryCorpus();
    invalid.cases[0].sourceExclusions = [{ path: excludedPath, reason: "Not used by the repair." }];
    assert.throws(() => validateRepositoryConfirmatoryCorpus(invalid), /exclusion/i);
  }
});

test("rejects an undersized or concentrated corpus", () => {
  for (const change of [
    (value) => value.cases.pop(),
    (value) => {
      value.cases = Array.from({ length: 33 }, (_, index) => caseDefinition(index));
    },
    (value) => {
      value.cases.forEach(
        (item) =>
          (item.repository = {
            id: "one-application",
            url: "https://github.com/example/one-application",
            license: "MIT",
            licenseFile: "LICENSE",
          }),
      );
    },
    (value) => {
      value.cases[5].kind = "negative_control";
      value.cases[5].upstreamCommit = value.cases[5].baselineCommit;
      value.cases[5].safetyRationale = "The implementation already enforces the contract.";
    },
    (value) => {
      value.cases[6].kind = "repair";
      value.cases[6].upstreamCommit = commit("repaired-case-7");
      value.cases[6].upstreamAdvisory =
        "https://github.com/example/application-4/security/advisories/repaired-case-7";
      value.cases[6].referenceStrategy = "implementation-only";
    },
    (value) => {
      value.cases.forEach((item) => (item.category = "security"));
    },
    (value) => {
      value.cases.forEach((item) => (item.runtime = "node"));
    },
    (value) => {
      value.cases.slice(0, 4).forEach(
        (item) =>
          (item.repository = {
            id: "one-application",
            url: "https://github.com/example/one-application",
            license: "MIT",
            licenseFile: "LICENSE",
          }),
      );
    },
  ]) {
    const value = corpus();
    change(value);
    assert.throws(() => validateRepositoryCorpusIntake(value), /corpus/i);
  }
});

test("rejects cases without unique identities, pins, or observable contracts", () => {
  for (const change of [
    (value) => {
      value.cases[1].id = value.cases[0].id;
    },
    (value) => {
      value.cases[0].repository.url = "not-a-url";
    },
    (value) => {
      delete value.cases[0].repository.licenseFile;
    },
    (value) => {
      value.cases[0].baselineCommit = "main";
    },
    (value) => {
      value.cases[0].upstreamCommit = value.cases[0].baselineCommit;
    },
    (value) => {
      value.cases[6].upstreamCommit = commit("changed-control");
    },
    (value) => {
      value.cases[0].upstreamAdvisory = "not-a-url";
    },
    (value) => {
      delete value.cases[0].referenceStrategy;
    },
    (value) => {
      value.cases[0].requirements = "";
    },
    (value) => {
      value.cases[0].editableFiles = [];
    },
    (value) => {
      delete value.cases[6].safetyRationale;
    },
  ]) {
    const value = corpus();
    change(value);
    assert.throws(() => validateRepositoryCorpusIntake(value), /case/i);
  }
});

test("rejects invalid selection time or inconsistent repository provenance", () => {
  for (const change of [
    (value) => {
      value.selectedAt = "sometime yesterday";
    },
    (value) => {
      value.cases[1].repository.url = "https://github.com/example/different-application";
    },
    (value) => {
      value.cases[2].repository.id = value.cases[0].repository.id;
    },
  ]) {
    const value = corpus();
    change(value);
    assert.throws(() => validateRepositoryCorpusIntake(value), /selectedAt|repository/i);
  }
});

test("the maintained v1 intake satisfies the held-out corpus policy", () => {
  const maintained = JSON.parse(
    readFileSync(new URL("../cases/repository-held-out-v1.json", import.meta.url), "utf8"),
  );
  assert.equal(validateRepositoryCorpusIntake(maintained), maintained);
});
