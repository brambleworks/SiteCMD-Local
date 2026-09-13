import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createRepositoryScannerEligibility,
  evaluateRepositoryScannerCase,
  repositoryScannerTargetIssue,
} from "./repository-scanner-eligibility.mjs";
import { digest } from "./workflow-plan.mjs";

const fingerprint = (value) => `sha256:${digest(value)}`;

function item(kind = "repair") {
  return {
    id: "unsafe-preview",
    kind,
    baselineCommit: "a".repeat(40),
    upstreamCommit: kind === "repair" ? "b".repeat(40) : "a".repeat(40),
    targetFinding: {
      checkId: "code_scan.unsafe-html",
      relativePath: "src/Preview.tsx",
      fingerprint: fingerprint("target"),
      sourceAnchor: "renderPreview(userHtml)",
    },
  };
}

function issue({
  fingerprint: identity = fingerprint("target"),
  checkId,
  relativePath,
  sourceExcerpt = "12 | renderPreview(userHtml)",
} = {}) {
  return {
    checkId: checkId ?? "code_scan.unsafe-html",
    relativePath: relativePath ?? "src/Preview.tsx",
    fingerprint: identity,
    severity: "high",
    title: "Raw HTML sink",
    line: 12,
    sourceExcerpt,
  };
}

test("accepts a repair only when the registered baseline finding clears", () => {
  const result = evaluateRepositoryScannerCase(item(), { issues: [issue()] }, { issues: [] });
  assert.equal(result.eligible, true);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.baseline.targetFingerprintMatches, 1);
  assert.equal(result.upstream.targetPathMatches, 0);

  const replacedFingerprint = evaluateRepositoryScannerCase(
    item(),
    { issues: [issue()] },
    { issues: [issue({ fingerprint: fingerprint("shifted") })] },
  );
  assert.equal(replacedFingerprint.eligible, false);
  assert.match(replacedFingerprint.reasons.join(" "), /remains/i);
});

test("allows unrelated findings from the same rule and path", () => {
  const unrelated = issue({
    fingerprint: fingerprint("unrelated"),
    sourceExcerpt: "40 | renderUnrelatedPanel(otherHtml)",
  });
  const result = evaluateRepositoryScannerCase(
    item(),
    { issues: [issue(), unrelated] },
    { issues: [unrelated] },
  );

  assert.equal(result.eligible, true);
  assert.equal(result.baseline.targetPathMatches, 2);
  assert.equal(result.baseline.targetFingerprintMatches, 1);
  assert.equal(result.upstream.targetPathMatches, 1);
  assert.equal(result.upstream.targetAnchorMatches, 0);
  assert.deepEqual(repositoryScannerTargetIssue(item(), result.baseline), issue());
});

test("exact target selection fails closed on incomplete eligibility evidence", () => {
  const result = evaluateRepositoryScannerCase(item(), { issues: [issue()] }, { issues: [] });
  assert.throws(() =>
    repositoryScannerTargetIssue(item(), {
      ...result.baseline,
      targetFingerprintMatches: 0,
    }),
  );
  assert.throws(() =>
    repositoryScannerTargetIssue(item(), {
      ...result.baseline,
      targetIssues: [],
    }),
  );
});

test("rejects a repair when the exact registered finding is absent at baseline", () => {
  const result = evaluateRepositoryScannerCase(
    item(),
    { issues: [issue({ fingerprint: fingerprint("different") })] },
    { issues: [] },
  );
  assert.equal(result.eligible, false);
  assert.match(result.reasons.join(" "), /baseline fingerprint/i);
});

test("rejects a registered scanner finding outside the task's semantic source anchor", () => {
  const result = evaluateRepositoryScannerCase(
    item(),
    { issues: [issue({ sourceExcerpt: "99 | renderUnrelatedPanel(otherHtml)" })] },
    { issues: [] },
  );

  assert.equal(result.eligible, false);
  assert.match(result.reasons.join(" "), /semantic source anchor/i);
});

test("accepts a negative control only when the same finding remains observable", () => {
  const control = item("negative_control");
  const unrelated = issue({
    fingerprint: fingerprint("unrelated"),
    sourceExcerpt: "40 | renderUnrelatedPanel(otherHtml)",
  });
  assert.equal(
    evaluateRepositoryScannerCase(
      control,
      { issues: [issue(), unrelated] },
      { issues: [issue(), unrelated] },
    ).eligible,
    true,
  );
  const cleared = evaluateRepositoryScannerCase(control, { issues: [issue()] }, { issues: [] });
  assert.equal(cleared.eligible, false);
  assert.match(cleared.reasons.join(" "), /control finding/i);
});

test("creates immutable scanner artifacts tied to source and product receipts", () => {
  const repair = item();
  const corpus = { id: "confirmatory", cases: [repair] };
  const screening = {
    corpusId: corpus.id,
    intakeSha256: digest(corpus),
    passed: true,
    modelCalls: 0,
    cases: [{ id: repair.id, sourceCompatible: true }],
  };
  const product = {
    commit: "c".repeat(40),
    version: "1.3.0",
    sourceSha256: digest("source"),
    cliSha256: digest("cli"),
  };
  const baseline = JSON.stringify({ issues: [issue()] });
  const upstream = JSON.stringify({ issues: [] });
  const result = createRepositoryScannerEligibility(
    corpus,
    screening,
    product,
    [
      {
        id: repair.id,
        baseline: { raw: baseline, report: JSON.parse(baseline) },
        upstream: { raw: upstream, report: JSON.parse(upstream) },
      },
    ],
    "2026-09-09T12:00:00.000Z",
  );
  assert.equal(result.receipt.passed, true);
  assert.equal(result.receipt.modelCalls, 0);
  assert.equal(result.receipt.product.cliSha256, product.cliSha256);
  assert.equal(result.artifacts.size, 2);
  assert.equal(result.receipt.cases[0].baseline.sha256, digest(Buffer.from(baseline)));
  assert.equal(
    result.artifacts.get(result.receipt.cases[0].baseline.artifact).toString(),
    baseline,
  );
});

test("rejects mismatched reports, products, screening, and capture times", () => {
  const repair = item();
  const corpus = { id: "confirmatory", cases: [repair] };
  const screening = {
    corpusId: corpus.id,
    intakeSha256: digest(corpus),
    passed: true,
    modelCalls: 0,
    cases: [{ id: repair.id, sourceCompatible: true }],
  };
  const product = {
    commit: "c".repeat(40),
    version: "1.3.0",
    sourceSha256: digest("source"),
    cliSha256: digest("cli"),
  };
  const scanned = [
    {
      id: repair.id,
      baseline: { raw: JSON.stringify({ issues: [issue()] }), report: { issues: [] } },
      upstream: { raw: JSON.stringify({ issues: [] }), report: { issues: [] } },
    },
  ];
  assert.throws(
    () =>
      createRepositoryScannerEligibility(
        corpus,
        screening,
        product,
        scanned,
        "2026-09-09T12:00:00.000Z",
      ),
    /raw scanner report/i,
  );
  scanned[0].baseline.report = JSON.parse(scanned[0].baseline.raw);
  screening.intakeSha256 = digest("different");
  assert.throws(
    () =>
      createRepositoryScannerEligibility(
        corpus,
        screening,
        product,
        scanned,
        "2026-09-09T12:00:00.000Z",
      ),
    /screening/i,
  );
  screening.intakeSha256 = digest(corpus);
  product.cliSha256 = "invalid";
  assert.throws(
    () =>
      createRepositoryScannerEligibility(
        corpus,
        screening,
        product,
        scanned,
        "2026-09-09T12:00:00.000Z",
      ),
    /product/i,
  );
  product.cliSha256 = digest("cli");
  assert.throws(
    () => createRepositoryScannerEligibility(corpus, screening, product, scanned, "yesterday"),
    /capture/i,
  );
});
