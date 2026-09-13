import { requireCondition, requireHash, requireText } from "./workflow-contract.mjs";
import { canonicalJson, digest } from "./workflow-plan.mjs";

const COMMIT = /^[a-f0-9]{40}$/;

function targetMatches(report, target) {
  const issues = Array.isArray(report?.issues) ? report.issues : [];
  const pathMatches = issues.filter(
    (issue) => issue.checkId === target.checkId && issue.relativePath === target.relativePath,
  );
  const fingerprintMatches = pathMatches.filter(
    (issue) => issue.fingerprint === target.fingerprint,
  );
  const anchorMatches = pathMatches.filter(
    (issue) =>
      typeof issue.sourceExcerpt === "string" && issue.sourceExcerpt.includes(target.sourceAnchor),
  );
  return {
    issueCount: issues.length,
    targetPathMatches: pathMatches.length,
    targetFingerprintMatches: fingerprintMatches.length,
    targetAnchorMatches: anchorMatches.length,
    targetSemanticMatches: fingerprintMatches.filter(
      (issue) =>
        typeof issue.sourceExcerpt === "string" &&
        issue.sourceExcerpt.includes(target.sourceAnchor),
    ).length,
    targetIssues: pathMatches,
  };
}

export function evaluateRepositoryScannerCase(item, baselineReport, upstreamReport) {
  const baseline = targetMatches(baselineReport, item.targetFinding);
  const upstream = targetMatches(upstreamReport, item.targetFinding);
  const reasons = [];
  if (baseline.targetFingerprintMatches !== 1)
    reasons.push("The exact registered baseline fingerprint was not observed once.");
  if (baseline.targetSemanticMatches !== 1)
    reasons.push(
      "The registered baseline finding does not overlap the task's semantic source anchor.",
    );
  if (item.kind === "repair") {
    if (upstream.targetFingerprintMatches !== 0 || upstream.targetAnchorMatches !== 0)
      reasons.push("The registered finding remains after the upstream repair.");
  } else if (upstream.targetFingerprintMatches !== 1 || upstream.targetSemanticMatches !== 1) {
    reasons.push("The registered negative-control finding was not preserved unchanged.");
  }
  return { eligible: reasons.length === 0, reasons, baseline, upstream };
}

export function repositoryScannerTargetIssue(item, observation) {
  const target = item.targetFinding;
  const matches = (observation?.targetIssues ?? []).filter(
    (issue) =>
      issue.checkId === target.checkId &&
      issue.relativePath === target.relativePath &&
      issue.fingerprint === target.fingerprint,
  );
  requireCondition(
    observation?.targetFingerprintMatches === 1 &&
      observation.targetSemanticMatches === 1 &&
      matches.length === 1,
    `Scanner eligibility does not contain one exact target for ${item.id}`,
  );
  return matches[0];
}

function captureTime(value) {
  requireCondition(
    typeof value === "string" &&
      !Number.isNaN(Date.parse(value)) &&
      new Date(value).toISOString() === value,
    "Scanner eligibility capture time must be an ISO timestamp",
  );
  return value;
}

function validateProduct(product) {
  requireCondition(COMMIT.test(product?.commit ?? ""), "Scanner product commit is invalid");
  requireText(product.version, "scanner product version");
  requireHash(product.sourceSha256, "scanner product source digest");
  requireHash(product.cliSha256, "scanner product CLI digest");
}

function validateScan(scan, label) {
  requireCondition(
    typeof scan?.raw === "string" && scan.raw.length > 0,
    `${label} raw scan is empty`,
  );
  let parsed;
  try {
    parsed = JSON.parse(scan.raw);
  } catch {
    throw new Error(`${label} raw scanner report is not JSON`);
  }
  requireCondition(
    canonicalJson(parsed) === canonicalJson(scan.report) && Array.isArray(scan.report?.issues),
    `${label} raw scanner report disagrees with the parsed report`,
  );
}

export function createRepositoryScannerEligibility(
  corpus,
  screening,
  product,
  scanned,
  capturedAt,
) {
  validateProduct(product);
  requireCondition(
    screening?.corpusId === corpus.id &&
      screening.intakeSha256 === digest(corpus) &&
      screening.passed === true &&
      screening.modelCalls === 0 &&
      Array.isArray(screening.cases) &&
      screening.cases.length === corpus.cases.length &&
      screening.cases.every(
        (item, index) => item.id === corpus.cases[index].id && item.sourceCompatible === true,
      ),
    "Source screening does not match the scanner corpus",
  );
  requireCondition(
    Array.isArray(scanned) &&
      scanned.length === corpus.cases.length &&
      scanned.every((item, index) => item.id === corpus.cases[index].id),
    "Scanner results must preserve corpus case order",
  );
  const artifacts = new Map();
  const cases = scanned.map((result, index) => {
    const item = corpus.cases[index];
    validateScan(result.baseline, `${item.id} baseline`);
    validateScan(result.upstream, `${item.id} upstream`);
    const evaluation = evaluateRepositoryScannerCase(
      item,
      result.baseline.report,
      result.upstream.report,
    );
    const register = (variant, scan, observation) => {
      const bytes = Buffer.from(scan.raw);
      const sha256 = digest(bytes);
      const artifact = `scans/${item.id}-${variant}-${sha256}.json`;
      artifacts.set(artifact, bytes);
      return { artifact, sha256, ...observation };
    };
    return {
      id: item.id,
      eligible: evaluation.eligible,
      reasons: evaluation.reasons,
      baseline: register("baseline", result.baseline, evaluation.baseline),
      upstream: register("upstream", result.upstream, evaluation.upstream),
    };
  });
  const productIdentity = {
    commit: product.commit,
    version: product.version,
    sourceSha256: product.sourceSha256,
    cliSha256: product.cliSha256,
  };
  return {
    receipt: {
      schemaVersion: 1,
      corpusId: corpus.id,
      corpusSha256: digest(corpus),
      sourceScreeningSha256: digest(screening),
      capturedAt: captureTime(capturedAt),
      scannerObserved: true,
      modelCalls: 0,
      product: productIdentity,
      cases,
      passed: cases.every((item) => item.eligible),
    },
    artifacts,
  };
}
