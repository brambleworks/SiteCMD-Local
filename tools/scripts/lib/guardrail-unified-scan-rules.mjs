import { rustFunctionBody as functionBody } from "./guardrail-rust-function.mjs";

const LEGACY_SCAN_TABLES = [
  "scans",
  "scan_issues",
  "scan_sessions",
  "session_issues",
  "code_scans",
  "code_scan_issues",
];

const MIGRATION_OR_TEST_FILE =
  /(?:\/migrations(?:\/|\.rs$)|schema_snapshot\.sql$|(?:^|\/)(?:tests\.rs|[^/]+_tests\.rs)|\.(?:test|spec)\.[cm]?[jt]sx?$)/;

// Flat alternatives avoid the nested quantifiers rejected by the regex audit.
const TEST_MOD_PLAIN = /^#\[cfg\(test\)\]\s*mod\s+tests\b/;
const TEST_MOD_WITH_PATH = /^#\[cfg\(test\)\]\s*#\[path\s*=\s*"[^"]*"\]\s*mod\s+tests\b/;

function stripInlineRustTests(source) {
  for (const match of source.matchAll(/#\[cfg\(test\)\]/g)) {
    const rest = source.slice(match.index);
    if (TEST_MOD_PLAIN.test(rest) || TEST_MOD_WITH_PATH.test(rest)) {
      return source.slice(0, match.index);
    }
  }
  return source;
}

function sourceFiles(listFiles, extraRoots) {
  const sourcePredicate = (file) => /\.(?:rs|sql|ts|tsx|mjs)$/.test(file);
  return [
    ...listFiles("apps/desktop/src-tauri/src", sourcePredicate),
    ...extraRoots.flatMap((root) => listFiles(root, sourcePredicate)),
  ];
}

function productionSource(read, file) {
  const source = read(file);
  return file.endsWith(".rs") ? stripInlineRustTests(source) : source;
}

export function unifiedScanArchitectureFailures(read, exists, listFiles, extraRoots = []) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const files = sourceFiles(listFiles, extraRoots);
  const productionFiles = files.filter((file) => !MIGRATION_OR_TEST_FILE.test(file));

  const legacySql = new RegExp(
    // Escapes keep the quote/backtick character class inside this template literal.
    // eslint-disable-next-line no-useless-escape
    `\\b(?:FROM|JOIN|INTO|UPDATE|DELETE\\s+FROM|CREATE\\s+TABLE|DROP\\s+TABLE|ALTER\\s+TABLE|REFERENCES)\\s+[\\\"\\\`]?(?:${LEGACY_SCAN_TABLES.join("|")})\\b`,
  );
  const legacySqlFiles = productionFiles.filter((file) =>
    legacySql.test(productionSource(read, file)),
  );
  check(
    legacySqlFiles.length === 0,
    `Production code must use scan_executions/scan_runs/scan_findings, never legacy scan tables: ${legacySqlFiles.join(", ")}`,
  );

  const pathBearingCodeId = /code_scan\.[A-Za-z0-9_.-]+:[A-Za-z0-9_./\\-]+/;
  const pathBearingFiles = productionFiles.filter((file) =>
    pathBearingCodeId.test(productionSource(read, file)),
  );
  check(
    pathBearingFiles.length === 0,
    `Canonical Code check IDs must stay rule-level; put files and lines in occurrence fields: ${pathBearingFiles.join(", ")}`,
  );

  const parserFiles = productionFiles.filter((file) => {
    const source = productionSource(read, file);
    return (
      source.includes("normalize_code_check_id") ||
      /(?:check_id|checkId)[^;\n]{0,100}\.split(?:_once)?\s*\(\s*['"]:/.test(source) ||
      /LIKE\s+['"]code_scan\.%:%/i.test(source)
    );
  });
  check(
    parserFiles.length === 0,
    `Production consumers must not parse or pattern-match canonical Code IDs for locations: ${parserFiles.join(", ")}`,
  );

  const issueStatesFile = "apps/desktop/src-tauri/src/db/issue_states.rs";
  const issueStates = exists(issueStatesFile) ? productionSource(read, issueStatesFile) : "";
  check(
    !/resolve_code_issue_state_ids|LIKE\s+['"]code_scan\.%:%|for\s+.*location/.test(issueStates),
    `${issueStatesFile} must reconcile canonical lifecycle rows without location fan-out.`,
  );

  return failures;
}

const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";
const CODE_NORMALIZATION = "apps/desktop/src-tauri/src/core/normalized_scan/code.rs";
const coverageCall =
  /sitecmd_protocol::coverage::covers\(\s*&batch\.coverage,\s*None,\s*&candidate\.check_id,\s*exact_claim_key,?\s*\)/;
const projectCoverage =
  /coverage:\s*ScanCoverageManifest::declared\(\s*ScanCoverageKind::Project,\s*Vec::new\(\),/;

export function scanRunProjectionFailures(read) {
  const failures = [];
  const projection = read(PROJECTION);
  const resolver = functionBody(projection, "resolve_covered_absences");
  if (!resolver) {
    failures.push(
      `${PROJECTION} must resolve absences in one place. Absence is the only evidence a fix leaves, and the rule for reading it belongs where it can be tested.`,
    );
  }
  if (resolver && !coverageCall.test(resolver)) {
    failures.push(
      `${PROJECTION} must ask the coverage manifest whether the run proved the pair. A second implementation of that question is how the desktop and the connected service start disagreeing about what was fixed.`,
    );
  }
  if (resolver && !resolver.includes("batch.coverage.successful")) {
    failures.push(`${PROJECTION} must refuse to resolve anything from an unsuccessful run.`);
  }
  if (resolver && !resolver.includes("load_open_candidates(")) {
    failures.push(
      `${PROJECTION} must read its candidates through load_open_candidates, which scopes the query to the run's open code findings.`,
    );
  }
  for (const dead of ["limit_pages", "filter_kind", "producer_ids"]) {
    if (projection.includes(dead)) {
      failures.push(
        `${PROJECTION} still switches on ${dead}. Per-kind filtering was the flat model: a page claim that resolves every check on the page cannot tell a check that passed from one that never ran.`,
      );
    }
  }
  const loader = functionBody(projection, "load_open_candidates");
  if (!loader || /\b(?:page_url|page_urls|route_bound)\b/.test(loader)) {
    failures.push(
      `${PROJECTION} must load code candidates without a route filter. A code run covers the project tree.`,
    );
  }
  const normalizer = functionBody(read(CODE_NORMALIZATION), "normalize_code_scan_with_inventory");
  if (!normalizer || !projectCoverage.test(normalizer)) {
    failures.push(
      `${CODE_NORMALIZATION} must declare project-wide coverage without page URLs so the projection can resolve checks across the project.`,
    );
  }
  return failures;
}
