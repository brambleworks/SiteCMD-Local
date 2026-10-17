import { constList } from "./guardrail-engine-lane-parsing.mjs";

const COVERAGE = "apps/desktop/src-tauri/crates/engine/src/coverage.rs";
const NORMALIZED = "apps/desktop/src-tauri/src/core/normalized_scan.rs";
const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";
const VERIFICATION = "apps/desktop/src-tauri/src/commands/scan/verification.rs";
const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";
const AXE = "apps/desktop/src-tauri/crates/engine/src/checks/accessibility/axe.rs";
const REGISTRY = "apps/desktop/src-tauri/src/core/code_scan/registry.rs";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";

// Extract a Rust function through its matching closing brace.
function functionBody(source, name) {
  const start = source.search(new RegExp(`fn ${name}\\b`));
  if (start === -1) return null;
  const open = source.indexOf("{", start);
  if (open === -1) return null;
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  return null;
}

function derivationFailures(read, failures) {
  const coverage = read(COVERAGE);
  const derive = functionBody(coverage, "derive");
  if (!derive) {
    failures.push(
      `${COVERAGE} must define derive: coverage comes from what a run produced, and a manifest anyone can assemble by hand is a claim about intent.`,
    );
  }
  if (derive && !derive.includes("CheckStatus::Skipped")) {
    failures.push(
      `${COVERAGE} derive must except pairs whose outcome was Skipped. A check that did not reach a verdict proves nothing, and claiming it turns a timeout into a fix.`,
    );
  }
  if (derive && !derive.includes("CoverageExceptionReason::SessionIncomplete")) {
    failures.push(
      `${COVERAGE} derive must except cross-page claims when the route set was incomplete. The pages that answered cannot speak for the ones that did not.`,
    );
  }

  const covers = functionBody(coverage, "covers");
  if (!covers) {
    failures.push(
      `${COVERAGE} must define covers: one function answers whether a run proved a pair, for local reconciliation and for a connected producer alike.`,
    );
  }
  if (covers && !covers.includes("self.successful")) {
    failures.push(
      `${COVERAGE} covers must refuse an unsuccessful run outright. A run that failed proves nothing whatever it managed to claim first.`,
    );
  }
  if (covers && !covers.includes("excepted_on")) {
    failures.push(
      `${COVERAGE} covers must consult the exceptions. A claim without its exceptions is the flat vector this encoding replaced.`,
    );
  }

  const claimKey = functionBody(coverage, "claim_key");
  if (claimKey && !claimKey.includes("FAMILY_PREFIXES")) {
    failures.push(
      `${COVERAGE} claim_key must resolve family ids from the registry's family prefixes. A hand-kept list of families drifts from the manifest that defines them.`,
    );
  }
}

function producerFailures(read, failures) {
  const normalized = read(NORMALIZED);
  for (const [name, expected] of [
    ["normalize_web_scan", "ClaimBasis::PerRoute"],
    ["normalize_multi_page_parent", "ClaimBasis::RouteSet"],
  ]) {
    const body = functionBody(normalized, name);
    if (!body) {
      failures.push(
        `${NORMALIZED} has no ${name}. If normalization moved, move this rule with it: coverage is derived where the run is normalized.`,
      );
      continue;
    }
    if (!body.includes("ScanCoverageManifest::derive")) {
      failures.push(
        `${NORMALIZED} ${name} must derive coverage from the run's own outcomes. A claim written next to the scan rather than from it says what the scan was asked to do.`,
      );
    }
    if (!body.includes(expected)) {
      failures.push(
        `${NORMALIZED} ${name} must declare ${expected}. A cross-page verdict claimed per route resolves findings on pages that never answered; a per-page verdict claimed for the set does the reverse.`,
      );
    }
  }
  const parent = functionBody(normalized, "normalize_multi_page_parent") ?? "";
  if (parent.includes("ClaimBasis::RouteSet") && !/complete:\s*\w+.*==/s.test(parent)) {
    failures.push(
      `${NORMALIZED} normalize_multi_page_parent must decide RouteSet completeness by comparing the pages that answered against the pages selected. A hardcoded complete claim is the partial-set bug with extra steps.`,
    );
  }

  const codeCoverage = functionBody(normalized, "normalize_code_scan") ?? "";
  if (!codeCoverage.includes("registered_code_check_ids")) {
    failures.push(
      `${NORMALIZED} normalize_code_scan must claim the registry's check ids. A code report carries findings only, so a claim derived from its rows would resolve nothing a code scan ever cleared.`,
    );
  }
  if (!read(REGISTRY).includes("pub fn registered_code_check_ids")) {
    failures.push(
      `${REGISTRY} must expose registered_code_check_ids. The release inventory and a run's coverage read one list, or a rule missing from either cannot be resolved or cannot be attributed.`,
    );
  }

  const verification = functionBody(read(VERIFICATION), "run_bounded_web_verification");
  if (!verification) {
    failures.push(
      `${VERIFICATION} has no run_bounded_web_verification. If bounded verification moved, move this rule with it: a rule that cannot find its subject stops checking it and passes forever.`,
    );
  }
  if (verification && !verification.includes("ScanCoverageManifest::derive")) {
    failures.push(
      `${VERIFICATION} must derive verification coverage from the pass's outcomes. Verification already reports a Skipped row for every id it could not re-prove; claiming the requested set instead lets the check the user asked about resolve the finding by timing out.`,
    );
  }
  if (verification && /page_urls:\s*vec!\[/.test(verification)) {
    failures.push(
      `${VERIFICATION} assembles a coverage manifest by hand. Every claim goes through derive, so nothing can quietly claim a check that did not run.`,
    );
  }
}

function projectionFailures(read, failures) {
  const projection = read(PROJECTION);
  const resolver = functionBody(projection, "resolve_covered_absences");
  if (!resolver) {
    failures.push(
      `${PROJECTION} must resolve absences in one place. Absence is the only evidence a fix leaves, and the rule for reading it belongs where it can be tested.`,
    );
  }
  if (resolver && !resolver.includes("coverage.covers(")) {
    failures.push(
      `${PROJECTION} must ask the coverage manifest whether the run proved the pair. A second implementation of that question is how the desktop and the connected service start disagreeing about what was fixed.`,
    );
  }
  if (resolver && !resolver.includes("batch.coverage.successful")) {
    failures.push(`${PROJECTION} must refuse to resolve anything from an unsuccessful run.`);
  }
  if (resolver && !resolver.includes("load_open_candidates(")) {
    failures.push(
      `${PROJECTION} must read its candidates through load_open_candidates, which bounds the query to the routes the claim can cover. An inlined SELECT decodes every open finding on the site for every page that finishes.`,
    );
  }
  for (const dead of ["limit_pages", "filter_kind", "producer_ids"]) {
    if (projection.includes(dead)) {
      failures.push(
        `${PROJECTION} still switches on ${dead}. Per-kind filtering was the flat model: a page claim that resolves every check on the page cannot tell a check that passed from one that never ran.`,
      );
    }
  }
  if (!functionBody(projection, "as_stored_keys")) {
    failures.push(
      `${PROJECTION} must normalize both sides of the route comparison. One side normalized and the other raw leaves a fixed issue open forever on any site whose URL case differs.`,
    );
  }
}

function familyFailures(read, failures) {
  const axe = functionBody(read(AXE), "evaluate_axe_report");
  if (axe && !axe.includes("executed_rules()")) {
    failures.push(
      `${AXE} evaluate_axe_report must report every rule that executed, not only the violations. A fixed violation deletes the id its own proof would need, so a clean report that says nothing leaves the finding unresolvable forever.`,
    );
  }
  if (axe && !axe.includes("axe_rule_coverage_result")) {
    failures.push(
      `${AXE} evaluate_axe_report must grade the non-violation rules through axe_rule_coverage_result, so a rule that could not be decided stays a coverage exception instead of reading as a pass.`,
    );
  }
}

function sessionFailures(read, failures) {
  const session = read(SESSION);
  const ids = constList(session, "SESSION_CHECK_IDS");
  if (!ids || ids.length === 0) {
    failures.push(
      `${SESSION} must declare SESSION_CHECK_IDS. A check that reports only when it finds something is a check nothing can prove ran.`,
    );
    return;
  }
  if (!(functionBody(session, "analyze_session") ?? "").includes("unreported_outcomes")) {
    failures.push(
      `${SESSION} analyze_session must report an outcome for every session check, not only the ones that found something. Silence cannot be told apart from a clean result, and coverage is derived from these rows.`,
    );
  }

  let manifest;
  try {
    manifest = JSON.parse(read(MANIFEST));
  } catch (error) {
    failures.push(`${MANIFEST} is missing or unparseable (${error.message}).`);
    return;
  }
  const entries = new Map(manifest.entries.map((entry) => [entry.check, entry]));
  for (const id of ids) {
    const entry = entries.get(id);
    if (!entry) {
      failures.push(
        `${MANIFEST} has no entry for ${id}, which the session analyzer emits. Connect resolves an observation's ids against the published manifest and drops what it cannot resolve, so an unregistered id is a finding that never lands.`,
      );
      continue;
    }
    if (entry.scope !== "session") {
      failures.push(
        `${MANIFEST} scopes ${id} as ${entry.scope}, but the session analyzer produces it from the whole scanned set. A page-scoped cross-page check lets a partial scan resolve findings on pages it never visited.`,
      );
    }
  }
}

export function coverageFailures(read) {
  const failures = [];
  derivationFailures(read, failures);
  producerFailures(read, failures);
  projectionFailures(read, failures);
  familyFailures(read, failures);
  sessionFailures(read, failures);
  return failures;
}
