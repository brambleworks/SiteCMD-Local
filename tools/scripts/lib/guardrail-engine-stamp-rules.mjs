const ENGINE_RELEASE = "apps/desktop/src-tauri/crates/engine/src/release.rs";
const CORE_STAMP = "apps/desktop/src-tauri/src/core/engine_release.rs";
const DB_STAMP = "apps/desktop/src-tauri/src/db/engine_release.rs";
const SCAN_RUNS = "apps/desktop/src-tauri/src/db/scan_runs.rs";
const BLAME = "apps/desktop/src-tauri/src/core/regression_blame.rs";
const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/019_engine_release_stamp.sql";

// Return a Rust function through its matching closing brace.
function functionBody(source, name) {
  const start = source.search(new RegExp(`fn ${name}\\(`));
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

// Extract every scan_runs insert column list.
function scanRunInsertColumns(source) {
  return [...source.matchAll(/INSERT INTO scan_runs \(([\s\S]*?)\)/g)].map((match) => match[1]);
}

export function engineStampFailures(read) {
  const failures = [];

  const scanRuns = read(SCAN_RUNS);
  const insertColumns = scanRunInsertColumns(scanRuns);
  if (insertColumns.length === 0) {
    failures.push(
      `${SCAN_RUNS} has no INSERT INTO scan_runs. If persistence moved, move this rule with it: the stamp has to be written where runs are written.`,
    );
  }
  for (const columns of insertColumns) {
    for (const column of ["engine_release", "manifest_digest", "execution_profile_json"]) {
      if (!columns.includes(column)) {
        failures.push(
          `${SCAN_RUNS} inserts a scan run without ${column}. An unstamped run is unattributable forever, and every later comparison against it silently concludes nothing.`,
        );
      }
    }
  }
  const stampHelper = functionBody(scanRuns, "record_run_stamp");
  if (!stampHelper) {
    failures.push(
      `${SCAN_RUNS} must build the stamp itself in record_run_stamp rather than accept one from callers. A caller that forgot would produce a run nothing can be compared against.`,
    );
  }
  if (stampHelper && !stampHelper.includes("crate::core::engine_release::stamp(")) {
    failures.push(
      `${SCAN_RUNS} record_run_stamp must derive the stamp from crate::core::engine_release::stamp, not from literals. A hand-written stamp eventually names a build that never existed.`,
    );
  }
  if (stampHelper && !stampHelper.includes("record_inventory(")) {
    failures.push(
      `${SCAN_RUNS} record_run_stamp must record the inventory alongside the stamp, in the caller's transaction, so a run can never point at an inventory that is not there.`,
    );
  }
  // Call sites only: the definition's own parameter list is not a call.
  for (const call of scanRuns.matchAll(/(?<!fn )record_run_stamp\(\s*([^,]+),/g)) {
    if (call[1].trim() !== "&tx") {
      failures.push(
        `${SCAN_RUNS} calls record_run_stamp outside the run's transaction (${call[1].trim()}). The inventory and the run that references it commit together or not at all.`,
      );
    }
  }

  const coreStamp = read(CORE_STAMP);
  if (!coreStamp.includes('env!("CARGO_PKG_VERSION")')) {
    failures.push(
      `${CORE_STAMP} must read the release from the crate version. A hand-maintained release string is a claim about a build nobody verified.`,
    );
  }
  if (!coreStamp.includes("CheckInventory::from_manifest")) {
    failures.push(
      `${CORE_STAMP} must build the inventory from the capability manifest, so a check added to the engine is inventoried without anyone remembering to.`,
    );
  }
  if (!coreStamp.includes("with_unversioned") || !coreStamp.includes("registered_code_check_ids")) {
    failures.push(
      `${CORE_STAMP} must inventory the code-scan checks too. Code batches ship constantly, and an uninventoried new code check is exactly the finding blame would pin on an innocent commit.`,
    );
  }

  const engineRelease = read(ENGINE_RELEASE);
  const stampCurrent = functionBody(engineRelease, "current");
  if (stampCurrent && !stampCurrent.includes("capability_manifest()")) {
    failures.push(
      `${ENGINE_RELEASE} ReleaseStamp::current must read the digest from the manifest this build carries. A stamp that names a document the build does not hold is worse than no stamp.`,
    );
  }
  const compare = functionBody(engineRelease, "comparability");
  if (compare && !/\(None, Some\(_\)\) => Comparability::NewCheck/.test(compare)) {
    failures.push(
      `${ENGINE_RELEASE} comparability must answer NewCheck when only the later build has the check. Its appearance is the scanner growing, never the site regressing.`,
    );
  }
  if (compare && !/\(Some\(_\), None\) => Comparability::Retired/.test(compare)) {
    failures.push(
      `${ENGINE_RELEASE} comparability must answer Retired when only the earlier build had the check. Its disappearance is the scanner shrinking, never the site improving.`,
    );
  }
  if (compare && !compare.includes("Comparability::DetectorChanged")) {
    failures.push(
      `${ENGINE_RELEASE} comparability must answer DetectorChanged on a moved contract. A re-contracted check compared against its own past verifies findings fixed under changed semantics.`,
    );
  }

  const dbStamp = read(DB_STAMP);
  const readStamp = functionBody(dbStamp, "read_stamp");
  if (readStamp && readStamp.includes("crate::core::engine_release::")) {
    failures.push(
      `${DB_STAMP} read_stamp must not fall back to the current build. Filling a missing stamp in with the running binary claims a past run was taken by code that did not exist yet.`,
    );
  }
  const recordInventory = functionBody(dbStamp, "record_inventory");
  if (recordInventory && !/SELECT 1 FROM engine_releases/.test(recordInventory)) {
    failures.push(
      `${DB_STAMP} record_inventory must skip a build already on record. The rows describe a past build, and a past build does not change its mind.`,
    );
  }
  if (recordInventory && /INSERT OR REPLACE INTO engine_release/.test(recordInventory)) {
    failures.push(
      `${DB_STAMP} record_inventory must not overwrite a recorded inventory. Rewriting it destroys the only evidence of what the older build could produce.`,
    );
  }

  const blame = read(BLAME);
  const attributable = functionBody(blame, "attributable");
  if (!attributable) {
    failures.push(
      `${BLAME} must keep an attributable() decision. Without it every appearing finding is laid at the deploy's door, including the ones this release invented.`,
    );
  }
  if (attributable) {
    for (const withheld of ["NewCheck", "Retired", "DetectorChanged", "ProfileChanged"]) {
      if (attributable.includes(`Comparability::${withheld}`)) {
        failures.push(
          `${BLAME} attributable() accepts Comparability::${withheld}. That verdict is positive evidence that the scanner moved, so the finding is not the deploy's.`,
        );
      }
    }
    if (attributable.includes("Comparability::Unattested")) {
      failures.push(
        `${BLAME} attributable() accepts an unattested comparison. A run produced by a build nobody can name is not a baseline to accuse a commit against, and "probably the same build" is the assumption that made upgrades look like regressions.`,
      );
    }
    if (!attributable.includes("Comparability::Unregistered")) {
      failures.push(
        `${BLAME} attributable() must still attribute ids no build ever registered. Integration signals are not engine checks, both builds were equally ignorant of them, and dropping them would silently narrow blame.`,
      );
    }
  }
  const emit = functionBody(blame, "emit_regression_blame");
  const decide = functionBody(blame, "decide_blame");
  const appearing = functionBody(blame, "appearing_issues");
  const withheld = functionBody(blame, "withheld_check_count");
  if ((blame.match(/!input\.active_check_ids\.contains\(/g) ?? []).length !== 1) {
    failures.push(`${BLAME} must define the appearing predicate exactly once.`);
  }
  if (
    !appearing?.includes("dedup_by_check_id(") ||
    !/filter\(\|issue\| !input\.active_check_ids\.contains\(&issue\.check_id\)\)/.test(appearing) ||
    !decide?.includes("appearing_issues(input)") ||
    !withheld?.includes("appearing_issues(input)")
  ) {
    failures.push(
      `${BLAME} must share appearing_issues between the decision and withheld count, with one deduplicated set of inactive checks.`,
    );
  }
  if (emit && !emit.includes("Attribution::between(")) {
    failures.push(
      `${BLAME} emit_regression_blame must resolve both runs' provenance before it accuses a commit.`,
    );
  }
  if (!decide) {
    failures.push(
      `${BLAME} must define decide_blame: the decision is what the hosted port replays, so it lives apart from git and the database.`,
    );
  }
  const emittedCode = emit?.replace(/\/\*[\s\S]*?\*\//g, "");
  if (
    emit &&
    !/^[ \t]*let\s+\w+\s*=\s*decide_blame\([^;]*&attribution\s*,?\s*\)/m.test(emittedCode)
  ) {
    failures.push(
      `${BLAME} emit_regression_blame must decide through decide_blame, the one decision both runtimes pin.`,
    );
  }
  if (decide && /\b(?:now\s*\(|env\s*::|Database\b|get_commits_between\b)/.test(decide)) {
    failures.push(
      `${BLAME} decide_blame must stay pure: clock, environment, database and git access belong in the caller.`,
    );
  }
  if (decide && !/partition\(\|issue\| attribution\.attributable/.test(decide)) {
    failures.push(
      `${BLAME} must split appearing findings on attribution before counting them, or the headline count blames commits for checks this release added.`,
    );
  }
  if (decide && !/filter\(\|check_id\| attribution\.attributable/.test(decide)) {
    failures.push(
      `${BLAME} must filter the fixed set on attribution too. A retired check stops reporting, and counting that as fixed credits a deploy for work nobody did.`,
    );
  }

  const migration = read(MIGRATION);
  for (const column of [
    "engine_release",
    "manifest_digest",
    "canonicalizer",
    "crawl_profile",
    "execution_profile_json",
    "scope_revision",
  ]) {
    if (!migration.includes(column)) {
      failures.push(
        `${MIGRATION} must add ${column} to scan_runs. The stamp is only as useful as the facts it carries.`,
      );
    }
  }
  if (!/PRIMARY KEY \(engine_release, manifest_digest\)/.test(migration)) {
    failures.push(
      `${MIGRATION} must key the recorded inventory by release AND manifest digest. A build can change its manifest without changing its version, and collapsing the two would let one inventory answer for both.`,
    );
  }
  if (/contract TEXT NOT NULL/.test(migration)) {
    failures.push(
      `${MIGRATION} must allow a NULL contract. Code-scan checks are enumerable but unversioned, and a placeholder contract would claim a promise nothing makes.`,
    );
  }

  return failures;
}
