import { scanStampFunctionBody as functionBody } from "./scan-stamp-function.mjs";

const CORE_STAMP = "apps/desktop/src-tauri/src/core/engine_release.rs";
const DB_STAMP = "apps/desktop/src-tauri/src/db/engine_release.rs";
const SCAN_RUNS = "apps/desktop/src-tauri/src/db/scan_runs.rs";
const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/019_engine_release_stamp.sql";

// Extract every scan_runs insert column list.
function scanRunInsertColumns(source) {
  return [...source.matchAll(/INSERT INTO scan_runs \(([\s\S]*?)\)/g)].map((match) => match[1]);
}

export function scanRunStampFailures(read) {
  const failures = [];

  const scanRuns = read(SCAN_RUNS);
  const insertColumns = scanRunInsertColumns(scanRuns);
  if (insertColumns.length === 0) {
    failures.push(
      `${SCAN_RUNS} has no INSERT INTO scan_runs. If persistence moved, move this rule with it: the stamp has to be written where runs are written.`,
    );
  }
  for (const columns of insertColumns) {
    for (const column of [
      "engine_release",
      "manifest_digest",
      "canonicalizer",
      "crawl_profile",
      "execution_profile_json",
    ]) {
      if (!columns.includes(column)) {
        failures.push(
          `${SCAN_RUNS} inserts a scan run without ${column}. An unstamped run is unattributable forever, and every later comparison against it silently concludes nothing.`,
        );
      }
    }
  }
  const persist = functionBody(scanRuns, "persist_run_batch") ?? "";
  const stampAt = persist.indexOf("crate::core::engine_release::code_stamp(");
  if (!/sitecmd_engine_host::load\(\)/.test(persist)) {
    failures.push(
      `${SCAN_RUNS} must load the module inside run persistence so the caller cannot supply the stamp.`,
    );
  }
  if (
    stampAt < 0 ||
    !/crate::core::engine_release::code_stamp\(\s*engine\.info\(\),/.test(persist)
  ) {
    failures.push(
      `${SCAN_RUNS} must derive the stamp from crate::core::engine_release::code_stamp using the loaded module's info.`,
    );
  }
  const transactionAt = persist.indexOf("conn.transaction()");
  const insertAt = persist.indexOf("INSERT INTO scan_runs");
  const commitAt = persist.indexOf("tx.commit()");
  if (
    transactionAt < 0 ||
    stampAt <= transactionAt ||
    insertAt <= stampAt ||
    commitAt <= insertAt ||
    !/tx\.execute\(\s*"INSERT INTO scan_runs/.test(persist)
  ) {
    failures.push(`${SCAN_RUNS} must write the module's stamp in the run's transaction.`);
  }

  const coreStamp = read(CORE_STAMP);
  if (!coreStamp.includes('env!("CARGO_PKG_VERSION")')) {
    failures.push(
      `${CORE_STAMP} must read the release from the crate version. A hand-maintained release string is a claim about a build nobody verified.`,
    );
  }
  const codeStamp = functionBody(coreStamp, "code_stamp") ?? "";
  if (!/manifest_digest:\s*info\.manifest_digest\.as_str\(\)/.test(codeStamp)) {
    failures.push(
      `${CORE_STAMP} must derive the stamp's manifest digest from the module's engine info.`,
    );
  }

  const dbStamp = read(DB_STAMP);
  const readStamp = functionBody(dbStamp, "read_stamp");
  if (readStamp && readStamp.includes("crate::core::engine_release::")) {
    failures.push(
      `${DB_STAMP} read_stamp must not fall back to the current build. Filling a missing stamp in with the running binary claims a past run was taken by code that did not exist yet.`,
    );
  }
  const inventoryWrite =
    /(?:INSERT INTO|INSERT OR [A-Z]+ INTO|UPDATE|DELETE FROM) engine_release(?:s|_checks)\b/;
  if ([scanRuns, coreStamp, dbStamp].some((source) => inventoryWrite.test(source))) {
    failures.push(`${SCAN_RUNS} and the stamp readers must leave legacy inventory rows untouched.`);
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
