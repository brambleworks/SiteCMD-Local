// A scan run can persist without the stamp of the module that produced it.
import { describe, expect, it } from "vitest";
import { scanRunStampFailures } from "./lib/guardrail-scan-run-stamp-rules.mjs";

const CORE_STAMP = "apps/desktop/src-tauri/src/core/engine_release.rs";
const DB_STAMP = "apps/desktop/src-tauri/src/db/engine_release.rs";
const SCAN_RUNS = "apps/desktop/src-tauri/src/db/scan_runs.rs";
const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/019_engine_release_stamp.sql";

const HEALTHY = {
  [SCAN_RUNS]: `
fn persist_run_batch(conn: &mut Connection, batch: NormalizedRunBatch) -> Result<i64, DbError> {
    let tx = conn.transaction()?;
    let engine = sitecmd_engine_host::load()?;
    let stamp = crate::core::engine_release::code_stamp(engine.info(), None);
    tx.execute(
        "INSERT INTO scan_runs (
            execution_id, engine_release, manifest_digest, canonicalizer,
            crawl_profile, execution_profile_json, scope_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    tx.commit()?;
    Ok(1)
}
`,
  [CORE_STAMP]: `
pub const ENGINE_RELEASE: &str = env!("CARGO_PKG_VERSION");
pub fn code_stamp(info: &EngineInfo, scan_profile: Option<&str>) -> ReleaseStamp {
    ReleaseStamp {
        engine_release: ENGINE_RELEASE.into(),
        manifest_digest: info.manifest_digest.as_str().into(),
    }
}
`,
  [DB_STAMP]: `
pub(super) fn read_stamp(conn: &Connection, run_id: i64) -> Result<Option<ReleaseStamp>, DbError> {
    let row = conn.query_row("SELECT engine_release FROM scan_runs WHERE id = ?1", params![run_id], |row| row.get(0)).optional()?;
    Ok(None)
}
`,
  [MIGRATION]: `
ALTER TABLE scan_runs ADD COLUMN engine_release TEXT;
ALTER TABLE scan_runs ADD COLUMN manifest_digest TEXT;
ALTER TABLE scan_runs ADD COLUMN canonicalizer INTEGER;
ALTER TABLE scan_runs ADD COLUMN crawl_profile INTEGER;
ALTER TABLE scan_runs ADD COLUMN execution_profile_json TEXT;
ALTER TABLE scan_runs ADD COLUMN scope_revision INTEGER;

CREATE TABLE engine_releases (
    engine_release TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    PRIMARY KEY (engine_release, manifest_digest)
);

CREATE TABLE engine_release_checks (
    check_id TEXT NOT NULL,
    contract TEXT,
    compare_on TEXT NOT NULL DEFAULT '[]',
    family INTEGER NOT NULL DEFAULT 0
);
`,
};

function failuresWith(overrides = {}) {
  const files = { ...HEALTHY, ...overrides };
  return scanRunStampFailures((file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  });
}

describe("every run says what produced it", () => {
  it("passes when every rule holds", () => {
    // Bug: The guardrail could reject a run with a complete module stamp.
    expect(failuresWith()).toEqual([]);
  });

  it("fails when a run is inserted without the release that produced it", () => {
    // Bug: A persisted run could lose the release that produced it.
    const unstamped = HEALTHY[SCAN_RUNS].replace(
      "execution_id, engine_release, manifest_digest",
      "execution_id, manifest_digest",
    );
    expect(failuresWith({ [SCAN_RUNS]: unstamped }).join(" ")).toContain(
      "inserts a scan run without engine_release",
    );
  });

  it("fails when the stamp is hand-written instead of derived from the build", () => {
    // Bug: A hand-written stamp could identify the wrong build.
    const literal = HEALTHY[SCAN_RUNS].replace(
      "let stamp = crate::core::engine_release::code_stamp(engine.info(), None);",
      'let stamp = RunStamp { engine_release: "1.5.4".into() };',
    );
    expect(failuresWith({ [SCAN_RUNS]: literal }).join(" ")).toContain(
      "must derive the stamp from crate::core::engine_release::code_stamp",
    );
  });

  it("fails when the run is inserted outside its transaction", () => {
    // A write outside the transaction could leave partial evidence behind.
    const outside = HEALTHY[SCAN_RUNS].replace("tx.execute(", "conn.execute(");
    expect(failuresWith({ [SCAN_RUNS]: outside }).join(" ")).toContain(
      "must write the module's stamp in the run's transaction",
    );
  });

  it("fails when the release string stops coming from the crate version", () => {
    // Bug: A hardcoded release string could become stale when the crate version changes.
    const hardcoded = HEALTHY[CORE_STAMP].replace('env!("CARGO_PKG_VERSION")', '"1.5.4"');
    expect(failuresWith({ [CORE_STAMP]: hardcoded }).join(" ")).toContain(
      "must read the release from the crate version",
    );
  });

  it("fails when the stamp omits the module's manifest digest", () => {
    // A host-provided digest can attribute the evidence to a different module.
    const compiled = HEALTHY[CORE_STAMP].replace(
      "info.manifest_digest.as_str()",
      "COMPILED_DIGEST",
    );
    expect(failuresWith({ [CORE_STAMP]: compiled }).join(" ")).toContain(
      "must derive the stamp's manifest digest from the module's engine info",
    );
  });
});

describe("what the older build could produce survives the upgrade", () => {
  it("fails when a missing stamp falls back to the current build", () => {
    // Bug: An older run without a stamp could be attributed to the current build.
    const borrowed = HEALTHY[DB_STAMP].replace(
      "    Ok(None)",
      "    Ok(Some(crate::core::engine_release::code_stamp(engine.info(), None)))",
    );
    expect(failuresWith({ [DB_STAMP]: borrowed }).join(" ")).toContain(
      "must not fall back to the current build",
    );
  });

  it("fails when a recorded inventory can be rewritten", () => {
    // Bug: Replacing a recorded inventory could change how past runs are interpreted.
    const rewritten =
      HEALTHY[DB_STAMP] +
      'fn write(conn: &Connection) { conn.execute("INSERT OR REPLACE INTO engine_releases (...) VALUES (...)"); }';

    expect(failuresWith({ [DB_STAMP]: rewritten }).join(" ")).toContain(
      "must leave legacy inventory rows untouched",
    );
  });

  it("detects all inventory write forms for both legacy tables", () => {
    // A pattern the regex audit refuses blocked the push gate.
    const readOnly = `${SCAN_RUNS} and the stamp readers must leave legacy inventory rows untouched.`;
    for (const table of ["engine_releases", "engine_release_checks"]) {
      for (const verb of ["INSERT INTO", "INSERT OR IGNORE INTO", "UPDATE", "DELETE FROM"]) {
        const sql = `${verb} ${table}`;
        const source = HEALTHY[DB_STAMP] + `\nconst SQL: &str = "${sql}";`;
        expect(failuresWith({ [DB_STAMP]: source }), sql).toEqual([readOnly]);
      }
    }

    for (const sql of [
      "SELECT * FROM engine_releases",
      "UPDATE engine_release_checks_archive",
      "INSERT OR ignore INTO engine_releases",
      "DELETE FROM engine_release",
    ]) {
      const source = HEALTHY[DB_STAMP] + `\nconst SQL: &str = "${sql}";`;
      expect(failuresWith({ [DB_STAMP]: source }), sql).toEqual([]);
    }
  });

  it("fails when the recorded inventory is keyed by release alone", () => {
    // Bug: Different inventories for the same release could collide.
    const looseKey = HEALTHY[MIGRATION].replace(
      "PRIMARY KEY (engine_release, manifest_digest)",
      "PRIMARY KEY (engine_release)",
    );
    expect(failuresWith({ [MIGRATION]: looseKey }).join(" ")).toContain(
      "must key the recorded inventory by release AND manifest digest",
    );
  });

  it("fails when an unversioned check is forced to carry a contract", () => {
    // Bug: A required contract could prevent unversioned checks from being recorded.
    const forced = HEALTHY[MIGRATION].replace("contract TEXT,", "contract TEXT NOT NULL,");
    expect(failuresWith({ [MIGRATION]: forced }).join(" ")).toContain("must allow a NULL contract");
  });

  it("fails when the stamp columns are dropped from the migration", () => {
    // Bug: A migrated database could lack the scope revision column needed for run stamps.
    const trimmed = HEALTHY[MIGRATION].replace(
      "ALTER TABLE scan_runs ADD COLUMN scope_revision INTEGER;",
      "",
    );
    expect(failuresWith({ [MIGRATION]: trimmed }).join(" ")).toContain(
      "must add scope_revision to scan_runs",
    );
  });
});
