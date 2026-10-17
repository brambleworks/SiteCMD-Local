import { describe, expect, it } from "vitest";
import { engineStampFailures } from "./lib/guardrail-engine-stamp-rules.mjs";

const ENGINE_RELEASE = "apps/desktop/src-tauri/crates/engine/src/release.rs";
const CORE_STAMP = "apps/desktop/src-tauri/src/core/engine_release.rs";
const DB_STAMP = "apps/desktop/src-tauri/src/db/engine_release.rs";
const SCAN_RUNS = "apps/desktop/src-tauri/src/db/scan_runs.rs";
const BLAME = "apps/desktop/src-tauri/src/core/regression_blame.rs";
const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/019_engine_release_stamp.sql";

const HEALTHY = {
  [SCAN_RUNS]: `
fn record_run_stamp(
    conn: &Connection,
    surface: ObservedSurface,
) -> Result<RunStamp, DbError> {
    let stamp = crate::core::engine_release::stamp(surface, scan_profile, browser_ran);
    super::engine_release::record_inventory(conn, &stamp, &CURRENT_INVENTORY, recorded_at)?;
    Ok(RunStamp { engine_release: stamp.engine_release })
}

impl Database {
    pub fn start_multi_page_scan_run(&self) -> Result<i64, DbError> {
        let stamp = record_run_stamp(&tx, ObservedSurface::Web, None, false, started_at)?;
        tx.execute(
            "INSERT INTO scan_runs (
                execution_id, engine_release, manifest_digest, canonicalizer,
                crawl_profile, execution_profile_json, scope_revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        Ok(1)
    }

    pub fn persist_normalized_scan_run(&self) -> Result<i64, DbError> {
        let stamp = record_run_stamp(&tx, surface, None, false, batch.started_at)?;
        tx.execute(
            "INSERT INTO scan_runs (
                execution_id, engine_release, manifest_digest, canonicalizer,
                crawl_profile, execution_profile_json, scope_revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        Ok(1)
    }
}
`,
  [CORE_STAMP]: `
pub const ENGINE_RELEASE: &str = env!("CARGO_PKG_VERSION");
pub static CURRENT_INVENTORY: LazyLock<CheckInventory> = LazyLock::new(|| {
    CheckInventory::from_manifest(&sitecmd_engine::manifest::capability_manifest())
        .with_unversioned(crate::core::code_scan::registry::registered_code_check_ids())
});
`,
  [ENGINE_RELEASE]: `
impl ReleaseStamp {
    pub fn current(engine_release: impl Into<String>) -> Self {
        Self { manifest_digest: crate::manifest::capability_manifest().manifest_digest }
    }
}

pub fn comparability(check_id: &str) -> Comparability {
    match (before.inventory.lookup(check_id), after.inventory.lookup(check_id)) {
        (None, None) => Comparability::Unregistered,
        (None, Some(_)) => Comparability::NewCheck,
        (Some(_), None) => Comparability::Retired,
        (Some(earlier), Some(later)) => {
            if earlier.contract != later.contract {
                return Comparability::DetectorChanged;
            }
            Comparability::Comparable
        }
    }
}
`,
  [DB_STAMP]: `
pub(super) fn record_inventory(conn: &Connection) -> Result<(), DbError> {
    let already_recorded: Option<i64> = conn
        .query_row("SELECT 1 FROM engine_releases WHERE engine_release = ?1", params![release], |row| row.get(0))
        .optional()?;
    if already_recorded.is_some() {
        return Ok(());
    }
    conn.execute("INSERT INTO engine_releases (engine_release) VALUES (?1)", params![release])?;
    Ok(())
}

pub(super) fn read_stamp(conn: &Connection, run_id: i64) -> Result<Option<ReleaseStamp>, DbError> {
    let row = conn.query_row("SELECT engine_release FROM scan_runs WHERE id = ?1", params![run_id], |row| row.get(0)).optional()?;
    Ok(None)
}
`,
  [BLAME]: `
impl Attribution {
    pub(crate) fn attributable(&self, check_id: &str) -> bool {
        matches!(
            self.verdict(check_id),
            Comparability::Comparable | Comparability::Unregistered
        )
    }
}

pub fn emit_regression_blame(ctx: BlameContext<'_>) -> Option<RegressionNotice> {
    let attribution = Attribution::between(ctx.db, previous.scan_id, ctx.scan_id);
    let decision = decide_blame(&input, &attribution)?;
    None
}

fn appearing_issues(input: &BlameInput) -> Vec<&CurrentIssue> {
    dedup_by_check_id(input.current_issues.iter()
        .filter(|issue| !input.active_check_ids.contains(&issue.check_id)).collect())
}

fn withheld_check_count(input: &BlameInput, attribution: &impl BlameAttribution) -> usize {
    appearing_issues(input).into_iter()
        .filter(|issue| !attribution.attributable(&issue.check_id)).count()
}

pub fn decide_blame(input: &BlameInput, attribution: &impl BlameAttribution) -> Option<BlameDecision> {
    let appeared = appearing_issues(input);
    let (new_issues, detector_changed): (Vec<&CurrentIssue>, Vec<&CurrentIssue>) = appeared
        .into_iter()
        .partition(|issue| attribution.attributable(&issue.check_id));
    let mut fixed_check_ids: Vec<&String> = snapshot
        .active_check_ids
        .iter()
        .filter(|check_id| attribution.attributable(check_id))
        .collect();
    None
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
  return engineStampFailures((file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  });
}

describe("every run says what produced it", () => {
  it("passes when every rule holds", () => {
    expect(failuresWith()).toEqual([]);
  });

  it("fails when a run is inserted without the release that produced it", () => {
    const unstamped = HEALTHY[SCAN_RUNS].replace(
      '                execution_id, engine_release, manifest_digest, canonicalizer,\n                crawl_profile, execution_profile_json, scope_revision\n             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",\n        )?;\n        Ok(1)\n    }\n\n    pub fn persist_normalized_scan_run',
      '                execution_id\n             ) VALUES (?1)",\n        )?;\n        Ok(1)\n    }\n\n    pub fn persist_normalized_scan_run',
    );
    expect(failuresWith({ [SCAN_RUNS]: unstamped }).join(" ")).toContain(
      "inserts a scan run without engine_release",
    );
  });

  it("fails when the stamp is hand-written instead of derived from the build", () => {
    const literal = HEALTHY[SCAN_RUNS].replace(
      "let stamp = crate::core::engine_release::stamp(surface, scan_profile, browser_ran);",
      'let stamp = RunStamp { engine_release: "1.5.4".into() };',
    );
    expect(failuresWith({ [SCAN_RUNS]: literal }).join(" ")).toContain(
      "must derive the stamp from crate::core::engine_release::stamp",
    );
  });

  it("fails when the inventory is recorded outside the run's transaction", () => {
    const outside = HEALTHY[SCAN_RUNS].replace(
      "record_run_stamp(&tx, surface,",
      "record_run_stamp(conn, surface,",
    );
    expect(failuresWith({ [SCAN_RUNS]: outside }).join(" ")).toContain(
      "calls record_run_stamp outside the run's transaction",
    );
  });

  it("fails when the release string stops coming from the crate version", () => {
    const hardcoded = HEALTHY[CORE_STAMP].replace('env!("CARGO_PKG_VERSION")', '"1.5.4"');
    expect(failuresWith({ [CORE_STAMP]: hardcoded }).join(" ")).toContain(
      "must read the release from the crate version",
    );
  });

  it("fails when code-scan checks stop being inventoried", () => {
    const webOnly = HEALTHY[CORE_STAMP].replace(
      ".with_unversioned(crate::core::code_scan::registry::registered_code_check_ids())",
      "",
    );
    expect(failuresWith({ [CORE_STAMP]: webOnly }).join(" ")).toContain(
      "must inventory the code-scan checks too",
    );
  });

  it("fails when the stamp names a manifest the build does not carry", () => {
    const detached = HEALTHY[ENGINE_RELEASE].replace(
      "crate::manifest::capability_manifest().manifest_digest",
      "recorded_digest",
    );
    expect(failuresWith({ [ENGINE_RELEASE]: detached }).join(" ")).toContain(
      "must read the digest from the manifest this build carries",
    );
  });
});

describe("what the older build could produce survives the upgrade", () => {
  it("fails when a missing stamp falls back to the current build", () => {
    const borrowed = HEALTHY[DB_STAMP].replace(
      "    Ok(None)",
      "    Ok(Some(crate::core::engine_release::stamp(ObservedSurface::Web, None, false)))",
    );
    expect(failuresWith({ [DB_STAMP]: borrowed }).join(" ")).toContain(
      "must not fall back to the current build",
    );
  });

  it("fails when a recorded inventory can be rewritten", () => {
    const rewritten = HEALTHY[DB_STAMP].replace(
      'conn.execute("INSERT INTO engine_releases (engine_release) VALUES (?1)", params![release])?;',
      'conn.execute("INSERT OR REPLACE INTO engine_releases (engine_release) VALUES (?1)", params![release])?;',
    );
    expect(failuresWith({ [DB_STAMP]: rewritten }).join(" ")).toContain(
      "must not overwrite a recorded inventory",
    );
  });

  it("fails when the recorded inventory is keyed by release alone", () => {
    const looseKey = HEALTHY[MIGRATION].replace(
      "PRIMARY KEY (engine_release, manifest_digest)",
      "PRIMARY KEY (engine_release)",
    );
    expect(failuresWith({ [MIGRATION]: looseKey }).join(" ")).toContain(
      "must key the recorded inventory by release AND manifest digest",
    );
  });

  it("fails when an unversioned check is forced to carry a contract", () => {
    const forced = HEALTHY[MIGRATION].replace("contract TEXT,", "contract TEXT NOT NULL,");
    expect(failuresWith({ [MIGRATION]: forced }).join(" ")).toContain("must allow a NULL contract");
  });

  it("fails when the stamp columns are dropped from the migration", () => {
    const trimmed = HEALTHY[MIGRATION].replace(
      "ALTER TABLE scan_runs ADD COLUMN scope_revision INTEGER;",
      "",
    );
    expect(failuresWith({ [MIGRATION]: trimmed }).join(" ")).toContain(
      "must add scope_revision to scan_runs",
    );
  });
});

describe("blame accuses a commit only when the scanner held still", () => {
  it.each([
    ["fn appearing_issues(", "fn other_issues("],
    ["let appeared = appearing_issues(input);", "let appeared = input.current_issues;"],
    ["appearing_issues(input).into_iter()", "input.current_issues.iter()"],
    ["!input.active_check_ids.contains(&issue.check_id)", "true"],
  ])("requires one definition of appearing checks: %s", (before, after) => {
    const mutant = HEALTHY[BLAME].replace(before, after);
    expect(mutant).not.toEqual(HEALTHY[BLAME]);
    expect(failuresWith({ [BLAME]: mutant }).join(" ")).toContain(
      "must share appearing_issues between the decision and withheld count",
    );
  });

  it("fails when a check the older build lacked is blamed on a deploy", () => {
    const permissive = HEALTHY[BLAME].replace(
      "Comparability::Comparable | Comparability::Unregistered",
      "Comparability::Comparable | Comparability::Unregistered | Comparability::NewCheck",
    );
    expect(failuresWith({ [BLAME]: permissive }).join(" ")).toContain(
      "attributable() accepts Comparability::NewCheck",
    );
  });

  it("fails when a re-contracted check is blamed on a deploy", () => {
    const permissive = HEALTHY[BLAME].replace(
      "Comparability::Comparable | Comparability::Unregistered",
      "Comparability::Comparable | Comparability::DetectorChanged",
    );
    expect(failuresWith({ [BLAME]: permissive }).join(" ")).toContain(
      "attributable() accepts Comparability::DetectorChanged",
    );
  });

  it("fails when an unattested comparison is treated as evidence", () => {
    const permissive = HEALTHY[BLAME].replace(
      "Comparability::Comparable | Comparability::Unregistered",
      "Comparability::Comparable | Comparability::Unregistered | Comparability::Unattested",
    );
    expect(failuresWith({ [BLAME]: permissive }).join(" ")).toContain(
      "accepts an unattested comparison",
    );
  });

  it("fails when ids the engine never produced stop being attributed", () => {
    const narrowed = HEALTHY[BLAME].replace(
      "Comparability::Comparable | Comparability::Unregistered",
      "Comparability::Comparable",
    );
    expect(failuresWith({ [BLAME]: narrowed }).join(" ")).toContain(
      "must still attribute ids no build ever registered",
    );
  });

  it("fails when appearing findings are counted before attribution", () => {
    const unsplit = HEALTHY[BLAME].replace(
      "    let (new_issues, detector_changed): (Vec<&CurrentIssue>, Vec<&CurrentIssue>) = appeared\n        .into_iter()\n        .partition(|issue| attribution.attributable(&issue.check_id));",
      "    let new_issues = appeared;",
    );
    expect(failuresWith({ [BLAME]: unsplit }).join(" ")).toContain(
      "must split appearing findings on attribution",
    );
  });

  it("fails when a retired check is still counted as a fix", () => {
    const unfiltered = HEALTHY[BLAME].replace(
      "        .filter(|check_id| attribution.attributable(check_id))\n",
      "",
    );
    expect(failuresWith({ [BLAME]: unfiltered }).join(" ")).toContain(
      "must filter the fixed set on attribution too",
    );
  });

  it("fails when blame stops reading provenance at all", () => {
    const blind = HEALTHY[BLAME].replace(
      "    let attribution = Attribution::between(ctx.db, previous.scan_id, ctx.scan_id);",
      "",
    );
    expect(failuresWith({ [BLAME]: blind }).join(" ")).toContain(
      "must resolve both runs' provenance",
    );
  });

  it("fails when emitting blame bypasses the shared decision", () => {
    const bypassed = HEALTHY[BLAME].replace(
      "    let decision = decide_blame(&input, &attribution)?;",
      "",
    );
    expect(failuresWith({ [BLAME]: bypassed }).join(" ")).toContain(
      "must decide through decide_blame",
    );
  });

  it("fails when the shared decision is missing", () => {
    const missing = HEALTHY[BLAME].replace("pub fn decide_blame(", "pub fn other_decision(");
    expect(failuresWith({ [BLAME]: missing }).join(" ")).toContain("must define decide_blame");
  });

  it.each([
    "    let decision = decide_blame(&input, &AlwaysAttributable)?;",
    "    // let decision = decide_blame(&input, &attribution)?;",
    "    /* let decision = decide_blame(&input, &attribution)?; */",
  ])("rejects a decision without recorded attribution: %s", (replacement) => {
    const replaced = HEALTHY[BLAME].replace(
      "    let decision = decide_blame(&input, &attribution)?;",
      replacement,
    );
    expect(failuresWith({ [BLAME]: replaced }).join(" ")).toContain(
      "must decide through decide_blame",
    );
  });

  it.each([
    "chrono::Utc::now()",
    "std::env::var(key)",
    "Database::open(path)",
    "get_commits_between(path)",
  ])("rejects runtime access in the decision: %s", (expression) => {
    const impure = HEALTHY[BLAME].replace(
      "    let (new_issues, detector_changed)",
      `    let forbidden = ${expression};\n    let (new_issues, detector_changed)`,
    );
    expect(failuresWith({ [BLAME]: impure }).join(" ")).toContain("decide_blame must stay pure");
  });
});
