import { describe, expect, it } from "vitest";
import { verificationProvenanceFailures } from "./lib/guardrail-issue-state-rules.mjs";

const VOCAB = "apps/desktop/src-tauri/crates/protocol/src/vocab.rs";
const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/020_verification_provenance.sql";
const STORE = "apps/desktop/src-tauri/src/db/issue_states.rs";
const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";

function sources() {
  return {
    "apps/desktop/src-tauri/src/db/migrations/001_baseline.sql": "CREATE TABLE work_items (...);",
    [VOCAB]: `pub enum VerifiedBy { UserClaim, LocalScan }
impl VerifiedBy {
    pub fn proves_absence(self) -> bool {
        matches!(self, VerifiedBy::LocalScan)
    }
}`,
    [MIGRATION]: `ALTER TABLE t ADD COLUMN verified_by TEXT
  CHECK ((status = 'verified') = (verified_by IS NOT NULL));`,
    [STORE]: `pub fn reconcile_reobserved_lifecycle(tx: &Transaction) -> Result<(), DbError> {
    for verified_by in VerifiedBy::ALL {
        let next = if verified_by.proves_absence() { "regressed" } else { "new" };
        tx.execute("UPDATE project_issue_states SET status = ?1, verified_by = NULL", next)?;
    }
    Ok(())
}`,
    [PROJECTION]: `reconcile_reobserved_lifecycle(tx, project_id, &environment_url, observed_at, ids)?;`,
  };
}

function failures(mutate = () => {}) {
  const files = sources();
  mutate(files);
  const read = (file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  };
  const exists = (file) => file in files;
  return verificationProvenanceFailures(read, exists).join("\n");
}

describe("the shared vocabulary", () => {
  it("passes when every rule holds", () => {
    expect(failures()).toBe("");
  });

  it("fails when the prover vocabulary leaves the engine", () => {
    expect(failures((files) => delete files[VOCAB])).toContain("VerifiedBy with proves_absence");
  });

  it("fails when nothing answers whether a verification observed anything", () => {
    expect(
      failures((files) => {
        files[VOCAB] = "pub enum VerifiedBy { UserClaim, LocalScan }";
      }),
    ).toContain("proves_absence");
  });
});

describe("the schema invariant", () => {
  it("fails when the migration is gone", () => {
    expect(failures((files) => delete files[MIGRATION])).toContain("BOTH directions");
  });

  it("fails when the CHECK only forbids one direction", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = "CHECK (verified_by IS NULL OR status = 'verified')";
      }),
    ).toContain("BOTH directions");
  });
});

describe("re-observation", () => {
  it("fails when a re-observed verification branches on the status alone", () => {
    expect(
      failures((files) => {
        files[STORE] = files[STORE].replace(
          'let next = if verified_by.proves_absence() { "regressed" } else { "new" };',
          'let next = "regressed";',
        );
      }),
    ).toContain("proves_absence()");
  });

  it("fails when the prover outlives the status it described", () => {
    expect(
      failures((files) => {
        files[STORE] = files[STORE].replace(", verified_by = NULL", "");
      }),
    ).toContain("clear verified_by");
  });

  it("fails when a scan path reconciles lifecycle on its own", () => {
    expect(
      failures((files) => {
        files[PROJECTION] = "// reconciles inline";
      }),
    ).toContain("shared reconcile_reobserved_lifecycle");
  });

  it("fails when a scan path writes the regressed status itself", () => {
    expect(
      failures((files) => {
        files[PROJECTION] += '\ntx.execute("UPDATE", IssueStatus::Regressed.as_str())?;';
      }),
    ).toContain("must not write the regressed status");
  });

  it("fails when the reconciler is missing entirely", () => {
    expect(
      failures((files) => {
        files[STORE] = files[STORE].replace("pub fn reconcile_reobserved_lifecycle", "pub fn gone");
      }),
    ).toContain("proves_absence()");
  });
});
