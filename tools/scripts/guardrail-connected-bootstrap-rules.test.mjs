import { describe, expect, it } from "vitest";
import { connectedBootstrapFailures } from "./lib/guardrail-connected-bootstrap-rules.mjs";

const BOOTSTRAP = "apps/desktop/src-tauri/src/db/connected_bootstrap.rs";
const REGISTRY = "apps/desktop/src-tauri/src/db/mod.rs";
const OTHER = "apps/desktop/src-tauri/src/background/sync.rs";
const OTHER_TESTS = "apps/desktop/src-tauri/src/db/connected_bootstrap_tests.rs";
const CLI = "apps/desktop/src-tauri/src/cli/scan.rs";
const CLI_BINARY = "apps/desktop/src-tauri/crates/cli/src/main.rs";

function sources() {
  const files = {
    [BOOTSTRAP]: `pub enum BootstrapState {
    Active,
    Snoozed { until: i64 },
    Ignored,
    Blocked { reason: Option<String> },
    Verified { by: VerifiedBy },
    Regressed,
}

pub enum OccurrenceLocation {
    File { rule: String, path: String },
    Whole,
}

fn state_from_row(check_id: &str, status: IssueStatus) -> Result<BootstrapState, DbError> {
    Ok(match status {
        IssueStatus::Snoozed => BootstrapState::Snoozed {
            until: snooze_until.ok_or_else(|| {
                DbError::Other(format!("snoozed group {check_id} has no deadline to declare"))
            })?,
        },
        IssueStatus::Verified => BootstrapState::Verified {
            by: verified_by.ok_or_else(|| {
                DbError::Other(format!("verified group {check_id} has no prover to name"))
            })?,
        },
        IssueStatus::Regressed => BootstrapState::Regressed,
    })
}

fn read_projection(conn: &Connection) -> Result<(), DbError> {
    let mut statement = conn.prepare(
        "SELECT check_id, source, MIN(first_seen_at)
         FROM work_items
         WHERE project_id = ?1 AND env_url = ?2 AND resolved_at IS NULL AND source = 'code_scan'
         GROUP BY check_id, source",
    )?;
    Ok(())
}

fn read_overrides(conn: &Connection) -> Result<(), DbError> {
    let mut statement = conn.prepare(
        "SELECT check_id, status FROM project_issue_states
         WHERE project_id = ?1 AND env_url = ?2",
    )?;
    Ok(())
}

fn last_known_occurrences(conn: &Connection) -> Result<(), DbError> {
    let mut statement = conn.prepare(
        "WITH present AS (
             SELECT DISTINCT finding.canonical_check_id AS check_id,
                             run.execution_id AS execution_id,
                             execution.started_at AS started_at
             FROM scan_findings finding
             JOIN scan_runs run ON run.id = finding.run_id
             WHERE run.status = 'complete'
               AND run.source = 'code_scan'
               AND finding.verdict IN ('fail', 'warn')
         ),
         newest AS (
             SELECT check_id, execution_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY check_id
                        ORDER BY started_at DESC, execution_id DESC
                    ) AS recency
             FROM present
         )
         SELECT newest.check_id, finding.producer_check_id
         FROM newest
         JOIN scan_findings finding ON finding.run_id = run.id
         WHERE newest.recency = 1
           AND run.status = 'complete'
           AND run.source = 'code_scan'
           AND finding.verdict IN ('fail', 'warn')",
    )?;
    Ok(())
}

fn latest_evidence(conn: &Connection) -> Result<Option<SourceEvidence>, DbError> {
    let execution = conn.prepare("SELECT id FROM scan_runs WHERE source = 'code_scan'")?;
    let runs = conn.prepare("SELECT id FROM scan_runs WHERE source = 'code_scan'")?;
    let mut statement = conn.prepare(
        "SELECT finding.canonical_check_id
         FROM scan_findings finding
         JOIN scan_runs run ON run.id = finding.run_id
         WHERE run.status = 'complete'
           AND run.source = 'code_scan'
           AND finding.verdict IN ('fail', 'warn')",
    )?;
    Ok(None)
}

impl Database {
    pub fn derive_bootstrap_set(&self) -> Result<BootstrapSet, DbError> {
        self.execute(move |conn| {
            let tx = conn.unchecked_transaction()?;
            read_projection(&tx)?;
            read_overrides(&tx)?;
            tx.commit()?;
            for (check_id, mut draft) in drafts {
                if !draft.present && draft.state.is_none() {
                    continue;
                }
            }
            Ok(BootstrapSet { groups, evidence })
        })?
    }
}`,
    [REGISTRY]: `mod connected_bootstrap;
pub use connected_bootstrap::{BootstrapGroup, BootstrapSet, BootstrapState};`,
    [OTHER]: `fn drain() {}`,
    [OTHER_TESTS]: `fn derive_bootstrap_set_fixture() {}`,
    [CLI]: `pub fn run_scan() {}`,
    [CLI_BINARY]: `fn main() {}`,
  };
  for (let index = 0; index < 120; index += 1) {
    files[`apps/desktop/src-tauri/src/filler_${index}.rs`] = "fn noop() {}";
  }
  return files;
}

function failures(mutate = () => {}) {
  const files = sources();
  mutate(files);
  const read = (file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  };
  const exists = (file) => file in files;
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
  return connectedBootstrapFailures(read, exists, listFiles).join("\n");
}

describe("the group set", () => {
  it("passes when every rule holds", () => {
    expect(failures()).toBe("");
  });

  it("fails when only the projection is read", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace("            read_overrides(&tx)?;\n", "");
      }),
    ).toContain("union the current projection");
  });

  it("fails when only the overrides are read", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace("            read_projection(&tx)?;\n", "");
      }),
    ).toContain("union the current projection");
  });

  it("fails when the set and the evidence are read separately", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "let tx = conn.unchecked_transaction()?;",
          "let tx = conn;",
        );
      }),
    ).toContain("one transaction");
  });

  it("fails when a scan-fixed group nobody decided about is revived", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "if !draft.present && draft.state.is_none() {",
          "if false {",
        );
      }),
    ).toContain("neither an open row nor an override");
  });

  it("fails when the projection read stops filtering to open rows", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(" AND resolved_at IS NULL", "");
      }),
    ).toContain("open work_items projection");
  });

  it("fails when the overrides are read from somewhere else", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "FROM project_issue_states",
          "FROM work_item_states",
        );
      }),
    ).toContain("read lifecycle overrides");
  });

  it("fails when the derivation also writes", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "            tx.commit()?;",
          `            tx.execute("INSERT INTO project_issue_states (status) VALUES (?1)", [])?;
            tx.commit()?;`,
        );
      }),
    ).toContain("must write nothing");
  });

  it("fails when the effective state is declared instead of the stored one", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "fn state_from_row(check_id: &str, status: IssueStatus)",
          "fn state_from_row(check_id: &str, status: IssueStatus, now_ms: i64)",
        );
      }),
    ).toContain("stored state, not the effective one");
  });

  it("fails when the registry does not expose the derivation", () => {
    expect(failures((files) => (files[REGISTRY] = "mod code_scans;"))).toContain(
      "must register the bootstrap derivation",
    );
  });
});

describe("the state vocabulary", () => {
  it("fails when bootstrap cannot report a regression", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace("    Regressed,\n}", "}");
      }),
    ).toContain("express a regression");
  });

  it("fails when a second place can build a state", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = `fn assert_state() -> Result<BootstrapState, DbError> { Ok(claimed) }
${files[BOOTSTRAP]}`;
      }),
    ).toContain("exactly one place");
  });

  it("fails when a dismissal with no deadline is repaired instead of refused", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          `until: snooze_until.ok_or_else(|| {
                DbError::Other(format!("snoozed group {check_id} has no deadline to declare"))
            })?,`,
          "until: snooze_until.unwrap_or(0),",
        );
      }),
    ).toContain("refuse a dismissal");
  });

  it("fails when a verification with no prover is repaired instead of refused", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          `by: verified_by.ok_or_else(|| {
                DbError::Other(format!("verified group {check_id} has no prover to name"))
            })?,`,
          "by: verified_by.unwrap_or(VerifiedBy::UserClaim),",
        );
      }),
    ).toContain("refuse a dismissal");
  });

  it("fails when the derivation speaks the wire's vocabulary", () => {
    for (const word of ["claimed_fixed", "verified_fixed", "query_dependent", "location_hash"]) {
      expect(
        failures((files) => {
          files[BOOTSTRAP] = `fn wire() -> &'static str { "${word}" }\n${files[BOOTSTRAP]}`;
        }),
      ).toContain("belongs to the payload builder");
    }
  });
});

describe("occurrence identity", () => {
  it("fails when a line number reaches an identity", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "    File { rule: String, path: String },",
          "    File { rule: String, path: String, line: Option<u32> },",
        );
      }),
    ).toContain("line number into an occurrence identity");
  });

  it("fails when the line-counting field moves into an occurrence type", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "    File { rule: String, path: String },",
          "    File {\n        rule: String,\n        path: String,\n        line: Option<u32>,\n    },",
        );
      }),
    ).toContain("line number into an occurrence identity");
  });

  it("fails when a code location is keyed by something other than rule and path", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "    File { rule: String, path: String },",
          "    File { occurrence_id: String },",
        );
      }),
    ).toContain("producer rule and the repository-relative path");
  });

  it("fails when a local finding id reaches an occurrence identity", () => {
    // A covert channel from module to network
    expect(
      failures((files) => {
        files[BOOTSTRAP] += "\npub struct OccurrenceIdentity {\n    finding_id: String,\n}";
      }),
    ).toContain("local finding IDs belong only in instance counting");
  });

  it("fails when a passing check becomes an occurrence", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          `         WHERE run.status = 'complete'
           AND run.source = 'code_scan'
           AND finding.verdict IN ('fail', 'warn')",
    )?;
    Ok(None)`,
          `         WHERE run.status = 'complete'",
    )?;
    Ok(None)`,
        );
      }),
    ).toContain("only actionable findings");
  });

  it("fails when an unfinished run becomes evidence", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replaceAll("run.status = 'complete'\n", "1 = 1\n");
      }),
    ).toContain("only complete runs");
  });

  it("fails when the last-known set is one page run rather than the scan", () => {
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "ORDER BY started_at DESC, execution_id DESC",
          "ORDER BY started_at DESC, run_id DESC",
        );
      }),
    ).toContain("newest EXECUTION");
  });

  it("fails when legacy web evidence enters the local projection", () => {
    // A desktop-era web finding can be submitted from the local database.
    expect(
      failures((files) => {
        files[BOOTSTRAP] = files[BOOTSTRAP].replace(
          "AND resolved_at IS NULL AND source = 'code_scan'",
          "AND resolved_at IS NULL",
        );
      }),
    ).toContain("must derive local evidence and groups from code scans only");
  });
});

describe("the sweep", () => {
  it("fails when a second derivation appears elsewhere", () => {
    expect(failures((files) => (files[OTHER] = "fn derive_bootstrap_set() {}"))).toContain(
      "second bootstrap derivation",
    );
  });

  it("allows a test module to drive the derivation", () => {
    expect(failures((files) => (files[OTHER_TESTS] = "fn derive_bootstrap_set() {}"))).toBe("");
  });

  it("fails when the CI path derives a bootstrap set", () => {
    expect(failures((files) => (files[CLI] = "fn go() { db.derive_bootstrap_set(); }"))).toContain(
      "no lifecycle store to bootstrap from",
    );
  });

  it("fails when the CLI enumeration finds nothing", () => {
    expect(
      failures((files) => {
        delete files[CLI];
        delete files[CLI_BINARY];
      }),
    ).toContain("found no CLI sources");
  });

  it("fails when the Rust enumeration breaks", () => {
    expect(
      failures((files) => {
        for (const file of Object.keys(files)) {
          if (file.includes("filler_")) delete files[file];
        }
      }),
    ).toContain("enumeration broke");
  });
});
