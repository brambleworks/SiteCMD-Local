import { describe, expect, it } from "vitest";
import { submissionOrderingFailures } from "./lib/guardrail-submission-ordering-rules.mjs";

const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/021_submission_ordering.sql";
const STORE = "apps/desktop/src-tauri/src/db/connected_producer.rs";
const EXECUTIONS = "apps/desktop/src-tauri/src/db/scan_executions.rs";
const RUNS = "apps/desktop/src-tauri/src/db/scan_runs.rs";
const HELPERS = "apps/desktop/src-tauri/src/db/helpers.rs";
const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";
const CLI = "apps/desktop/src-tauri/src/cli/scan.rs";
const CLI_BINARY = "apps/desktop/src-tauri/crates/cli/src/main.rs";

function sources() {
  return {
    [MIGRATION]: `CREATE TABLE IF NOT EXISTS connected_producer (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    installation_id TEXT NOT NULL,
    submission_sequence INTEGER NOT NULL,
    minted_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connected_site_watermarks (
    project_id INTEGER NOT NULL,
    env_url TEXT NOT NULL,
    event_sequence INTEGER NOT NULL,
    pulled_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, env_url)
);
ALTER TABLE scan_executions ADD COLUMN based_on_event_sequence INTEGER NOT NULL DEFAULT 0;`,
    [STORE]: `pub(super) fn site_event_watermark(conn: &Connection) -> Result<i64, DbError> {
    Ok(conn.query_row("SELECT event_sequence", [], |row| row.get(0)).optional()?.unwrap_or(0))
}`,
    [EXECUTIONS]: `let based_on_event_sequence = super::connected_producer::site_event_watermark(&tx)?;
tx.execute(
    "INSERT INTO scan_executions (started_at, based_on_event_sequence)
     VALUES (:started_at, :based_on_event_sequence)",
    named_params! { ":based_on_event_sequence": based_on_event_sequence },
)?;`,
    [RUNS]: `tx.execute("INSERT INTO scan_runs (engine_release) VALUES (?1)", params![stamp])?;`,
    [HELPERS]: `pub(crate) fn lifecycle_env_url(environment_scope_key: &str) -> String {
    if environment_scope_key.starts_with("project:") {
        environment_scope_key.to_string()
    } else {
        normalize_url(environment_scope_key).0
    }
}`,
    [PROJECTION]: `let environment_url = lifecycle_env_url(&batch.environment_scope_key);`,
    [CLI]: `pub fn run_scan() {}`,
    [CLI_BINARY]: `fn main() {}`,
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
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
  return submissionOrderingFailures(read, exists, listFiles).join("\n");
}

describe("the schema", () => {
  it("passes when every rule holds", () => {
    expect(failures()).toBe("");
  });

  it("fails when the migration is gone", () => {
    expect(failures((files) => delete files[MIGRATION])).toContain("one single-row table");
  });

  it("fails when a second installation identity becomes representable", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace("CHECK (id = 1)", "");
      }),
    ).toContain("one single-row table");
  });

  it("fails when the per-site watermark table is missing", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "CREATE TABLE IF NOT EXISTS connected_site_watermarks",
          "CREATE TABLE IF NOT EXISTS something_else",
        );
      }),
    ).toContain("connected_site_watermarks");
  });

  it("fails when the basis is stamped on the run instead of the execution", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "ALTER TABLE scan_executions ADD COLUMN based_on_event_sequence",
          "ALTER TABLE scan_runs ADD COLUMN based_on_event_sequence",
        );
      }),
    ).toContain("starts looking");
  });
});

describe("allocating a submission number", () => {
  it("fails when the identity is keyed to a credential", () => {
    expect(
      failures((files) => {
        files[STORE] += `\nlet id = keyring::get_license_key(app)?;`;
      }),
    ).toContain("license_key");
  });
});

describe("the declared basis", () => {
  it("fails when an absent watermark reads as something other than genesis", () => {
    expect(
      failures((files) => {
        files[STORE] = files[STORE].replace("unwrap_or(0)", "unwrap_or(i64::MAX)");
      }),
    ).toContain("genesis value 0");
  });

  it("fails when the execution's basis is rewritten after creation", () => {
    expect(
      failures((files) => {
        files[EXECUTIONS] +=
          `\ntx.execute("UPDATE scan_executions SET based_on_event_sequence = ?1", [])?;`;
      }),
    ).toContain("never update it afterwards");
  });

  it("fails when the basis is captured at run persistence instead", () => {
    expect(
      failures((files) => {
        files[RUNS] += `\nlet basis: i64 = read_watermark(&tx, based_on_event_sequence)?;`;
      }),
    ).toContain("inherit their execution's stamp");
  });
});

describe("one site key", () => {
  it("fails when the shared environment-key derivation is gone", () => {
    expect(
      failures((files) => {
        files[HELPERS] = files[HELPERS].replace("lifecycle_env_url", "some_other_name");
      }),
    ).toContain("single (project_id, env_url) derivation");
  });

  it("fails when a caller re-derives the key itself", () => {
    expect(
      failures((files) => {
        files[PROJECTION] =
          `let env = if key.starts_with("project:") { key } else { normalize(key) };`;
      }),
    ).toContain("re-derives");
  });
});

describe("CI carries no sequence", () => {
  it("fails when the CLI path allocates one", () => {
    expect(
      failures((files) => {
        files[CLI] = `let ticket = db.allocate_submission_sequence(now)?;`;
      }),
    ).toContain("concurrent and disposable");
  });

  it("allows tests to seed an existing desktop producer sequence", () => {
    expect(
      failures((files) => {
        files[CLI] =
          `fn run() {}\n#[cfg(test)]\nmod tests { fn seed(db: Db) { db.allocate_submission_sequence(1); } }`;
      }),
    ).toBe("");
  });

  it("fails when the CLI enumeration finds nothing", () => {
    expect(
      failures((files) => {
        delete files[CLI];
        delete files[CLI_BINARY];
      }),
    ).toContain("found no CLI sources");
  });
});
