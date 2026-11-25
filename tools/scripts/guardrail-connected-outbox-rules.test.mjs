import { describe, expect, it } from "vitest";
import { connectedOutboxFailures } from "./lib/guardrail-connected-outbox-rules.mjs";

const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/022_connected_mutation_outbox.sql";
const OTHER = "apps/desktop/src-tauri/src/background/sync.rs";
const OTHER_TESTS = "apps/desktop/src-tauri/src/db/migrations_tests.rs";
const CLI = "apps/desktop/src-tauri/src/cli/scan.rs";
const CLI_BINARY = "apps/desktop/src-tauri/crates/cli/src/main.rs";

function sources() {
  const files = {
    [MIGRATION]: `-- The installation token and every other credential live in the keychain.
CREATE TABLE IF NOT EXISTS connected_sites (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_url TEXT NOT NULL,
    site_id TEXT NOT NULL,
    connected_at INTEGER NOT NULL,
    bootstrapped_at INTEGER,
    PRIMARY KEY (project_id, env_url)
);
CREATE TABLE IF NOT EXISTS connected_group_revisions (
    project_id INTEGER NOT NULL,
    env_url TEXT NOT NULL,
    check_id TEXT NOT NULL,
    state_revision INTEGER NOT NULL,
    pulled_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, env_url, check_id),
    FOREIGN KEY (project_id, env_url)
        REFERENCES connected_sites(project_id, env_url) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS connected_mutation_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    env_url TEXT NOT NULL,
    check_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    snooze_until INTEGER,
    block_reason TEXT,
    based_on_revision INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    decided_at INTEGER NOT NULL,
    UNIQUE (project_id, env_url, check_id),
    CHECK ((decision = 'snooze') = (snooze_until IS NOT NULL)),
    FOREIGN KEY (project_id, env_url)
        REFERENCES connected_sites(project_id, env_url) ON DELETE CASCADE
);`,
    [OTHER]: `fn drain() {}`,
    [OTHER_TESTS]: `conn.execute("INSERT INTO connected_mutation_outbox (decision) VALUES ('ignore')", [])`,
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
  return connectedOutboxFailures(read, exists, listFiles).join("\n");
}

describe("the schema", () => {
  it("passes when every rule holds", () => {
    expect(failures()).toBe("");
  });

  it("fails when the site binding is gone", () => {
    expect(failures((files) => delete files[MIGRATION])).toContain("bind a project environment");
  });

  it("fails when the binding carries a credential", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "    site_id TEXT NOT NULL,",
          "    site_id TEXT NOT NULL,\n    installation_token TEXT NOT NULL,",
        );
      }),
    ).toContain("OS keychain");
  });

  it("fails when nothing records what was pulled about each group", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "CREATE TABLE IF NOT EXISTS connected_group_revisions",
          "CREATE TABLE IF NOT EXISTS something_else",
        );
      }),
    ).toContain("picture a decision is guarded against");
  });

  it("fails when a group can hold two pending decisions at once", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "    UNIQUE (project_id, env_url, check_id),\n",
          "",
        );
      }),
    ).toContain("one pending decision per group");
  });

  it("fails when the idempotency key is not unique", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "idempotency_key TEXT NOT NULL UNIQUE",
          "idempotency_key TEXT NOT NULL",
        );
      }),
    ).toContain("pre-assign a unique idempotency key");
  });

  it("fails when intent outlives the binding it was recorded under", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          `    FOREIGN KEY (project_id, env_url)
        REFERENCES connected_sites(project_id, env_url) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS connected_mutation_outbox`,
          `    FOREIGN KEY (project_id, env_url) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS connected_mutation_outbox`,
        );
      }),
    ).toContain("scope pulled revisions and undelivered intent");
  });

  it("fails when a recorded snooze can have no deadline", () => {
    expect(
      failures((files) => {
        files[MIGRATION] = files[MIGRATION].replace(
          "    CHECK ((decision = 'snooze') = (snooze_until IS NOT NULL)),\n",
          "",
        );
      }),
    ).toContain("payload only that decision carries");
  });
});

describe("retained outbox schema has no runtime writer", () => {
  it("fails when a runtime module writes the outbox directly", () => {
    expect(
      failures((files) => {
        files[OTHER] =
          `conn.execute("INSERT INTO connected_mutation_outbox (decision) VALUES (?1)", p)?;`;
      }),
    ).toContain("The CLI runtime must not record local intent");
  });

  it("allows tests to drive the schema directly", () => {
    expect(failures()).not.toContain("The CLI runtime must not record local intent");
  });

  it("fails when the sweep stops seeing the tree", () => {
    expect(
      failures((files) => {
        for (const file of Object.keys(files)) {
          if (file.includes("/filler_")) delete files[file];
        }
      }),
    ).toContain("the enumeration broke");
  });
});

describe("CI cannot decide a group lifecycle", () => {
  it("fails when the CI path decides a group's lifecycle", () => {
    expect(
      failures((files) => {
        files[CLI] = `db.record_group_decision(p, &env, &check, GroupDecision::Ignore, now)?;`;
      }),
    ).toContain("no user whose decision it would be");
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
