const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/022_connected_mutation_outbox.sql";
// Site bindings must never persist credentials from the OS keychain.
const CREDENTIAL_WORDS = ["token", "secret", "password", "credential"];

// Test modules may drive the retained schema directly.
function isProdRustFile(file) {
  if (/[/\\]tests[/\\]/.test(file)) return false;
  return !/(_tests?\.rs|^tests\.rs)$/.test(file.split(/[/\\]/).pop());
}

/**
 * @param {(file: string) => string} read
 * @param {(file: string) => boolean} exists
 * @param {(dir: string, predicate: (file: string) => boolean) => string[]} listFiles
 */
export function connectedOutboxFailures(read, exists, listFiles, extraRoots = []) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };

  const migration = exists(MIGRATION) ? read(MIGRATION) : "";
  check(
    /CREATE TABLE IF NOT EXISTS connected_sites\b/.test(migration) &&
      /PRIMARY KEY \(project_id, env_url\)/.test(migration),
    `${MIGRATION} must bind a project environment to one connected site. Without the binding nothing can answer whether a decision is owed to anyone, or whether bootstrap has committed.`,
  );
  // Columns only: the header prose says where the credential does live.
  const columns = migration.replace(/^\s*--.*$/gm, "");
  for (const word of CREDENTIAL_WORDS) {
    check(
      !new RegExp(word, "i").test(columns),
      `${MIGRATION} mentions ${word}: the site binding must hold no credential. The installation token belongs in the OS keychain, not in a row that every backup of the scan history copies.`,
    );
  }
  check(
    /CREATE TABLE IF NOT EXISTS connected_group_revisions\b/.test(migration),
    `${MIGRATION} must store the group revisions this installation has pulled: they are the picture a decision is guarded against, and they cannot be recovered after the decision is made.`,
  );
  check(
    /CREATE TABLE IF NOT EXISTS connected_mutation_outbox\b/.test(migration) &&
      /UNIQUE \(project_id, env_url, check_id\)/.test(migration),
    `${MIGRATION} must keep one pending decision per group. Two entries guarding the same revision ask the service to apply one group twice inside a single atomic batch.`,
  );
  check(
    /idempotency_key TEXT NOT NULL UNIQUE/.test(migration),
    `${MIGRATION} must pre-assign a unique idempotency key per recorded decision, so a crash between sending and hearing back resubmits the same request instead of a second one that reads as a new decision.`,
  );
  check(
    (migration.match(/REFERENCES connected_sites\(project_id, env_url\) ON DELETE CASCADE/g) || [])
      .length >= 2,
    `${MIGRATION} must scope pulled revisions and undelivered intent to the binding they were recorded under: kept past a disconnect, they would guard a mutation with a revision from a stream this installation never pulled.`,
  );
  check(
    /\(decision = 'snooze'\) = \(snooze_until IS NOT NULL\)/.test(migration),
    `${MIGRATION} must tie a recorded decision to the payload only that decision carries, the way the lifecycle table ties provenance to status: a snooze with no deadline is a dismissal that never expires.`,
  );

  const rustFiles = ["apps/desktop/src-tauri/src", ...extraRoots].flatMap((dir) =>
    listFiles(dir, (file) => file.endsWith(".rs")),
  );
  check(
    rustFiles.length > 100,
    `connected-outbox guardrail scanned only ${rustFiles.length} Rust files; the enumeration broke. Update guardrail-connected-outbox-rules.mjs.`,
  );
  for (const file of rustFiles) {
    if (!isProdRustFile(file)) continue;
    check(
      !read(file).includes("INSERT INTO connected_mutation_outbox"),
      `${file} writes the outbox directly. The CLI runtime must not record local intent.`,
    );
  }
  const ciFiles = [
    ...listFiles("apps/desktop/src-tauri/src/cli", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/crates/cli/src", (file) => file.endsWith(".rs")),
  ];
  check(
    ciFiles.length > 0,
    "connected-outbox guardrail found no CLI sources; update guardrail-connected-outbox-rules.mjs.",
  );
  for (const file of ciFiles) {
    check(
      !read(file).includes("record_group_decision"),
      `${file} records a lifecycle decision: a CI submission cannot touch groups, and a checkout has no user whose decision it would be.`,
    );
  }

  return failures;
}
