const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/021_submission_ordering.sql";
const STORE = "apps/desktop/src-tauri/src/db/connected_producer.rs";
const EXECUTIONS = "apps/desktop/src-tauri/src/db/scan_executions.rs";
const RUNS = "apps/desktop/src-tauri/src/db/scan_runs.rs";
const HELPERS = "apps/desktop/src-tauri/src/db/helpers.rs";
const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";

// Submission identity must survive credential rotation.
const CREDENTIAL_SYMBOLS = ["license_key", "catalog_token", "instance_id", "activation"];

/**
 * @param {(file: string) => string} read
 * @param {(file: string) => boolean} exists
 * @param {(dir: string, predicate: (file: string) => boolean) => string[]} listFiles
 */
export function submissionOrderingFailures(read, exists, listFiles) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const source = (file) => (exists(file) ? read(file) : "");

  const migration = source(MIGRATION);
  check(
    /CREATE TABLE IF NOT EXISTS connected_producer\b/.test(migration) &&
      /CHECK \(id = 1\)/.test(migration) &&
      /installation_id/.test(migration) &&
      /submission_sequence/.test(migration),
    `${MIGRATION} must keep one installation identity and its submission counter in one single-row table: a counter without the identity that scopes it orders nothing, and two rows would be two namespaces for one producer.`,
  );
  check(
    /CREATE TABLE IF NOT EXISTS connected_site_watermarks\b/.test(migration),
    `${MIGRATION} must create connected_site_watermarks: the per-site event sequence this installation last pulled is what every snapshot declares as its basis.`,
  );
  check(
    /ALTER TABLE scan_executions ADD COLUMN based_on_event_sequence/.test(migration),
    `${MIGRATION} must stamp the basis on scan_executions, the row written when the scan starts looking.`,
  );

  const store = source(STORE);
  for (const symbol of CREDENTIAL_SYMBOLS) {
    check(
      !store.includes(symbol),
      `${STORE} references ${symbol}: the installation identity must not be derived from or stored with a credential, because token rotation has to continue the same counter rather than restart the namespace.`,
    );
  }
  check(
    /fn site_event_watermark/.test(store) && /unwrap_or\(0\)/.test(store),
    `${STORE} must read an absent watermark as the genesis value 0, the protocol's answer for a site whose bootstrap precedes every event it will have.`,
  );

  const executions = source(EXECUTIONS);
  check(
    /site_event_watermark\(/.test(executions) &&
      /:based_on_event_sequence/.test(executions) &&
      !/SET[\s\S]{0,200}based_on_event_sequence/.test(executions),
    `${EXECUTIONS} must capture the basis once, when the execution is created, and never update it afterwards: a basis written later describes what the producer learned during the scan, not before it.`,
  );
  check(
    !source(RUNS).includes("based_on_event_sequence"),
    `${RUNS} must not read or write the basis: run rows are written when a collector finishes, so a pull that landed mid-scan would raise the declared basis of evidence gathered before it. Runs inherit their execution's stamp by join.`,
  );

  check(
    /pub\(crate\) fn lifecycle_env_url/.test(source(HELPERS)),
    `${HELPERS} must own the single (project_id, env_url) derivation shared by the lifecycle overlay and the connected watermark; two derivations is how they start describing two different sites.`,
  );
  for (const file of [PROJECTION, STORE]) {
    check(
      !/starts_with\("project:"\)/.test(source(file)),
      `${file} re-derives the lifecycle environment key; call helpers::lifecycle_env_url instead.`,
    );
  }

  // Disposable CI runners have no durable counter, so CLI submissions must not
  // allocate a sequence.
  const cliFiles = [
    ...listFiles("apps/desktop/src-tauri/src/cli", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/crates/cli/src", (file) => file.endsWith(".rs")),
  ];
  check(
    cliFiles.length > 0,
    "submission-ordering guardrail found no CLI sources; update guardrail-submission-ordering-rules.mjs.",
  );
  for (const file of cliFiles) {
    const productionSource = read(file).split("#[cfg(test)]", 1)[0];
    check(
      !productionSource.includes("allocate_submission_sequence"),
      `${file} allocates a submission sequence: CI runs are concurrent and disposable with no persistent counter, so a CI submission is ordered by the deployment it embeds and carries no sequence.`,
    );
  }

  return failures;
}
