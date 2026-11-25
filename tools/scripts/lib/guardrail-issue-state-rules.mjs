// Only observed absence may later become a regression.
const BASELINE_SQL = "apps/desktop/src-tauri/src/db/migrations/001_baseline.sql";
const ISSUE_STATES_RS = "apps/desktop/src-tauri/src/db/issue_states.rs";
const PROVENANCE_MIGRATION =
  "apps/desktop/src-tauri/src/db/migrations/020_verification_provenance.sql";
const VOCAB_RS = "apps/desktop/src-tauri/crates/protocol/src/vocab.rs";
const SCAN_PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";

function functionBody(source, name) {
  const start = source.search(new RegExp(`fn ${name}\\b`));
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

export function verificationProvenanceFailures(read, exists) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };

  const vocab = exists(VOCAB_RS) ? read(VOCAB_RS) : "";
  check(
    /pub enum VerifiedBy/.test(vocab) && /pub fn proves_absence/.test(vocab),
    `${VOCAB_RS} must define VerifiedBy with proves_absence: whether a verification observed the issue was gone is the one question the regression path asks, and the desktop, the CLI, and the connected producer must ask it of the same definition.`,
  );

  const migration = exists(PROVENANCE_MIGRATION) ? read(PROVENANCE_MIGRATION) : "";
  check(
    /\(status = 'verified'\) = \(verified_by IS NOT NULL\)/.test(migration),
    `${PROVENANCE_MIGRATION} must keep the CHECK tying provenance to status in BOTH directions. Without it a verified row can exist with nobody attesting to it, and a stale prover can outlive the verification it described.`,
  );

  check(
    exists(BASELINE_SQL) && !read(BASELINE_SQL).includes("project_work_items"),
    `${BASELINE_SQL} must not recreate project_work_items.`,
  );

  const store = exists(ISSUE_STATES_RS) ? read(ISSUE_STATES_RS) : "";
  const reconciler = functionBody(store, "reconcile_reobserved_lifecycle");
  check(
    reconciler !== null && reconciler.includes("proves_absence()"),
    `${ISSUE_STATES_RS} must decide a re-observed verification's next state from proves_absence(). Branching on the status alone reports a claimed fix that was never real as a regression.`,
  );
  check(
    reconciler !== null && /verified_by = NULL/.test(reconciler),
    `${ISSUE_STATES_RS} re-observation must clear verified_by with the status; the schema CHECK rejects the row otherwise, and a leftover prover would describe a verification that no longer holds.`,
  );
  const projection = exists(SCAN_PROJECTION) ? read(SCAN_PROJECTION) : "";
  check(
    projection.includes("reconcile_reobserved_lifecycle"),
    `${SCAN_PROJECTION} must call the shared reconcile_reobserved_lifecycle.`,
  );
  check(
    !/IssueStatus::Regressed/.test(projection),
    `${SCAN_PROJECTION} must not write the regressed status itself. Regression is decided once, from the verification's provenance, in ${ISSUE_STATES_RS}.`,
  );

  return failures;
}
