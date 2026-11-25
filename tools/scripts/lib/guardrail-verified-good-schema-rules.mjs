const MIGRATION = "apps/desktop/src-tauri/src/db/migrations/018_verified_good_profile.sql";
export function verifiedGoodSchemaFailures(read) {
  const failures = [];
  const migration = read(MIGRATION);
  if (!/drift_value_json/.test(migration) || !/good_value_json/.test(migration)) {
    failures.push(
      `${MIGRATION} must store the good value and the differing value in separate columns. One column would destroy the comparison the row exists to make.`,
    );
  }

  return failures;
}
