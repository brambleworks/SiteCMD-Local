// Dashboard-only setup must never be reintroduced on the client credential.
const CLIENT = "apps/desktop/src-tauri/src/connected_service.rs";
export function connectedSetupFailures(read) {
  const failures = [];
  for (const file of [CLIENT]) {
    const source = read(file);
    for (const name of [
      "create_connected_site",
      "create_site",
      "delete_site",
      "erase_site",
      "verify_site",
      "mint_ci_token",
      "put_scope",
      "mutate_group",
    ]) {
      if (new RegExp(`(?:pub(?:\\([^)]*\\))?\\s+)?(?:async\\s+)?fn\\s+${name}\\b`).test(source))
        failures.push(`${file}: dashboard-only ${name} must stay outside the CLI client`);
    }
  }
  return failures;
}
