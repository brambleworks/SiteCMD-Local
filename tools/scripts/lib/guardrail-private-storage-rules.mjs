export function privateStorageSafetyFailures(read) {
  const appIdentity = read("apps/desktop/src-tauri/src/app_identity.rs");
  const auditLog = read("apps/desktop/src-tauri/src/audit_log.rs");
  const failures = [];

  if (
    !appIdentity.includes("ensure_private_directory") ||
    !appIdentity.includes("from_mode(0o700)") ||
    !appIdentity.includes("from_mode(0o600)") ||
    !appIdentity.includes("custom_flags(libc::O_NOFOLLOW)") ||
    !auditLog.includes("ensure_private_directory(parent)") ||
    !auditLog.includes("custom_flags(libc::O_NOFOLLOW)") ||
    !auditLog.includes("restrict_open_private_file(&file)")
  ) {
    failures.push(
      "CLI private state must keep app-data and log directories owner-only, keep database/audit/debug-secret files owner-only, and refuse symlink file writes.",
    );
  }

  return failures;
}
