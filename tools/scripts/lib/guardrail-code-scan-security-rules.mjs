export function codeScanSecurityFailures(read) {
  const failures = [];
  const issueTypes = read("apps/desktop/src-tauri/crates/protocol/src/code_scan.rs");
  const databaseTargets = read("apps/desktop/src-tauri/src/core/database_targets.rs");
  const databaseDiscovery = read("apps/desktop/src-tauri/src/core/database_targets/discovery.rs");
  const scopeTests = read("apps/desktop/src-tauri/src/core/project_listing_tests.rs");
  const protocol = read("apps/desktop/src-tauri/crates/protocol/src/engine_abi/mod.rs");
  const sessionHost = read("apps/desktop/src-tauri/src/core/audit/session_host.rs");
  const sessionTests = read("apps/desktop/src-tauri/src/core/audit/session_host/tests.rs");
  const listing = read("apps/desktop/src-tauri/src/core/project_listing.rs");
  const networkPolicy =
    read("apps/desktop/src-tauri/src/network_policy.rs") +
    read("apps/desktop/src-tauri/src/network_policy_tests.rs");
  const dnsCache = read("apps/desktop/src-tauri/src/dns_cache.rs");
  const constants = read("apps/desktop/src-tauri/src/constants.rs");
  if (
    /\bsource_excerpt\b|\bsourceExcerpt\b|\bexcerpt_for_(?:config_)?line\b|\bexcerpt\s*:/.test(
      issueTypes,
    )
  ) {
    failures.push("Code Scan outputs must omit source excerpts and code lines.");
  }
  if (!(
    databaseTargets.includes("bound_local_sqlite_path") &&
    databaseTargets.includes("canonicalize_local_sqlite_path") &&
    databaseDiscovery.includes("canonicalize_local_sqlite_path(&path") &&
    databaseTargets.includes("security_regression_rejects_absolute_sqlite_paths_outside_project") &&
    databaseTargets.includes("security_regression_rejects_sqlite_symlinks_that_escape_project")
  )) {
    failures.push(
      "Code Scan local SQLite inspection must stay bounded to the linked project/env directory and reject symlink escapes.",
    );
  }
  if (!(
    protocol.includes("pub const AUDIT_MAX_FILES: usize = 5_000;") &&
    protocol.includes("pub const AUDIT_MAX_FILE_BYTES: u64 = 1_000_000;") &&
    sessionHost.includes("ReadBudget::new(CODE_SCAN_MAX_TEXT_BYTES, AUDIT_MAX_FILE_BYTES)") &&
    listing.includes("list_project_with_limits(root, MAX_PROJECT_FILES, MAX_PROJECT_DEPTH)") &&
    listing.includes("if depth > self.max_depth") &&
    listing.includes("if self.files.len() >= self.max_files") &&
    constants.includes("pub const CODE_SCAN_MAX_TEXT_BYTES: u64 = 64_000_000;") &&
    scopeTests.includes("fn project_listing_rejects_a_second_file_over_its_budget()") &&
    sessionTests.includes("fn host_text_budget_is_shared_across_rounds()")
  )) {
    failures.push(
      "Code Scan filesystem collection must keep file-count, total-byte, and depth budgets with regression tests.",
    );
  }
  if (!(
    networkPolicy.includes("validate_resolved_domain_ip_target(domain, addr.ip(), policy)?") &&
    networkPolicy.includes(
      "security_regression_domain_resolution_rejects_loopback_under_scan_policy",
    )
  )) {
    failures.push(
      "Scan URL DNS validation must reject non-localhost domains that resolve to loopback addresses.",
    );
  }
  if (!(
    dnsCache.includes("validate_resolved_addrs(&host, &addrs, policy)?") &&
    dnsCache.includes("security_regression_cached_public_host_cannot_rebind_to_loopback") &&
    dnsCache.includes(".max_capacity(max_entries)") &&
    dnsCache.includes(".time_to_live(ttl)") &&
    dnsCache.includes("crate::constants::DNS_CACHE_TTL") &&
    constants.includes("pub const DNS_CACHE_TTL: Duration") &&
    dnsCache.includes("cache_evicts_by_capacity_and_ttl")
  )) {
    failures.push(
      "HTTP DNS resolution must re-check cached and fresh answers against the shared scan URL policy and keep a bounded TTL cache.",
    );
  }
  return failures;
}
