#!/usr/bin/env node
import { spawnSync } from "node:child_process";

// Accepted advisories require a reason and a recent manual review date.
const REVIEW_WARN_DAYS = 120;
const ALLOWED_WARNING_ADVISORIES = new Map([
  ...["RUSTSEC-2026-0370", "RUSTSEC-2026-0371", "RUSTSEC-2026-0372"].map((id) => [
    id,
    {
      reason:
        "zbus 5's zvariant, zbus_names and zvariant_derive are pulled transitively through tauri-plugin-notification (notify-rust) and tauri-plugin-single-instance for Linux D-Bus; they merged into zbus 6.0, and no release of those plugins uses it yet.",
      reviewedAt: "2026-10-18",
    },
  ]),
]);

// Vulnerability exceptions require no reachable fix and no untrusted-input path.
const ALLOWED_VULNERABILITY_ADVISORIES = new Map();

const tree = spawnSync(
  "cargo",
  [
    "tree",
    "--manifest-path",
    "apps/desktop/src-tauri/Cargo.toml",
    "--locked",
    "--workspace",
    "--all-features",
    "--target",
    "all",
    "--edges",
    "normal,build,dev",
    "--prefix",
    "none",
    "--format",
    "{p}",
    "--color",
    "never",
  ],
  { cwd: new URL("../..", import.meta.url), encoding: "utf8" },
);
if (tree.status !== 0 || !tree.stdout?.trim()) {
  console.error("Cannot verify the Rust workspace dependency graph for RUSTSEC-2026-0543.");
  if (tree.error) console.error(tree.error.message);
  if (tree.stderr) process.stderr.write(tree.stderr);
  process.exit(1);
}
if (/^chrono v/m.test(tree.stdout)) {
  console.error("RUSTSEC-2026-0543: chrono is active in the Rust workspace dependency graph.");
  process.exit(1);
}

const result = spawnSync(
  "cargo",
  [
    "audit",
    "--file",
    "apps/desktop/src-tauri/Cargo.lock",
    "--format",
    "json",
    ...(process.env.SITECMD_RUST_AUDIT_FETCH === "1" ? [] : ["--no-fetch", "--stale"]),
  ],
  {
    cwd: new URL("../..", import.meta.url),
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 20,
  },
);

let report;
try {
  report = result.stdout ? JSON.parse(result.stdout) : null;
} catch {
  report = null;
}

if (!report) {
  process.stderr.write(result.stderr);
  process.stderr.write(result.stdout);
  process.stderr.write("Unable to parse cargo audit JSON output.\n");
  process.exit(result.status || 1);
}

const vulnerabilities = report.vulnerabilities?.list ?? [];
const warnings = Object.values(report.warnings ?? {}).flat();
const observedAllowedWarningIds = new Set();
const unexpectedWarnings = [];

for (const warning of warnings) {
  const id = warning?.advisory?.id;
  if (ALLOWED_WARNING_ADVISORIES.has(id)) {
    observedAllowedWarningIds.add(id);
  } else {
    unexpectedWarnings.push(warning);
  }
}

const staleAllowedWarningIds = [...ALLOWED_WARNING_ADVISORIES.keys()].filter(
  (id) => !observedAllowedWarningIds.has(id),
);

const observedAllowedVulnerabilityIds = new Set();
const unexpectedVulnerabilities = [];

for (const finding of vulnerabilities) {
  const id = finding?.advisory?.id;
  if (ALLOWED_VULNERABILITY_ADVISORIES.has(id)) {
    observedAllowedVulnerabilityIds.add(id);
  } else {
    unexpectedVulnerabilities.push(finding);
  }
}

const staleAllowedVulnerabilityIds = [...ALLOWED_VULNERABILITY_ADVISORIES.keys()].filter(
  (id) => !observedAllowedVulnerabilityIds.has(id),
);

if (
  unexpectedVulnerabilities.length > 0 ||
  unexpectedWarnings.length > 0 ||
  staleAllowedWarningIds.length > 0 ||
  staleAllowedVulnerabilityIds.length > 0
) {
  if (unexpectedVulnerabilities.length > 0) {
    console.error("Rust dependency vulnerabilities found:");
    for (const finding of unexpectedVulnerabilities) {
      console.error(
        `- ${finding.advisory.id} ${finding.package.name}@${finding.package.version}: ${finding.advisory.title}`,
      );
    }
  }

  if (staleAllowedVulnerabilityIds.length > 0) {
    console.error(
      "Rust dependency vulnerability allowlist has stale entries (advisory no longer reported; remove the acceptance):",
    );
    for (const id of staleAllowedVulnerabilityIds) {
      const entry = ALLOWED_VULNERABILITY_ADVISORIES.get(id);
      console.error(`- ${id}: ${entry.reason}`);
    }
  }

  if (unexpectedWarnings.length > 0) {
    console.error("Unexpected Rust dependency advisory warnings found:");
    for (const finding of unexpectedWarnings) {
      console.error(
        `- ${finding.advisory.id} ${finding.package.name}@${finding.package.version}: ${finding.advisory.title}`,
      );
    }
  }

  if (staleAllowedWarningIds.length > 0) {
    console.error("Rust dependency warning allowlist has stale entries:");
    for (const id of staleAllowedWarningIds) {
      const entry = ALLOWED_WARNING_ADVISORIES.get(id);
      console.error(`- ${id}: ${entry.reason}`);
    }
  }

  process.exit(1);
}

// Warn, without failing, when an advisory exception needs manual review.
const today = new Date();
const staleByReview = [];
for (const [id, entry] of [...ALLOWED_WARNING_ADVISORIES, ...ALLOWED_VULNERABILITY_ADVISORIES]) {
  const reviewed = new Date(entry.reviewedAt);
  if (Number.isNaN(reviewed.getTime())) {
    console.error(`::error::audit-rust-deps: ${id} has an invalid reviewedAt: ${entry.reviewedAt}`);
    process.exit(1);
  }
  const ageDays = Math.floor((today.getTime() - reviewed.getTime()) / (1000 * 60 * 60 * 24));
  if (ageDays > REVIEW_WARN_DAYS) {
    staleByReview.push({ id, ageDays });
  }
}
for (const { id, ageDays } of staleByReview) {
  console.warn(
    `::warning::audit-rust-deps: ${id} was last reviewed ${ageDays} days ago (threshold ${REVIEW_WARN_DAYS}). Check whether upstream now has a fix, then update reviewedAt in tools/scripts/audit-rust-deps.mjs.`,
  );
}

console.log(
  `Rust dependency audit passed: 0 unexpected vulnerabilities (${observedAllowedVulnerabilityIds.size} documented acceptances), ${observedAllowedWarningIds.size} documented transitive warnings${staleByReview.length > 0 ? `, ${staleByReview.length} due for re-review` : ""}.`,
);
