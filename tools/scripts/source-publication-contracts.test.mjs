const { test } = process.env.VITEST ? await import("vitest") : await import("node:test");
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const rust = "apps/desktop/src-tauri/";
const read = (path) => readFileSync(rust + path, "utf8");

// Bug M3: legacy artifact rejection invokes git and can expose its stderr.
test("non-marker artifacts are rejected without invoking a diff reader", () => {
  assert.doesNotMatch(read("src/cli/autofix/publish_job.rs"), /repo::patch_paths/);
  assert.doesNotMatch(read("src/cli/autofix/repo.rs"), /pub fn (apply_patch|patch_paths)/);
});

// Bug M4: run and publish can choose different targets and write sets.
test("run and regeneration use the same template planner", () => {
  assert.match(read("src/cli/autofix/run_job.rs"), /template_plan::plan_finding/);
  const planner = read("src/cli/autofix/template_plan.rs");
  assert.match(planner.split("fn plan_with_reads")[0], /plan_with_reads\(project, target, fixer,/);
  assert.match(planner.split("fn regenerate")[1], /plan_with_reads\(project, target, fixer,/);
  assert.match(planner, /fixes::request_with_file\(\s*Task::FixPlan/);
  assert.match(read("src/cli/autofix/publish_job.rs"), /template_plan::regenerate/);
  assert.doesNotMatch(read("src/cli/autofix/run_job.rs"), /fixer\.plan\(/);
});

// Both CLI output and the canary must use the format table owned by the enum.
test("the CLI canary and audit share the format table", () => {
  assert.match(read("src/cli/publication_tests.rs"), /CodeScanReportFormat::ALL/);
  assert.match(read("src/cli/audit.rs"), /CodeScanReportFormat::ALL/);
});

// Bug M6: digit-only canaries collide with timestamps and identifiers.
test("source canary markers cannot be a timestamp substring", () => {
  const markers = read("src/cli/publication_tests.rs").split("let markers = [")[1].split("];")[0];
  assert.doesNotMatch(markers, /"\d+"/);
});

// Bug M9: exact-line validation still describes an excerpt range.
test("brief validation describes exact lines", () => {
  assert.doesNotMatch(
    read("src/cli/autofix/brief_publish.rs"),
    /outside the brief's line range|brief's range only chose/,
  );
});

const rustCanaryCalls = [
  "fixture-evidence.txt",
  "audit_project(root.path())",
  "format_report(report,",
  "run_with_output(",
  "args.output = Some(",
  "std::fs::read_to_string(file)",
  '"reason": markers[0]',
  "fixes::one_fix_text(",
  "FixTextTarget::Code",
  "brief::brief_artifact(",
  "brief_publish::verify_brief(",
  "brief_publish::render_issue(",
  "exit_check::check_brief(",
  "exit_check::check_hosted_brief(",
  "artifact::write_artifact(",
  "std::fs::read_dir(dir.path())",
  'join("patch.diff")',
  "publish_job::pull_request_text(",
  "publish_job::manifest_matches_claim(",
  "publish_job::finding_reports(",
  "issue_fingerprint(",
  "connected::scan_this_checkout(",
  "connected::build_candidate_snapshot(",
  "serde_json::to_string(&snapshot)",
  "ci_submission_body(",
];

function assertRustPublicationCanary(source) {
  for (const required of rustCanaryCalls) {
    assert.ok(source.includes(required), `Rust publication canary must retain ${required}`);
  }
}

test("Rust source canary covers the public publication surfaces", () => {
  // Removing a canary surface can leave a source disclosure undetected.
  const source = read("src/cli/publication_tests.rs");
  assertRustPublicationCanary(source);
  for (const required of rustCanaryCalls) {
    const mutated = source.replaceAll(required, "removed_canary_contract");
    assert.throws(() => assertRustPublicationCanary(mutated), { name: "AssertionError" });
  }
});
