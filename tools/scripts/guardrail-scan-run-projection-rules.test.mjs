// Run reconciliation can resolve findings without a successful project-wide coverage claim.
import { describe, expect, it } from "vitest";
import { scanRunProjectionFailures } from "./lib/guardrail-unified-scan-rules.mjs";

const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";
const CODE_NORMALIZATION = "apps/desktop/src-tauri/src/core/normalized_scan/code.rs";
const HEALTHY = {
  [PROJECTION]: `
fn resolve_covered_absences(tx: &Transaction<'_>) -> Result<(), DbError> {
    if !batch.coverage.successful {
        return Ok(());
    }
    let resolved = load_open_candidates(tx, &scope)?
        .filter(|row| sitecmd_protocol::coverage::covers(&batch.coverage, None, &candidate.check_id, exact_claim_key));
    Ok(())
}

fn load_open_candidates(tx: &Transaction<'_>) -> Result<Vec<OpenCandidate>, DbError> {
    tx.prepare("SELECT id, signal_id, check_id FROM work_items")?
}
`,
  [CODE_NORMALIZATION]: `
fn normalize_code_scan_with_inventory() -> Result<NormalizedRunBatch, String> {
    Ok(NormalizedRunBatch {
        coverage: ScanCoverageManifest::declared(ScanCoverageKind::Project, Vec::new(), checks),
    })
}
`,
};

function failuresWith(overrides = {}) {
  const files = { ...HEALTHY, ...overrides };
  return scanRunProjectionFailures((file) => {
    if (!(file in files)) throw new Error(`unexpected read: ${file}`);
    return files[file];
  });
}

describe("scan run projection", () => {
  it("accepts a project-wide exact coverage projection", () => {
    // Bug: A valid coverage claim could be rejected by an overly narrow check.
    expect(failuresWith()).toEqual([]);
  });

  it("fails when the projection stops asking the coverage manifest", () => {
    // Bug: A route match alone could resolve a finding for a check the run did not cover.
    const reimplemented = HEALTHY[PROJECTION].replace(
      "sitecmd_protocol::coverage::covers(&batch.coverage, None, &candidate.check_id, exact_claim_key)",
      "batch.coverage.checks.contains(&candidate.check_id)",
    );
    expect(failuresWith({ [PROJECTION]: reimplemented }).join(" ")).toContain(
      "must ask the coverage manifest whether the run proved the pair",
    );
  });

  it("fails when the projection widens an exact check claim", () => {
    // A family claim can resolve a code finding without covering that exact check.
    const widened = HEALTHY[PROJECTION].replace("exact_claim_key)", "family_claim_key)");
    expect(failuresWith({ [PROJECTION]: widened }).join(" ")).toContain(
      "must ask the coverage manifest whether the run proved the pair",
    );
  });

  it("fails when the projection resolves from an unsuccessful run", () => {
    // Bug: An unsuccessful run could resolve findings it failed to check.
    const lenient = HEALTHY[PROJECTION].replace("if !batch.coverage.successful", "if false");
    expect(failuresWith({ [PROJECTION]: lenient }).join(" ")).toContain(
      "must refuse to resolve anything from an unsuccessful run",
    );
  });

  it("fails when per-kind SQL filtering comes back", () => {
    // Bug: Per-kind SQL filtering could diverge from the coverage manifest's rules.
    const flat = HEALTHY[PROJECTION].replace(
      "let resolved =",
      "let limit_pages = matches!(batch.coverage.kind, ScanCoverageKind::Page); let resolved =",
    );
    expect(failuresWith({ [PROJECTION]: flat }).join(" ")).toContain(
      "still switches on limit_pages",
    );
  });

  it("fails when the candidate query is inlined back into the resolver", () => {
    // An inline query could bypass the shared scope of resolution candidates.
    const inlined = HEALTHY[PROJECTION].replace(
      "load_open_candidates(tx, &scope)?",
      'tx.prepare("SELECT id, signal_id, check_id FROM work_items")?',
    );
    expect(failuresWith({ [PROJECTION]: inlined }).join(" ")).toContain(
      "must read its candidates through load_open_candidates",
    );
  });

  it("fails when code coverage declares a page scope or includes routes", () => {
    // A code run with route-scoped coverage can miss findings elsewhere in the project.
    for (const claim of [
      "ScanCoverageKind::Page, Vec::new()",
      "ScanCoverageKind::Project, routes",
    ]) {
      const routed = HEALTHY[CODE_NORMALIZATION].replace(
        "ScanCoverageKind::Project, Vec::new()",
        claim,
      );
      expect(failuresWith({ [CODE_NORMALIZATION]: routed }).join(" ")).toContain(
        "must declare project-wide coverage without page URLs",
      );
    }
  });

  it("fails when the projection filters candidates by page URL", () => {
    // A page URL filter can hide open findings from a code run.
    const filtered = HEALTHY[PROJECTION].replace(
      "FROM work_items",
      "FROM work_items WHERE page_url IS NULL",
    );
    expect(failuresWith({ [PROJECTION]: filtered }).join(" ")).toContain(
      "must load code candidates without a route filter",
    );
  });

  it("fails when the projection passes a route to the coverage check", () => {
    // Passing a route makes the resolution check depend on web scope.
    const routed = HEALTHY[PROJECTION].replace("None, &candidate", "route.as_deref(), &candidate");
    expect(failuresWith({ [PROJECTION]: routed }).join(" ")).toContain(
      "must ask the coverage manifest whether the run proved the pair",
    );
  });
});
