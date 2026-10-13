import { describe, expect, it } from "vitest";
import { coverageFailures } from "./lib/guardrail-coverage-rules.mjs";

const COVERAGE = "apps/desktop/src-tauri/crates/engine/src/coverage.rs";
const NORMALIZED = "apps/desktop/src-tauri/src/core/normalized_scan.rs";
const PROJECTION = "apps/desktop/src-tauri/src/db/scan_run_projection.rs";
const VERIFICATION = "apps/desktop/src-tauri/src/commands/scan/verification.rs";
const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";
const AXE = "apps/desktop/src-tauri/crates/engine/src/checks/accessibility/axe.rs";
const REGISTRY = "apps/desktop/src-tauri/src/core/code_scan/registry.rs";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";

const HEALTHY = {
  [COVERAGE]: `
static FAMILY_PREFIXES: LazyLock<Vec<&'static str>> = LazyLock::new(|| vec![]);

pub fn claim_key(check_id: &str) -> &str {
    FAMILY_PREFIXES.iter().max_by_key(|prefix| prefix.len()).copied().unwrap_or(check_id)
}

impl ScanCoverageManifest {
    pub fn derive(kind: ScanCoverageKind) -> Self {
        for outcome in outcomes {
            if outcome.status == CheckStatus::Skipped {
                skipped.entry(outcome.route).or_default().insert(outcome.check_id);
            }
        }
        if basis == (ClaimBasis::RouteSet { complete: false }) {
            exceptions.push(CoverageException {
                reason: CoverageExceptionReason::SessionIncomplete,
            });
        }
        Self { kind }
    }

    pub fn covers(&self, route: Option<&str>, check_id: &str) -> bool {
        if !self.successful || !self.claims_check(check_id) {
            return false;
        }
        !self.excepted_on(route, check_id)
    }
}
`,
  [NORMALIZED]: `
pub fn normalize_multi_page_parent() -> Result<NormalizedRunBatch, serde_json::Error> {
    batch.coverage = ScanCoverageManifest::derive(
        ScanCoverageKind::PageSet,
        covered_page_urls,
        &outcomes(&batch.findings, false),
        ClaimBasis::RouteSet { complete: successful_page_urls.len() == selected_page_count },
    );
    Ok(batch)
}

pub fn normalize_web_scan() -> Result<NormalizedRunBatch, serde_json::Error> {
    let coverage = ScanCoverageManifest::derive(
        ScanCoverageKind::Page,
        vec![result.url.clone()],
        &outcomes(&findings, true),
        ClaimBasis::PerRoute,
    );
    Ok(batch)
}

pub fn normalize_code_scan() -> Result<NormalizedRunBatch, serde_json::Error> {
    let coverage = ScanCoverageManifest::declared(
        ScanCoverageKind::Project,
        Vec::new(),
        crate::core::code_scan::registry::registered_code_check_ids().collect(),
    );
    Ok(batch)
}
`,
  [PROJECTION]: `
fn resolve_covered_absences(tx: &Transaction<'_>) -> Result<(), DbError> {
    if !batch.coverage.successful {
        return Ok(());
    }
    let coverage = as_stored_keys(&batch.coverage);
    let resolved = load_open_candidates(tx, &scope, &coverage)?
        .filter(|row| coverage.covers(route.as_deref(), check_id));
    Ok(())
}

fn as_stored_keys(coverage: &ScanCoverageManifest) -> ScanCoverageManifest {
    stored.page_urls = coverage.page_urls.iter().map(|url| normalize_url(url).0).collect();
    stored
}
`,
  [VERIFICATION]: `
pub(crate) async fn run_bounded_web_verification() -> Result<VerifyChecksResult, ScanError> {
    batch.coverage = ScanCoverageManifest::derive(
        ScanCoverageKind::CheckSet,
        vec![scan_result.url.clone()],
        &crate::core::normalized_scan::batch_outcomes(&batch),
        ClaimBasis::PerRoute,
    );
    Ok(result)
}
`,
  [SESSION]: `
pub const SESSION_CHECK_IDS: &[&str] = &[
    "seo.duplicate_title_across_pages",
    "seo.orphan_pages",
];

pub fn analyze_session(pages: &[PageSignals]) -> Vec<CheckResult> {
    results.extend(unreported_outcomes(&results, pages, sitemap_urls));
    results
}
`,
  [AXE]: `
pub fn evaluate_axe_report(report: &AxeReport) -> Vec<CheckResult> {
    let mut results = report.violations.iter().map(axe_violation_result).collect();
    results.extend(
        report.executed_rules().into_iter().map(|rule| axe_rule_coverage_result(rule, outcome)),
    );
    results
}
`,
  [REGISTRY]: `
pub fn registered_code_check_ids() -> impl Iterator<Item = String> {
    CODE_CHECKS.iter().map(|check| super::canonical_code_check_id(check.slug))
}
`,
  [MANIFEST]: JSON.stringify({
    entries: [
      { check: "seo.duplicate_title_across_pages", scope: "session" },
      { check: "seo.orphan_pages", scope: "session" },
    ],
  }),
};

function failuresWith(overrides = {}) {
  const files = { ...HEALTHY, ...overrides };
  return coverageFailures((path) => {
    if (!(path in files)) throw new Error(`unexpected read: ${path}`);
    return files[path];
  });
}

describe("coverage guardrail", () => {
  it("passes on the shape the repository ships", () => {
    expect(failuresWith()).toEqual([]);
  });

  it("fails when a skipped check stops being excepted", () => {
    const claimed = HEALTHY[COVERAGE].replace("CheckStatus::Skipped", "CheckStatus::Pass");
    expect(failuresWith({ [COVERAGE]: claimed }).join(" ")).toContain(
      "must except pairs whose outcome was Skipped",
    );
  });

  it("fails when an incomplete route set stops excepting its cross-page claims", () => {
    const claimed = HEALTHY[COVERAGE].replace(
      "CoverageExceptionReason::SessionIncomplete",
      "CoverageExceptionReason::CheckSkipped",
    );
    expect(failuresWith({ [COVERAGE]: claimed }).join(" ")).toContain(
      "must except cross-page claims when the route set was incomplete",
    );
  });

  it("fails when an unsuccessful run stops being refused outright", () => {
    const lenient = HEALTHY[COVERAGE].replace("!self.successful || ", "");
    expect(failuresWith({ [COVERAGE]: lenient }).join(" ")).toContain(
      "must refuse an unsuccessful run outright",
    );
  });

  it("fails when covers stops consulting the exceptions", () => {
    const claimOnly = HEALTHY[COVERAGE].replace("!self.excepted_on(route, check_id)", "true");
    expect(failuresWith({ [COVERAGE]: claimOnly }).join(" ")).toContain(
      "must consult the exceptions",
    );
  });

  it("fails when family resolution stops reading the registry", () => {
    const handKept = HEALTHY[COVERAGE].replace(
      "FAMILY_PREFIXES.iter()",
      'vec!["accessibility.axe."].iter()',
    );
    expect(failuresWith({ [COVERAGE]: handKept }).join(" ")).toContain(
      "must resolve family ids from the registry's family prefixes",
    );
  });

  it("fails when a producer asserts coverage instead of deriving it", () => {
    const asserted = HEALTHY[NORMALIZED].replace(
      /let coverage = ScanCoverageManifest::derive\([\s\S]*?\);\n\s*Ok\(batch\)\n\}\n\npub fn normalize_code_scan/,
      "Ok(batch)\n}\n\npub fn normalize_code_scan",
    );
    expect(failuresWith({ [NORMALIZED]: asserted }).join(" ")).toContain(
      "normalize_web_scan must derive coverage from the run's own outcomes",
    );
  });

  it("fails when a cross-page run claims its verdicts per route", () => {
    const perRoute = HEALTHY[NORMALIZED].replace(
      "ClaimBasis::RouteSet { complete: successful_page_urls.len() == selected_page_count }",
      "ClaimBasis::PerRoute",
    );
    expect(failuresWith({ [NORMALIZED]: perRoute }).join(" ")).toContain(
      "must declare ClaimBasis::RouteSet",
    );
  });

  it("fails when route-set completeness stops being measured", () => {
    const hardcoded = HEALTHY[NORMALIZED].replace(
      "complete: successful_page_urls.len() == selected_page_count",
      "complete: true",
    );
    expect(failuresWith({ [NORMALIZED]: hardcoded }).join(" ")).toContain(
      "must decide RouteSet completeness by comparing",
    );
  });

  it("fails when the code claim stops reading the registry", () => {
    const invented = HEALTHY[NORMALIZED].replace(
      "crate::core::code_scan::registry::registered_code_check_ids().collect()",
      "vec![]",
    );
    expect(failuresWith({ [NORMALIZED]: invented }).join(" ")).toContain(
      "normalize_code_scan must claim the registry's check ids",
    );
  });

  it("fails when the shared code-check list disappears", () => {
    const gone = HEALTHY[REGISTRY].replace("pub fn registered_code_check_ids", "fn other");
    expect(failuresWith({ [REGISTRY]: gone }).join(" ")).toContain(
      "must expose registered_code_check_ids",
    );
  });

  it("fails when verification claims the set it was asked to prove", () => {
    const asserted = HEALTHY[VERIFICATION].replace(
      "ScanCoverageManifest::derive",
      "ScanCoverageManifest::declared",
    );
    expect(failuresWith({ [VERIFICATION]: asserted }).join(" ")).toContain(
      "must derive verification coverage from the pass's outcomes",
    );
  });

  it("fails when the verification path moves out from under the rule", () => {
    const moved = HEALTHY[VERIFICATION].replace(
      "run_bounded_web_verification",
      "run_bounded_web_check",
    );
    expect(failuresWith({ [VERIFICATION]: moved }).join(" ")).toContain(
      "has no run_bounded_web_verification",
    );
  });

  it("fails when verification assembles a manifest by hand", () => {
    const literal = HEALTHY[VERIFICATION].replace(
      "vec![scan_result.url.clone()],",
      "page_urls: vec![scan_result.url.clone()],",
    );
    expect(failuresWith({ [VERIFICATION]: literal }).join(" ")).toContain(
      "assembles a coverage manifest by hand",
    );
  });

  it("fails when the projection stops asking the coverage manifest", () => {
    const reimplemented = HEALTHY[PROJECTION].replace(
      "coverage.covers(route.as_deref(), check_id)",
      "coverage.page_urls.contains(&route)",
    );
    expect(failuresWith({ [PROJECTION]: reimplemented }).join(" ")).toContain(
      "must ask the coverage manifest whether the run proved the pair",
    );
  });

  it("fails when the projection resolves from an unsuccessful run", () => {
    const lenient = HEALTHY[PROJECTION].replace("if !batch.coverage.successful", "if false");
    expect(failuresWith({ [PROJECTION]: lenient }).join(" ")).toContain(
      "must refuse to resolve anything from an unsuccessful run",
    );
  });

  it("fails when per-kind SQL filtering comes back", () => {
    const flat = HEALTHY[PROJECTION].replace(
      "let coverage = as_stored_keys(&batch.coverage);",
      "let limit_pages = matches!(batch.coverage.kind, ScanCoverageKind::Page);",
    );
    expect(failuresWith({ [PROJECTION]: flat }).join(" ")).toContain(
      "still switches on limit_pages",
    );
  });

  it("fails when the candidate query is inlined back into the resolver", () => {
    const inlined = HEALTHY[PROJECTION].replace(
      "load_open_candidates(tx, &scope, &coverage)?",
      'tx.prepare("SELECT id, signal_id, check_id, page_url FROM work_items")?',
    );
    expect(failuresWith({ [PROJECTION]: inlined }).join(" ")).toContain(
      "must read its candidates through load_open_candidates",
    );
  });

  it("fails when only one side of the route comparison is normalized", () => {
    const asymmetric = HEALTHY[PROJECTION].replace("fn as_stored_keys", "fn unused_helper");
    expect(failuresWith({ [PROJECTION]: asymmetric }).join(" ")).toContain(
      "must normalize both sides of the route comparison",
    );
  });

  it("fails when a clean axe report stops reporting the rules it ran", () => {
    const violationsOnly = HEALTHY[AXE].replace("report.executed_rules()", "report.violations");
    expect(failuresWith({ [AXE]: violationsOnly }).join(" ")).toContain(
      "must report every rule that executed",
    );
  });

  it("fails when non-violation rules stop being graded by outcome", () => {
    const flattened = HEALTHY[AXE].replace("axe_rule_coverage_result(rule, outcome)", "row(rule)");
    expect(failuresWith({ [AXE]: flattened }).join(" ")).toContain(
      "must grade the non-violation rules through axe_rule_coverage_result",
    );
  });

  it("fails when the session analyzer stops reporting outcomes for clean checks", () => {
    const findingsOnly = HEALTHY[SESSION].replace(
      "results.extend(unreported_outcomes(&results, pages, sitemap_urls));",
      "",
    );
    expect(failuresWith({ [SESSION]: findingsOnly }).join(" ")).toContain(
      "must report an outcome for every session check",
    );
  });

  it("fails when a session check has no manifest entry", () => {
    const missing = JSON.stringify({
      entries: [{ check: "seo.duplicate_title_across_pages", scope: "session" }],
    });
    expect(failuresWith({ [MANIFEST]: missing }).join(" ")).toContain(
      "has no entry for seo.orphan_pages",
    );
  });

  it("fails when a cross-page check is registered as page-scoped", () => {
    const mislabelled = JSON.stringify({
      entries: [
        { check: "seo.duplicate_title_across_pages", scope: "session" },
        { check: "seo.orphan_pages", scope: "page" },
      ],
    });
    expect(failuresWith({ [MANIFEST]: mislabelled }).join(" ")).toContain(
      "scopes seo.orphan_pages as page",
    );
  });
});
