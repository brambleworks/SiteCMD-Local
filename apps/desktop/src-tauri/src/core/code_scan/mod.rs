use crate::checks::Severity;
use crate::core::database_targets::{
    canonicalize_local_sqlite_path, is_mysql_database_target, resolve_local_sqlite_path,
    validate_local_database_target,
};
#[cfg(test)]
use postgres::Client as PostgresClient;
use postgres::NoTls;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

mod error;
pub use error::CodeScanError;

mod reporting;
pub use reporting::{format_report, has_issue_at_or_above};

mod identity;
pub use identity::canonical_code_check_id;
// The pure identity extractions and the cap-candidate classification live in
// the portable engine crate (shared with the hosted scorer); re-exported here
// at their original paths.
pub use sitecmd_engine::cap::{
    is_score_cap_candidate_check, SCORE_CAP_CANDIDATE_CODE_RULES, SCORE_CAP_CANDIDATE_WEB_CHECKS,
};
pub use sitecmd_engine::identity::{
    code_producer_rule_id, code_rule_id, validate_canonical_check_id,
};

mod types;
pub(crate) use types::code_scan_domain_label;
pub use types::code_scan_domain_rank;
pub use types::severity_rank;
pub use types::{
    code_issue_domain, score_report, summarize_code_scan_domain, CodeIssue, CodeIssueCountKey,
    CodeIssueView, CodeScanDomain, CodeScanReport, CodeScanReportFormat, CodeScanReportView,
    CodeScanSkippedScopes,
};

mod patterns;
use patterns::*;

mod issue_utils;
use issue_utils::*;
mod issue_rationale;
use issue_rationale::code_issue_rationale;
// Enumerable registry of every code-scan check. Owns the code half of
// severity_policy (policy_severity / allows_critical), the authoritative
// domain classification (code_issue_domain), and the honest check count.
mod package_inventory;
pub mod registry;
use package_inventory::*;
mod project_inventory;
use project_inventory::*;
mod route_helpers;
use route_helpers::*;
mod laravel_routes;
use laravel_routes::{collect_laravel_route_protection, LaravelRouteProtection};

mod filesystem;
mod text_budget;
use text_budget::ScanTextBudget;
mod scan_scope;
mod vendored;
use filesystem::{
    collect_project_inventory, read_project_file, ProjectFile, SourceFile, JS_SOURCE_EXTENSIONS,
};

pub(crate) fn read_bounded_project_text(
    root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Option<String> {
    crate::core::safe_fs::read_bounded_text_under_root(root, path, max_bytes)
}
#[cfg(test)]
use filesystem::{is_drupal_scaffold_file, is_vendored_path, should_skip_walker_dir};
mod file_analysis;
use file_analysis::{analyze_file, FileSignalSummary};
mod supply_chain;
use supply_chain::analyze_supply_chain;
mod operations;
use operations::analyze_operations;
mod ai_scaffolding;
use ai_scaffolding::analyze_ai_scaffolding;

mod database_analysis;
use database_analysis::*;

#[derive(Debug, Clone)]
pub struct CodeScanAuditProgress {
    pub check_id: &'static str,
    pub status: &'static str,
    pub results_count: usize,
    pub checks_done: usize,
    pub checks_total: usize,
}

/// Explicitly authorized Code Scan behaviors that go beyond static file
/// analysis. The default remains entirely filesystem-local and never opens a
/// project database connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeScanOptions {
    pub inspect_local_databases: bool,
}

/// Code Scan progress is reported as a 0-100 percentage across the analyze
/// passes; this is the denominator, not a check count.
const SCAN_PROGRESS_SCALE: usize = 100;

fn emit_code_scan_progress<F>(
    progress: &F,
    check_id: &'static str,
    status: &'static str,
    results_count: usize,
    checks_done: usize,
) where
    F: Fn(CodeScanAuditProgress),
{
    progress(CodeScanAuditProgress {
        check_id,
        status,
        results_count,
        checks_done,
        // `checks_done` is a 0-100 percent-complete value across the four
        // analyze passes, not a literal check count, so the denominator is a
        // fixed percentage scale. The honest first-party check count is
        // `registry::code_check_count`.
        checks_total: SCAN_PROGRESS_SCALE,
    });
}

/// Canonicalize a Code Scan root and require it to stay inside the user's home.
/// Every user- or persistence-derived entry point must call this before walking.
pub fn validate_project_path(raw: &Path) -> Result<PathBuf, String> {
    let canonical =
        fs::canonicalize(raw).map_err(|e| format!("Cannot resolve project path: {}", e))?;
    let home_raw = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "No home directory available".to_string())?;
    let home = home_raw
        .canonicalize()
        .map_err(|_| "Cannot resolve home directory for path validation".to_string())?;
    if !canonical.starts_with(&home) {
        return Err(format!(
            "Project path must live inside your home directory; {} is outside",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn has_project_root_marker(root: &Path) -> bool {
    const MARKER_FILES: &[&str] = &[
        "package.json",
        "composer.json",
        "Gemfile",
        "go.mod",
        "Cargo.toml",
        "pyproject.toml",
        "requirements.txt",
        "schema.prisma",
        "drizzle.config.js",
        "drizzle.config.ts",
        "drizzle.config.mjs",
        "astro.config.mjs",
        "astro.config.ts",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "vite.config.js",
        "vite.config.mjs",
        "vite.config.ts",
    ];
    const MARKER_DIRS: &[&str] = &[
        "src",
        "app",
        "pages",
        "components",
        "lib",
        "functions",
        "api",
        "prisma",
        "drizzle",
        "migrations",
        "supabase",
        "db",
        "database",
        ".cursor",
        ".claude",
        ".mcp",
        ".windsurf",
        "web/modules/custom",
        "web/themes/custom",
        "wp-content/plugins",
        "wp-content/themes",
    ];

    MARKER_FILES
        .iter()
        .any(|marker| root.join(marker).is_file())
        || MARKER_DIRS.iter().any(|marker| root.join(marker).is_dir())
}

#[tracing::instrument(skip(root))]
pub fn audit_project(root: &Path) -> Result<CodeScanReport, String> {
    audit_project_with_options(root, CodeScanOptions::default())
}

#[tracing::instrument(skip(root))]
pub fn audit_project_with_options(
    root: &Path,
    options: CodeScanOptions,
) -> Result<CodeScanReport, String> {
    audit_project_with_options_and_progress(root, options, |_| {})
}

#[tracing::instrument(skip(root, progress))]
pub fn audit_project_with_progress<F>(root: &Path, progress: F) -> Result<CodeScanReport, String>
where
    F: Fn(CodeScanAuditProgress),
{
    audit_project_with_options_and_progress(root, CodeScanOptions::default(), progress)
}

pub fn audit_project_with_options_and_progress<F>(
    root: &Path,
    options: CodeScanOptions,
    progress: F,
) -> Result<CodeScanReport, String>
where
    F: Fn(CodeScanAuditProgress),
{
    audit_project_with_control(root, options, progress, || false).map_err(|error| error.to_string())
}

/// Audit a project while observing cancellation. `cancelled` is polled between
/// stages and before every file, so a cancelled run stops inside the analyze
/// pass instead of finishing it, and returns no report at all.
#[tracing::instrument(skip(root, progress, cancelled))]
pub fn audit_project_with_control<F, C>(
    root: &Path,
    options: CodeScanOptions,
    progress: F,
    cancelled: C,
) -> Result<CodeScanReport, CodeScanError>
where
    F: Fn(CodeScanAuditProgress),
    C: Fn() -> bool + Sync,
{
    audit_project_with_text_budget(
        root,
        options,
        progress,
        cancelled,
        crate::constants::CODE_SCAN_MAX_TEXT_BYTES,
    )
}

fn audit_project_with_text_budget<F, C>(
    root: &Path,
    options: CodeScanOptions,
    progress: F,
    cancelled: C,
    max_text_bytes: u64,
) -> Result<CodeScanReport, CodeScanError>
where
    F: Fn(CodeScanAuditProgress),
    C: Fn() -> bool + Sync,
{
    if !root.is_dir() {
        return Err(CodeScanError::Failed(
            "Project path is not a valid directory".into(),
        ));
    }
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }

    let project_info = crate::core::project::detect_project(root);
    emit_code_scan_progress(&progress, "code-scan.collect-files", "running", 0, 5);
    let inventory = collect_project_inventory(root)?;
    let files = inventory.source_files;
    let project_files = inventory.project_files;
    // Carry pruned-directory counts into the scan summary.
    let skipped_scopes = inventory.skipped_scopes;
    let mut text_budget = ScanTextBudget::new(max_text_bytes, &cancelled);
    text_budget.account_sources(&files)?;
    let manifests = collect_package_manifests(&project_files, &mut text_budget)?;
    emit_code_scan_progress(&progress, "code-scan.collect-files", "complete", 0, 15);
    if files.is_empty() && !has_project_root_marker(root) {
        return Err(CodeScanError::Failed(
            "Code Scan could not find app source files, schema files, or project config in the linked project folder. Choose the project root that contains your project manifest (package.json, composer.json, Cargo.toml, go.mod, pyproject.toml) or source directories like src, app, pages, or api."
                .into(),
        ));
    }
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }

    let mut issues = Vec::new();
    emit_code_scan_progress(&progress, "code-scan.analyze-source", "running", 0, 15);
    // Laravel routes files declare which middleware protect which controllers;
    // resolved once up front so per-file analysis can treat a routed
    // controller as an authenticated (or throttled) surface.
    let laravel_protection = collect_laravel_route_protection(&files);
    let laravel_protection = &laravel_protection;
    let cancelled = &cancelled;
    // Strided workers distribute clustered files, then rejoin results in file
    // order to preserve deterministic issue output.
    let mut summaries: Vec<FileSignalSummary> = Vec::with_capacity(files.len());
    if files.len() <= 1 {
        for file in &files {
            if cancelled() {
                return Err(CodeScanError::Cancelled);
            }
            let (file_issues, summary) = analyze_file(file, laravel_protection);
            issues.extend(file_issues);
            summaries.push(summary);
        }
    } else {
        let worker_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(files.len());
        std::thread::scope(|scope| {
            let files = &files;
            let handles: Vec<_> = (0..worker_count)
                .map(|worker| {
                    scope.spawn(move || {
                        let mut analyzed = Vec::new();
                        for (index, file) in
                            files.iter().enumerate().skip(worker).step_by(worker_count)
                        {
                            // Polled before every file so cancellation lands
                            // inside the analyze pass, not after it.
                            if cancelled() {
                                break;
                            }
                            let (file_issues, summary) = analyze_file(file, laravel_protection);
                            analyzed.push((index, file_issues, summary));
                        }
                        analyzed
                    })
                })
                .collect();
            // Progress is emitted only here on the parent thread (the workers
            // never touch it), so the callback need not be Sync.
            let worker_total = handles.len().max(1);
            let mut indexed: Vec<(usize, Vec<CodeIssue>, FileSignalSummary)> =
                Vec::with_capacity(files.len());
            let mut issue_count = 0usize;
            for (worker_index, handle) in handles.into_iter().enumerate() {
                // A join error means the worker thread itself panicked;
                // analyze_file is pure and cannot fail, so this is an
                // unrecoverable bug, not a runtime error to recover from.
                let worker_results = handle.join().expect("code-scan analyze worker panicked"); // allow-expect: worker-thread panic is unrecoverable
                issue_count += worker_results
                    .iter()
                    .map(|(_, file_issues, _)| file_issues.len())
                    .sum::<usize>();
                indexed.extend(worker_results);
                let done = 15 + (((worker_index + 1) * 40) / worker_total);
                emit_code_scan_progress(
                    &progress,
                    "code-scan.analyze-source",
                    "running",
                    issue_count,
                    done.min(55),
                );
            }
            // Restore exact file order across the strided workers.
            indexed.sort_unstable_by_key(|(index, ..)| *index);
            for (_, file_issues, summary) in indexed {
                issues.extend(file_issues);
                summaries.push(summary);
            }
        });
    }
    // Workers stop at their next file boundary, so a cancelled analyze pass
    // holds a partial issue set that must never become a report.
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    emit_code_scan_progress(
        &progress,
        "code-scan.analyze-source",
        "complete",
        issues.len(),
        55,
    );
    emit_code_scan_progress(
        &progress,
        "code-scan.supply-chain",
        "running",
        issues.len(),
        60,
    );
    issues.extend(analyze_supply_chain(
        root,
        &files,
        &project_files,
        &manifests,
        &mut text_budget,
    )?);
    emit_code_scan_progress(
        &progress,
        "code-scan.supply-chain",
        "complete",
        issues.len(),
        68,
    );
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    emit_code_scan_progress(
        &progress,
        "code-scan.operations",
        "running",
        issues.len(),
        72,
    );
    issues.extend(analyze_operations(
        root,
        &files,
        &summaries,
        &project_files,
        &manifests,
        options,
        &mut text_budget,
    )?);
    emit_code_scan_progress(
        &progress,
        "code-scan.operations",
        "complete",
        issues.len(),
        80,
    );
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    emit_code_scan_progress(
        &progress,
        "code-scan.ai-scaffolding",
        "running",
        issues.len(),
        81,
    );
    issues.extend(analyze_ai_scaffolding(root, &mut text_budget)?);
    emit_code_scan_progress(
        &progress,
        "code-scan.ai-scaffolding",
        "complete",
        issues.len(),
        82,
    );
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    emit_code_scan_progress(&progress, "code-scan.finalize", "running", issues.len(), 84);
    apply_framework_auth_overrides(project_info.framework.as_deref(), &files, &mut issues);
    // Sole production caller of the code-issue severity policy (guardrail-pinned).
    crate::core::severity_policy::normalize_code_issues(&mut issues);

    issues.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.relative_path.cmp(&b.relative_path))
            .then_with(|| a.title.cmp(&b.title))
    });
    issues.dedup_by(|a, b| a.id == b.id);

    // Report and work-item paths must stamp the same canonical check id so
    // lifecycle actions and scoring address one group.
    for issue in &mut issues {
        issue.check_id = canonical_code_check_id(&issue.id);
    }

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    for issue in &issues {
        match issue.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            Severity::Medium => medium_count += 1,
            Severity::Low => low_count += 1,
        }
    }
    emit_code_scan_progress(
        &progress,
        "code-scan.finalize",
        "complete",
        issues.len(),
        86,
    );

    Ok(CodeScanReport {
        checked_at: chrono::Utc::now().to_rfc3339(),
        framework: project_info.framework,
        issue_count: issues.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        issues,
        skipped_scopes,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod path_validation_tests {
    use super::*;
    use std::path::Path;

    fn home_dir_for_test() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .expect("HOME must be set for tests")
            .canonicalize()
            .expect("HOME must canonicalize")
    }

    #[test]
    fn rejects_path_outside_home() {
        let result = validate_project_path(Path::new("/etc"));
        assert!(
            result.is_err(),
            "expected /etc to be rejected, got {:?}",
            result
        );
    }

    #[test]
    fn rejects_nonexistent_path() {
        let result = validate_project_path(Path::new("/this/path/does/not/exist/anywhere"));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escaping_home() {
        // Create a symlink inside home that points outside home, and verify
        // canonicalize follows the symlink so the bound check rejects it.
        let home = home_dir_for_test();
        let link_name = format!(".sitecmd-test-symlink-{}", std::process::id());
        let link = home.join(&link_name);
        let _ = std::fs::remove_file(&link); // best-effort cleanup from prior runs

        if std::os::unix::fs::symlink("/etc", &link).is_ok() {
            let result = validate_project_path(&link);
            // canonicalize follows the symlink to /etc, which is outside home.
            assert!(
                result.is_err(),
                "expected symlink to /etc to be rejected, got {:?}",
                result
            );
            let _ = std::fs::remove_file(&link);
        } else {
            // If the test runner can't create symlinks (rare on Unix), skip.
            eprintln!("skipping symlink test (could not create symlink)");
        }
    }

    #[test]
    fn accepts_path_inside_home() {
        let home = home_dir_for_test();
        let result = validate_project_path(&home);
        assert!(
            result.is_ok(),
            "expected home to be accepted, got {:?}",
            result
        );
    }
}
