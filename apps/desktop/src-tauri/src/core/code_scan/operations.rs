use super::file_analysis::is_config_file;
use super::*;

mod app_readiness;
use app_readiness::collect_app_readiness_issues;
mod env_checks;
use env_checks::collect_env_issues;
mod framework_debug;
use framework_debug::collect_framework_debug_issues;
mod local_databases;
use local_databases::collect_local_database_issues;
mod supabase_policies;
use supabase_policies::collect_supabase_policy_issues;
mod project_hygiene;
use project_hygiene::collect_project_hygiene_issues;
mod runtime_eol;
mod typescript_config;
use runtime_eol::collect_runtime_eol_issues;
use typescript_config::collect_typescript_config_issues;

/// Whether this file is a first-party Drupal `.install` that actually declares
/// a schema-change hook. Drupal applies schema changes through `hook_update_N()`
/// and `hook_post_update_NAME()`, run by `drush updb`; an `.install` holding
/// only `hook_install()` sets a module up and establishes no update workflow,
/// so the path alone is not the signal.
fn drupal_install_file_declares_update_hook(file: &ProjectFile) -> bool {
    const MAX_INSTALL_FILE_BYTES: u64 = 250_000;
    let path = file.relative_path.to_ascii_lowercase().replace('\\', "/");
    if !path.ends_with(".install") || !(path.contains("/modules/") || path.contains("/profiles/")) {
        return false;
    }
    let Some(bytes) = read_project_file(file, MAX_INSTALL_FILE_BYTES) else {
        return false;
    };
    let Ok(content) = String::from_utf8(bytes) else {
        return false;
    };
    declares_drupal_update_hook(&content)
}

/// `<module>_update_<number>()` and `<module>_post_update_<name>()` are the two
/// schema-change hook forms Drupal's updater runs.
fn declares_drupal_update_hook(content: &str) -> bool {
    content.lines().any(|line| {
        let Some(rest) = line.trim_start().strip_prefix("function ") else {
            return false;
        };
        rest.contains("_post_update_")
            || rest
                .split("_update_")
                .skip(1)
                .any(|tail| tail.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// `summaries` is parallel to `files` (same order, same length): the per-file
/// predicates were computed during the parallel analyze phase so this serial
/// phase never re-scans file content for corpus-level booleans.
pub(super) fn analyze_operations(
    root: &Path,
    files: &[SourceFile],
    rust_modules: &scan_scope::RustModuleGraph,
    summaries: &[FileSignalSummary],
    project_files: &[ProjectFile],
    manifests: &[PackageManifest],
    options: CodeScanOptions,
    text_budget: &mut ScanTextBudget<'_>,
) -> Result<Vec<CodeIssue>, CodeScanError> {
    let project_paths = collect_project_paths(project_files);
    // Example templates are ordinary source/configuration. Actual dotenv
    // files can contain live credentials, so their values are read only for
    // an explicitly opted-in local-database inspection run.
    let env_files = collect_env_files(project_files, options.inspect_local_databases, text_budget)?;
    let database_artifacts = collect_database_artifacts(project_files, text_budget)?;
    let local_sqlite_snapshots = if options.inspect_local_databases {
        collect_local_sqlite_snapshots(root, &env_files)
    } else {
        Vec::new()
    };
    let local_postgres_snapshots = if options.inspect_local_databases {
        collect_local_postgres_snapshots(root, &env_files)?
    } else {
        Vec::new()
    };
    let deploy_configs = collect_deploy_config_files(project_files, text_budget)?;
    let source_env_keys = SourceEnvInventory::new(files, project_files, rust_modules, text_budget)?;
    let project_paths_lower = project_paths
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let declared_dependencies = manifests
        .iter()
        .flat_map(|manifest| manifest.dependencies.iter().cloned())
        .collect::<HashSet<_>>();
    let route_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| summary.route_like.then_some(file))
        .collect::<Vec<_>>();
    let server_action_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| summary.server_action_like.then_some(file))
        .collect::<Vec<_>>();
    let env_usage_file = files
        .iter()
        .zip(summaries)
        .find_map(|(file, summary)| summary.uses_env.then_some(file));
    let llm_file = files
        .iter()
        .zip(summaries)
        .find_map(|(file, summary)| summary.uses_llm.then_some(file));
    let llm_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| summary.uses_llm.then_some(file))
        .collect::<Vec<_>>();
    let db_file = files
        .iter()
        .zip(summaries)
        .find_map(|(file, summary)| summary.touches_db.then_some(file));
    let background_job_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| summary.background_jobs.then_some(file))
        .collect::<Vec<_>>();
    let frontend_supabase_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| summary.frontend_supabase.then_some(file))
        .collect::<Vec<_>>();
    let frontend_supabase_accesses =
        collect_frontend_supabase_table_accesses(&frontend_supabase_files);
    let client_auth_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| summary.client_auth.then_some(file))
        .collect::<Vec<_>>();
    let app_like = !route_files.is_empty()
        && (route_files.len() >= 2 || llm_file.is_some() || db_file.is_some());
    let complex_app = route_files.len() >= 3
        || (!route_files.is_empty() && (llm_file.is_some() || db_file.is_some()));
    let frontend_app = has_named_dependency(&declared_dependencies, FRONTEND_APP_PACKAGES)
        || project_paths_lower.iter().any(|path| {
            path.ends_with("/app/page.tsx")
                || path.ends_with("/app/page.jsx")
                || path.ends_with("/pages/_app.tsx")
                || path.ends_with("/pages/_app.jsx")
                || path.ends_with("/pages/index.tsx")
                || path.ends_with("/pages/index.jsx")
        });
    let example_env_files = env_files
        .iter()
        .filter(|file| is_example_env_file(&file.relative_path))
        .collect::<Vec<_>>();
    let has_healthcheck = summaries.iter().any(|summary| summary.healthcheck);
    let has_error_reporting =
        has_named_dependency(&declared_dependencies, ERROR_REPORTING_PACKAGES)
            || summaries.iter().any(|summary| summary.error_reporting);
    let has_structured_logging =
        has_named_dependency(&declared_dependencies, STRUCTURED_LOGGING_PACKAGES)
            || summaries.iter().any(|summary| summary.structured_logging);
    let has_ai_observability_integration =
        has_named_dependency(&declared_dependencies, AI_OBSERVABILITY_PACKAGES)
            || summaries.iter().any(|summary| summary.ai_observability);
    let has_feature_flags = summaries.iter().any(|summary| summary.feature_flags);
    let db_backed =
        db_file.is_some() || has_named_dependency(&declared_dependencies, DATABASE_PACKAGES);
    let ai_heavy_project = llm_files.len() >= 2
        || summaries
            .iter()
            .any(|summary| summary.uses_llm && summary.ai_heavy_marker);
    let middleware_protection = collect_next_middleware_protection(files);
    let has_server_auth_enforcement = summaries.iter().any(|summary| {
        (summary.route_like || summary.server_action_like) && summary.auth_enforcement
    }) || middleware_protection.global
        || !middleware_protection.prefixes.is_empty();
    let has_error_boundary = project_paths_lower.iter().any(|path| {
        path == "app/error.tsx"
            || path == "app/error.jsx"
            || path == "app/global-error.tsx"
            || path == "app/global-error.jsx"
            || path == "src/app/error.tsx"
            || path == "src/app/error.jsx"
            || path == "src/app/global-error.tsx"
            || path == "src/app/global-error.jsx"
            || path == "pages/_error.tsx"
            || path == "pages/_error.jsx"
            || path == "src/pages/_error.tsx"
            || path == "src/pages/_error.jsx"
            || path.contains("errorboundary")
    }) || summaries.iter().any(|summary| summary.error_boundary);
    let has_job_visibility = summaries.iter().any(|summary| summary.job_visibility)
        || (has_structured_logging && summaries.iter().any(|summary| summary.job_marker_words));
    let has_migration_workflow = project_paths_lower.iter().any(|path| {
        path.contains("/migrations/")
            || path.contains("/supabase/migrations/")
            || path.contains("/alembic/versions/")
    }) || project_files
        .iter()
        .any(drupal_install_file_declares_update_hook)
        || manifests.iter().any(|manifest| {
            serde_json::from_str::<Value>(&manifest.content)
                .ok()
                .and_then(|json| json.get("scripts").and_then(Value::as_object).cloned())
                .is_some_and(|scripts| {
                    scripts.keys().any(|key| {
                        let key = key.to_ascii_lowercase();
                        key == "migrate"
                            || key.starts_with("migrate:")
                            || key == "db:migrate"
                            || key.starts_with("db:migrate:")
                            || key == "db:push"
                            || key.starts_with("db:push:")
                    })
                })
        });
    let has_recovery_notes = project_has_path_or_text_signal(
        project_files,
        &[
            "backup", "restore", "recovery", "runbook", "disaster", "incident",
        ],
        &[
            "backup",
            "restore",
            "recovery",
            "runbook",
            "disaster",
            "point-in-time",
            "pitr",
        ],
    );
    let has_rollback_notes = project_has_path_or_text_signal(
        project_files,
        &["rollback", "roll-back", "runbook", "recovery", "incident"],
        &[
            "rollback",
            "roll back",
            "redeploy",
            "re-deploy",
            "last known-good",
            "last known good",
            "revert deployment",
            "deployment rollback",
        ],
    );
    let has_backup_restore_notes = project_has_path_or_text_signal(
        project_files,
        &["backup", "restore", "disaster"],
        &[
            "backup",
            "restore",
            "snapshot",
            "point-in-time",
            "pitr",
            "database dump",
        ],
    );
    let expected_db_tables = collect_expected_db_table_names(&database_artifacts);
    let expected_db_columns = collect_expected_db_columns(&database_artifacts);
    let expected_prisma_migrations = collect_expected_prisma_migration_names(&project_paths_lower);
    let expected_drizzle_migrations =
        collect_expected_drizzle_migration_names(&database_artifacts, &project_paths_lower);
    let route_db_files = files
        .iter()
        .zip(summaries)
        .filter_map(|(file, summary)| (summary.route_like && summary.touches_db).then_some(file))
        .collect::<Vec<_>>();
    let has_local_rls_markers = database_artifacts
        .iter()
        .any(|artifact| has_any(&artifact.content, &DB_RLS_PATTERNS));
    let local_rls_states = collect_local_rls_table_states(&database_artifacts);
    let db_lookup_fields = collect_db_lookup_fields(&database_artifacts);
    let has_db_index_hints = database_artifacts
        .iter()
        .any(|artifact| has_any(&artifact.content, &DB_INDEX_HINT_PATTERNS));
    let has_shared_data_layer = summaries.iter().any(|summary| summary.shared_data_layer);
    let mut issues = Vec::new();

    issues.extend(collect_source_schema_integrity_issues(&database_artifacts));

    collect_env_issues(
        &mut issues,
        files,
        &example_env_files,
        &source_env_keys,
        &env_files,
        options.inspect_local_databases,
    );

    collect_framework_debug_issues(&mut issues, files, &env_files);

    collect_local_database_issues(
        &mut issues,
        files,
        &local_sqlite_snapshots,
        &local_postgres_snapshots,
        &expected_db_tables,
        &expected_db_columns,
        &expected_prisma_migrations,
        &expected_drizzle_migrations,
    );

    collect_supabase_policy_issues(
        &mut issues,
        files,
        &frontend_supabase_accesses,
        &frontend_supabase_files,
        &local_rls_states,
        has_local_rls_markers,
        &db_lookup_fields,
        has_db_index_hints,
        &database_artifacts,
    );

    collect_app_readiness_issues(
        &mut issues,
        files,
        manifests,
        &route_files,
        &llm_files,
        llm_file,
        db_file,
        &background_job_files,
        &client_auth_files,
        &server_action_files,
        &route_db_files,
        app_like,
        complex_app,
        frontend_app,
        db_backed,
        ai_heavy_project,
        has_healthcheck,
        has_error_reporting,
        has_structured_logging,
        has_ai_observability_integration,
        has_server_auth_enforcement,
        has_error_boundary,
        has_feature_flags,
        has_job_visibility,
        has_migration_workflow,
        has_shared_data_layer,
        has_recovery_notes,
        has_rollback_notes,
        has_backup_restore_notes,
        &deploy_configs,
    );

    collect_project_hygiene_issues(
        &mut issues,
        root,
        files,
        summaries,
        manifests,
        &project_paths_lower,
        &declared_dependencies,
        &route_files,
        env_usage_file,
        app_like,
    );

    collect_runtime_eol_issues(&mut issues, project_files, manifests);
    collect_typescript_config_issues(&mut issues, project_files);

    Ok(issues)
}

fn project_has_path_or_text_signal(
    project_files: &[ProjectFile],
    path_terms: &[&str],
    content_terms: &[&str],
) -> bool {
    project_files.iter().any(|file| {
        let lower_path = file.relative_path.to_ascii_lowercase();
        if !looks_like_ops_note_path(&lower_path) {
            return false;
        }
        if path_terms.iter().any(|term| lower_path.contains(term)) {
            return true;
        }
        let Some(bytes) = read_project_file(file, 250_000) else {
            return false;
        };
        let Ok(content) = String::from_utf8(bytes) else {
            return false;
        };
        let lower = content.to_ascii_lowercase();
        content_terms.iter().any(|term| lower.contains(term))
    })
}

fn looks_like_ops_note_path(relative_path: &str) -> bool {
    let is_text_note = relative_path.ends_with(".md")
        || relative_path.ends_with(".mdx")
        || relative_path.ends_with(".txt")
        || relative_path.ends_with(".rst")
        || relative_path.ends_with(".adoc");
    if !is_text_note {
        return false;
    }
    relative_path == "readme.md"
        || relative_path.starts_with("docs/")
        || relative_path.starts_with("runbooks/")
        || relative_path.starts_with("ops/")
        || relative_path.contains("/docs/")
        || relative_path.contains("/runbooks/")
        || relative_path.contains("/ops/")
}

#[cfg(test)]
mod drupal_update_hook_tests {
    use super::declares_drupal_update_hook;

    #[test]
    fn only_schema_change_hooks_count_as_an_update_workflow() {
        assert!(declares_drupal_update_hook(
            "<?php\nfunction acme_core_update_10001() {\n  return 'done';\n}\n"
        ));
        assert!(declares_drupal_update_hook(
            "<?php\n  function acme_core_post_update_rebuild_index(&$sandbox) {\n}\n"
        ));

        // Setup and uninstall hooks establish no schema-change workflow, and a
        // mention outside a declaration is not one either.
        assert!(!declares_drupal_update_hook(
            "<?php\nfunction acme_core_install() {\n}\nfunction acme_core_uninstall() {\n}\n"
        ));
        assert!(!declares_drupal_update_hook(
            "<?php\n// See acme_core_update_10001() in the release notes.\n"
        ));
        assert!(!declares_drupal_update_hook(
            "<?php\nfunction acme_core_update_status() {\n}\n"
        ));
    }
}
