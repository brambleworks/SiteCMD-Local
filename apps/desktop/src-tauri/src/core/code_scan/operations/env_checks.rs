use super::*;

pub(super) fn collect_env_issues(
    issues: &mut Vec<CodeIssue>,
    files: &[SourceFile],
    example_env_files: &[&EnvFileSnapshot],
    source_env_keys: &SourceEnvInventory,
    env_files: &[EnvFileSnapshot],
    inspect_local_databases: bool,
) {
    let mut scoped_source_keys = vec![HashSet::new(); example_env_files.len()];
    let mut uncovered_env_usage_file = None;
    for (file, keys) in files.iter().zip(&source_env_keys.keys_by_file) {
        if keys.is_empty() {
            continue;
        }
        if let Some(index) = closest_env_example_index(&file.relative_path, example_env_files) {
            scoped_source_keys[index].extend(keys.iter().cloned());
        } else if uncovered_env_usage_file.is_none()
            && keys.iter().any(|key| !is_platform_injected_env_key(key))
        {
            uncovered_env_usage_file = Some(file);
        }
    }

    if let Some(file) = uncovered_env_usage_file {
        issues.push(build_issue(
            "env-example-missing",
            "operations",
            Severity::Medium,
            "Environment variables are used but no example env file was found",
            "This project reads at least one developer-supplied environment variable, but SiteCMD found no .env.example, .env.sample, or .env.template in the scanned tree. The variable may be optional or documented elsewhere, so this is a setup-documentation review rather than proof that the app cannot start.",
            file,
            first_match_line(&file.content, &ENV_USAGE_PATTERNS),
            Some("Environment variable access was detected, but no example env template was found in the project.".into()),
            Some("Add a scrubbed example env file for developer-supplied configuration. Mark each entry as required, optional, or defaulted; use clearly fake placeholders and never copy live credentials, customer identifiers, or production hosts.".into()),
            Some("From a clean checkout, configure the documented local workflow and representative optional features using only the example file plus referenced setup documentation. Confirm no additional developer-supplied key is discovered at runtime.".into()),
        ));
    }

    for (example_env, scoped_keys) in example_env_files.iter().zip(scoped_source_keys) {
        let mut missing_example_keys = scoped_keys
            .iter()
            .filter(|key| !example_env.keys.contains(*key))
            // Platform-injected variables (NODE_ENV, CI, VERCEL_*,...) are
            // provided by the runtime or deploy platform, not by developers;
            // demanding they appear in `.env.example` was busywork the official
            // platform docs advise against.
            .filter(|key| !is_platform_injected_env_key(key))
            .cloned()
            .collect::<Vec<_>>();
        missing_example_keys.sort_unstable();
        if !missing_example_keys.is_empty() {
            let (confidence, confidence_reason) = policy_confidence("env-example-incomplete");
            issues.push(CodeIssue {
                check_id: String::new(),
                id: format!("env-example-incomplete:{}", example_env.relative_path),
                category: "operations".into(),
                // Missing example keys are documentation gaps; names alone do
                // not establish high impact.
                severity: Severity::Medium,
                title: "Example env file is missing variables used by the app".into(),
                description: "The source reads environment keys that do not appear in the selected example env file. Some may be optional, dynamically supplied, or documented through another setup system, so review each named key before changing the template.".into(),
                relative_path: example_env.relative_path.clone(),
                absolute_path: example_env.absolute_path.to_string_lossy().to_string(),
                line: None,
                source_excerpt: None,
                evidence: Some(redact_evidence(format!(
                    "Source code references {} that do not appear in the example env template.",
                    format_key_list(&missing_example_keys)
                ))),
                why_now: Some("When source configuration and its setup template diverge, a clean checkout or newly enabled feature can require undocumented configuration. The operational impact depends on whether each key is required and where it is supplied.".into()),
                likely_fix: Some("Classify each named key as developer-supplied, platform-injected, optional, defaulted, or obsolete. Add only developer-supplied entries to the example with clearly fake placeholders and a required/optional note; update the detector's platform vocabulary if a provider injects a key SiteCMD does not recognize.".into()),
                confidence,
                confidence_reason,
                verify_hint: Some("From a clean checkout, configure the documented local workflow and representative optional features using the example plus referenced setup docs. Confirm required keys are present, optional keys fail safely or use documented defaults, and no real values entered the example.".into()),
            });
        }
    }

    for (anchor_file, drift_summary) in summarize_env_drift(env_files, &source_env_keys.all_keys) {
        let (confidence, confidence_reason) = policy_confidence("env-drift");
        issues.push(CodeIssue {
            check_id: String::new(),
            id: format!("env-drift:{}", anchor_file.relative_path),
            category: "operations".into(),
            severity: Severity::Medium,
            title: "Environment files have drifted across deploy contexts".into(),
            description: "Environment-parallel files in the scanned tree contain different subsets of source-referenced keys. That difference does not establish a defect: environment-specific variables, external secret injection, and feature differences can be intentional. Review the named mismatches against the deployment model.".into(),
            relative_path: anchor_file.relative_path.clone(),
            absolute_path: anchor_file.absolute_path.to_string_lossy().to_string(),
            line: None,
            source_excerpt: None,
            evidence: Some(redact_evidence(drift_summary)),
            why_now: Some("An unexplained key-set difference can surface only when a particular environment or feature path starts. The key name alone does not determine severity, even when it looks credential-related.".into()),
            likely_fix: Some("For each mismatch, decide whether the key is shared, intentionally environment-specific, injected outside the repository, optional, or obsolete. Align genuinely shared required keys, and document intentional differences beside the canonical example or deployment configuration instead of forcing every environment to have identical key sets.".into()),
            confidence,
            confidence_reason,
            verify_hint: Some("Validate the resolved configuration for each supported environment without exposing values. Exercise the feature that consumes each mismatched key and confirm required keys are supplied while documented environment-specific or optional differences behave as intended.".into()),
        });
    }

    if let Some((anchor_file, remote_target_summary)) = inspect_local_databases
        .then(|| summarize_remote_local_dev_database_targets(env_files))
        .flatten()
    {
        issues.push(CodeIssue {
            check_id: String::new(),
            id: format!("local-db-target-remote:{}", anchor_file.relative_path),
            category: "operations".into(),
            severity: Severity::Medium,
            title: "Local development env references a remote database host".into(),
            description: "SiteCMD parsed a literal database URL in a local/development env file whose host is not loopback, a local socket, or a single-label container service. A dedicated hosted development database or per-developer branch may be intentional. The scan cannot identify the remote account, project/branch, data classification, credential privileges, or safety guards on destructive commands.".into(),
            relative_path: anchor_file.relative_path.clone(),
            absolute_path: anchor_file.absolute_path.to_string_lossy().to_string(),
            line: None,
            source_excerpt: None,
            evidence: Some(redact_evidence(remote_target_summary)),
            why_now: Some("A remote development target increases the consequence of choosing the wrong account or branch during tests, seeds, resets, migrations, or repair scripts. The risk depends on isolation, data, privileges, and command safeguards rather than on remoteness alone.".into()),
            likely_fix: Some("Confirm whether remote development is part of the intended workflow. If it is, use an isolated non-production project or per-developer branch with synthetic data and least-privilege credentials, and guard destructive commands with an allowlist for the expected host plus database/project/branch identifier. Otherwise point local development at a local container, socket, SQLite file, or loopback service. Keep credentials in ignored local secrets or a secret manager.".into()),
            confidence: crate::checks::IssueConfidence::NeedsReview,
            confidence_reason: Some("The remote hostname is a direct parsed fact, but static env files do not establish whether the target is production, shared, isolated, read-only, or protected by runtime safety checks.".into()),
            verify_hint: Some("Resolve the effective local database configuration without printing credentials. Confirm the hostname, account, database plus project or branch identifier, data classification, and credential role. Exercise destructive-command guards against both the approved development target and a production-like target.".into()),
        });
    }
}

fn env_example_scope(relative_path: &str) -> &str {
    relative_path
        .rsplit_once('/')
        .map(|(directory, _)| directory)
        .unwrap_or("")
}

fn path_is_in_scope(relative_path: &str, scope: &str) -> bool {
    scope.is_empty()
        || relative_path
            .strip_prefix(scope)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn closest_env_example_index(source_path: &str, examples: &[&EnvFileSnapshot]) -> Option<usize> {
    examples
        .iter()
        .enumerate()
        .filter(|(_, example)| {
            path_is_in_scope(source_path, env_example_scope(&example.relative_path))
        })
        .max_by_key(|(_, example)| env_example_scope(&example.relative_path).len())
        .map(|(index, _)| index)
}

/// Env keys the runtime or deploy platform injects (never supplied by
/// developers), so their absence from `.env.example` is not a documentation
/// gap. Exact names cover Node/CI conventions; prefixes cover the common
/// hosting platforms and the local PHP development environments.
fn is_platform_injected_env_key(key: &str) -> bool {
    const EXACT: &[&str] = &[
        "NODE_ENV",
        "CI",
        "PORT",
        "TZ",
        "HOME",
        "HOSTNAME",
        "PWD",
        "PATH",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_DATA_HOME",
        "CARGO_MANIFEST_DIR",
        "DEV",
        "MODE",
        "VITE_APP_VERSION",
        "VITE_SOURCE_COMMIT",
        "IS_DDEV_PROJECT",
    ];
    const PREFIXES: &[&str] = &[
        "VERCEL_",
        "NEXT_RUNTIME",
        "CF_",
        "RAILWAY_",
        "RENDER_",
        "NETLIFY_",
        "GITHUB_",
        "GITLAB_",
        "FLY_",
        "HEROKU_",
        "AWS_LAMBDA_",
        "ACTIONS_ID_TOKEN_",
        "CARGO_PKG_",
        "DENO_DEPLOYMENT_",
        "DDEV_",
        "PLATFORM_",
        "LANDO_",
        "PANTHEON_",
    ];
    let upper = key.to_ascii_uppercase();
    EXACT.contains(&upper.as_str()) || PREFIXES.iter().any(|prefix| upper.starts_with(prefix))
}

#[cfg(test)]
#[path = "env_checks_tests.rs"]
mod fixture_tests;

#[cfg(test)]
mod tests {
    use super::is_platform_injected_env_key;

    #[test]
    fn platform_injected_env_keys_are_recognized() {
        // Injected by the runtime or platform: not documentation gaps.
        assert!(is_platform_injected_env_key("NODE_ENV"));
        assert!(is_platform_injected_env_key("CI"));
        assert!(is_platform_injected_env_key("VERCEL_ENV"));
        assert!(is_platform_injected_env_key("VERCEL_URL"));
        assert!(is_platform_injected_env_key("CF_PAGES_BRANCH"));
        assert!(is_platform_injected_env_key("RAILWAY_ENVIRONMENT"));
        assert!(is_platform_injected_env_key("GITHUB_ACTIONS"));
        assert!(is_platform_injected_env_key("ACTIONS_ID_TOKEN_REQUEST_URL"));
        assert!(is_platform_injected_env_key("APPDATA"));
        assert!(is_platform_injected_env_key("VITE_APP_VERSION"));
        assert!(is_platform_injected_env_key("CARGO_PKG_VERSION"));
        // Local and hosted PHP platforms inject their own markers.
        assert!(is_platform_injected_env_key("IS_DDEV_PROJECT"));
        assert!(is_platform_injected_env_key("DDEV_HOSTNAME"));
        assert!(is_platform_injected_env_key("PLATFORM_APPLICATION"));
        assert!(is_platform_injected_env_key("PLATFORM_BRANCH"));
        assert!(is_platform_injected_env_key("LANDO_INFO"));
        assert!(is_platform_injected_env_key("PANTHEON_ENVIRONMENT"));

        // Developer-supplied config must still be documented.
        assert!(!is_platform_injected_env_key("DATABASE_URL"));
        assert!(!is_platform_injected_env_key("OPENAI_API_KEY"));
        assert!(!is_platform_injected_env_key("STRIPE_SECRET_KEY"));
        assert!(!is_platform_injected_env_key("PORTAL_URL"));
        assert!(!is_platform_injected_env_key("CIRCLE_RADIUS"));
    }
}
