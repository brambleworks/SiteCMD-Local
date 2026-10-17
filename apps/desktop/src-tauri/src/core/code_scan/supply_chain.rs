use super::*;

mod committed_files;
use committed_files::{
    collect_dockerfile_pinning_issues, collect_npmrc_token_issues, collect_pipe_to_shell_issues,
};
mod config_secrets;
use config_secrets::collect_config_secret_issues;
mod github_actions;
use github_actions::{
    collect_workflow_injection_issues, collect_workflow_permission_issues,
    collect_workflow_pinning_issues, collect_workflow_pr_target_checkout_issues,
};
mod release_age;
use release_age::collect_release_age_issues;
mod dependency_ranges;
use dependency_ranges::collect_unbounded_dependency_issues;
mod lockfile_integrity;
use lockfile_integrity::collect_lockfile_integrity_issues;
mod usage_evidence;
use usage_evidence::collect_extra_usage_evidence;
mod resolution;
use resolution::{
    collect_base_url_prefixes, collect_path_alias_prefixes, importer_is_typescript,
    is_framework_provided, lockfile_dir_in_scope, types_package_name,
};

pub(super) fn analyze_supply_chain(
    root: &Path,
    files: &[SourceFile],
    project_files: &[ProjectFile],
    manifests: &[PackageManifest],
    text_budget: &mut ScanTextBudget<'_>,
) -> Result<Vec<CodeIssue>, CodeScanError> {
    let registry_config = collect_registry_config(root, manifests);
    let declared_dependencies = manifests
        .iter()
        .flat_map(|manifest| manifest.dependencies.iter().cloned())
        .collect::<HashSet<_>>();
    let local_package_names = manifests
        .iter()
        .filter_map(|manifest| manifest.package_name.clone())
        .collect::<HashSet<_>>();
    // Treat tsconfig path aliases as internal imports, not undeclared npm
    // dependencies. `baseUrl` roots are kept separate because they only apply
    // to the files their own config governs.
    let path_alias_prefixes = collect_path_alias_prefixes(project_files);
    let base_url_prefixes = collect_base_url_prefixes(project_files);
    let package_refs = collect_js_package_refs(files);
    let imported_packages = package_refs
        .iter()
        .map(|package_ref| package_ref.package_name.clone())
        .collect::<HashSet<_>>();

    let mut issues = Vec::new();
    let mut seen_ids = HashSet::new();
    // Usage evidence the source walk cannot see, read lazily only when an
    // unused-dependency candidate appears (bounded file reads).
    let mut extra_usage: Option<HashSet<String>> = None;
    // Excerpt lookups below were a linear scan of all files per emitted issue;
    // a repo with hundreds of supply-chain findings paid O(issues x files).
    let content_by_path: HashMap<&str, &str> = files
        .iter()
        .map(|file| (file.relative_path.as_str(), file.content.as_str()))
        .collect();
    let content_for =
        |relative_path: &str| -> &str { content_by_path.get(relative_path).copied().unwrap_or("") };

    for package_ref in package_refs {
        let framework_provided =
            is_framework_provided(&package_ref.package_name, &declared_dependencies);
        let matches_prefix = |prefix: &String| {
            package_ref.package_name == *prefix
                || package_ref
                    .package_name
                    .starts_with(&format!("{}/", prefix))
        };
        let alias_internal = path_alias_prefixes.iter().any(matches_prefix)
            || base_url_prefixes.iter().any(|(scope, prefixes)| {
                package_ref.relative_path.starts_with(scope.as_str())
                    && prefixes.iter().any(matches_prefix)
            });
        // A TypeScript file can import a package that ships no runtime module
        // of its own, resolving the specifier entirely through its
        // DefinitelyTyped declarations.
        let types_declared = importer_is_typescript(&package_ref.relative_path)
            && types_package_name(&package_ref.package_name)
                .is_some_and(|types_name| declared_dependencies.contains(&types_name));
        let declared = declared_dependencies.contains(&package_ref.package_name)
            || local_package_names.contains(&package_ref.package_name)
            || framework_provided
            || alias_internal
            || types_declared;

        if !declared {
            let id = format!(
                "undeclared-package:{}:{}",
                package_ref.relative_path,
                sanitize_identifier(&package_ref.package_name),
            );
            if seen_ids.insert(id.clone()) {
                // Graded by the shared confidence policy: import resolution is
                // a heuristic with a documented false-positive history (path
                // aliases, framework-provided namespaces, resolvers the scan
                // does not model).
                let (confidence, confidence_reason) =
                    crate::core::confidence_policy::code_issue_confidence("undeclared-package");
                issues.push(CodeIssue {
                    check_id: String::new(),
                    id,
                    category: "supply-chain".into(),
                    severity: Severity::Medium,
                    title: "Import is not matched to a declared or recognized local dependency".into(),
                    description: "This source import was not matched to a dependency declaration in any scanned package manifest, a scanned workspace package name, a recognized framework-provided namespace, or a parsed TypeScript path alias. It may be undeclared or misspelled, but an unsupported resolver, generated alias, parent workspace, or runtime-provided module can also explain it.".into(),
                    relative_path: package_ref.relative_path.clone(),
                    absolute_path: package_ref.absolute_path.clone(),
                    line: package_ref.line,
                    source_excerpt: excerpt_for_line(content_for(&package_ref.relative_path), package_ref.line),
                    evidence: Some(redact_evidence(format!(
                        "Import specifier '{}' was detected in source, but it was not matched to scanned dependencies, devDependencies, peerDependencies, optionalDependencies, workspace package names, recognized framework namespaces, or parsed TypeScript path aliases.",
                        package_ref.package_name
                    ))),
                    why_now: Some("A genuinely undeclared external dependency can fail in a clean install or rely on accidental local state, while an intentional alias should be explicit enough for the project resolver and CI to reproduce.".into()),
                    likely_fix: Some("Resolve the import with the project's actual package manager and build tool first. If it is an external package, confirm its identity and add it to the owning package manifest; if it is local, configure or document the workspace/path alias; if it is stale, remove the import. Do not install a similarly named package solely to clear the finding.".into()),
                    confidence,
                    confidence_reason: confidence_reason.map(|reason| reason.to_string()),
                    verify_hint: Some("Perform a frozen clean install and run the owning package's resolver, typecheck, or build. Confirm the import resolves through the intended declared package, workspace, or documented alias without pre-existing node_modules state.".into()),
                });
            }

            if let Some(expected_package) = suspicious_package_match(&package_ref.package_name) {
                let id = format!(
                    "suspicious-package:{}:{}",
                    package_ref.relative_path,
                    sanitize_identifier(&package_ref.package_name),
                );
                if seen_ids.insert(id.clone()) {
                    let (confidence, confidence_reason) = policy_confidence("suspicious-package");
                    issues.push(CodeIssue {
                        check_id: String::new(),
                        id,
                        category: "supply-chain".into(),
                        severity: Severity::Medium,
                        title: "Undeclared import resembles a popular package name".into(),
                        description: "This undeclared import is one edit or adjacent-character swap away from a curated popular package name. That string similarity is useful review evidence, but it does not prove the package exists, is installed, or is malicious. Review whether it is a typo, a workspace alias, or a module supplied by framework tooling.".into(),
                        relative_path: package_ref.relative_path.clone(),
                        absolute_path: package_ref.absolute_path.clone(),
                        line: package_ref.line,
                        source_excerpt: excerpt_for_line(content_for(&package_ref.relative_path), package_ref.line),
                        evidence: Some(redact_evidence(format!(
                            "Imported package '{}' looks very close to '{}'.",
                            package_ref.package_name, expected_package
                        ))),
                        why_now: Some("The nearest manifest does not declare this package. A clean install may fail unless a workspace alias, framework, or build tool supplies it, so confirming the resolution path avoids silently relying on local-only state.".into()),
                        likely_fix: Some(format!(
                            "Double-check the intended module. If this was meant to be the external package '{}', replace the import and pin the official package; otherwise document or configure the workspace/framework alias that resolves it.",
                            expected_package
                        )),
                        confidence,
                        confidence_reason,
                        verify_hint: Some("After fixing the import, reinstall from scratch and confirm package.json and the lockfile now point at the library you actually intended to use.".into()),
                    });
                }
            }
        }
    }

    // Workspace membership is read once per candidate workspace root; several
    // manifests share the same ancestors.
    let mut workspace_members: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

    for manifest in manifests {
        let manifest_dir = manifest.absolute_path.parent().unwrap_or(root);
        let resolved_registry_hosts = collect_lockfile_registry_hosts(manifest_dir);
        let lockfile_dir = lockfile_dir_in_scope(manifest_dir, root, &mut workspace_members);
        let has_supported_lockfile = lockfile_dir.is_some();
        let external_declared_dependencies = manifest
            .dependencies
            .iter()
            .filter(|dependency| {
                // npm workspaces let a member reference a sibling with a bare
                // `"*"`, which carries no `workspace:`/`link:` marker but still
                // resolves to a scanned local package.
                !manifest.local_dependencies.contains(*dependency)
                    && !local_package_names.contains(*dependency)
            })
            .cloned()
            .collect::<Vec<_>>();
        // Peer and optional entries are declared but not installed by this
        // package: the consuming application owns a peer install, and an
        // optional one may legitimately be absent.
        let external_installed_dependencies = external_declared_dependencies
            .iter()
            .filter(|dependency| manifest.installed_dependencies.contains(*dependency))
            .cloned()
            .collect::<Vec<_>>();

        for dependency in &external_declared_dependencies {
            let Some(spec) = manifest.dependency_specs.get(dependency) else {
                continue;
            };
            if !dependency_spec_uses_remote_url(spec) {
                continue;
            }

            let id = format!(
                "direct-url-dependency:{}:{}",
                manifest.relative_path,
                sanitize_identifier(dependency),
            );
            if seen_ids.insert(id.clone()) {
                issues.push(CodeIssue {
                    check_id: String::new(),
                    id,
                    category: "supply-chain".into(),
                    severity: Severity::Medium,
                    title: "Dependency uses a direct URL or Git source".into(),
                    description: "This dependency uses a Git or direct URL spec instead of a package-registry version. That can be intentional, but reproducibility and review depend on whether the spec resolves immutably, the lockfile captures it, credentials are kept out of the URL, and the source remains available.".into(),
                    relative_path: manifest.relative_path.clone(),
                    absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                    line: find_line(&manifest.content, dependency),
                    source_excerpt: excerpt_for_line(&manifest.content, find_line(&manifest.content, dependency)),
                    evidence: Some(redact_evidence(format!(
                        "Dependency '{}' uses a Git or direct URL source; the credential-bearing or otherwise sensitive spec is intentionally omitted from issue evidence.",
                        dependency
                    ))),
                    why_now: Some("A mutable branch, tag, or replaceable URL can change dependency bytes without a manifest edit, while embedded URL credentials can leak through source, logs, or reports.".into()),
                    likely_fix: Some("Prefer a trusted registry release when it meets the requirement. Otherwise remove credentials from the URL, pin Git sources to a full commit or direct artifacts to an independently verified digest/signature where supported, retain lockfile integrity metadata, and document the source and update owner.".into()),
                    confidence: crate::checks::IssueConfidence::High,
                    confidence_reason: None,
                    verify_hint: Some("From an isolated clean environment with approved credentials supplied out of band, run a frozen install twice and confirm the same immutable revision or digest resolves, the lockfile is unchanged, and no credential appears in the manifest, lockfile, logs, or scan output.".into()),
                });
            }
        }

        // Sample, example, and fixture apps are teaching material rather than
        // the project's shipped dependencies, and they are installed on their
        // own terms. `unbounded-dependency-range` skips the same population.
        let manifest_is_example_like = {
            let path = Path::new(&manifest.relative_path);
            is_example_like_path(path) || is_test_like_path(path)
        };

        if !external_installed_dependencies.is_empty()
            && !has_supported_lockfile
            && !manifest_is_example_like
        {
            let id = format!("lockfile-missing:{}", manifest.relative_path);
            if seen_ids.insert(id.clone()) {
                issues.push(CodeIssue {
                    check_id: String::new(),
                    id,
                    category: "supply-chain".into(),
                    severity: Severity::Medium,
                    title: "Declared npm dependencies have no recognized lockfile in scope".into(),
                    description: "This package.json declares external dependencies, but SiteCMD found no supported npm, Yarn, pnpm, or Bun lockfile in the package directory or applicable scanned workspace root. An unsupported package manager, generated lockfile, or intentionally library-only workflow may explain the absence; otherwise dependency resolution is not reproducibly captured.".into(),
                    relative_path: manifest.relative_path.clone(),
                    absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                    line: None,
                    source_excerpt: None,
                    evidence: Some(redact_evidence("External dependencies were found, but no lockfile format supported by SiteCMD was found in the package directory or applicable scanned workspace root.")),
                    why_now: Some("Without an authoritative lockfile or equivalent immutable resolution, clean installs can select different transitive versions at different times.".into()),
                    likely_fix: Some("Confirm the package manager and workspace ownership first. For an application or otherwise reproducible install, generate the native lockfile with the pinned package-manager version, review it, and make frozen installs authoritative in CI. If this is a published library that intentionally omits a lockfile, document that policy and mark the finding not applicable.".into()),
                    confidence: crate::checks::IssueConfidence::NeedsReview,
                    confidence_reason: Some("The absence of a SiteCMD-supported in-scope lockfile is factual, but unsupported, generated, parent-managed, or intentionally omitted resolution workflows may exist.".into()),
                    verify_hint: Some("In a disposable clean environment, run the package manager's frozen install and the build/tests twice. Confirm the lockfile remains unchanged and the owning package resolves through the intended workspace policy.".into()),
                });
            }
        }

        for dependency in &manifest.dependencies {
            if let Some(expected_package) = suspicious_package_match(dependency) {
                let id = format!(
                    "suspicious-manifest-package:{}:{}",
                    manifest.relative_path,
                    sanitize_identifier(dependency),
                );
                if seen_ids.insert(id.clone()) {
                    let (confidence, confidence_reason) =
                        policy_confidence("suspicious-manifest-package");
                    issues.push(CodeIssue {
                        check_id: String::new(),
                        id,
                        category: "supply-chain".into(),
                        severity: Severity::High,
                        title: "Declared dependency resembles a popular package name".into(),
                        description: "This declared dependency is one edit or adjacent-character swap away from a curated popular package name. Because it is in package.json, an install may fetch it, but name similarity alone does not prove the publisher, package contents, or intent are malicious. Verify provenance before changing or installing it.".into(),
                        relative_path: manifest.relative_path.clone(),
                        absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                        line: find_line(&manifest.content, dependency),
                        source_excerpt: excerpt_for_line(&manifest.content, find_line(&manifest.content, dependency)),
                        evidence: Some(redact_evidence(format!(
                            "Declared dependency '{}' looks very close to '{}'.",
                            dependency, expected_package
                        ))),
                        why_now: Some("The near-match name is part of the install manifest, so it can enter the dependency tree on a clean install if it resolves. This warrants prompt provenance review, not an automatic malware verdict.".into()),
                        likely_fix: Some(format!(
                            "Verify the declared package's provenance, publisher, registry, and intended use before installing it. If it is a typo for '{}', replace the name and regenerate the affected lockfile entries intentionally; if it is a legitimate distinct package, document the decision and mark the finding reviewed.",
                            expected_package
                        )),
                        confidence,
                        confidence_reason,
                        verify_hint: Some("Reinstall dependencies from a clean state and verify the package manager now resolves the intended official package.".into()),
                    });
                }
            }
        }

        // Names the in-scope lockfile resolves for this manifest. An empty set
        // means the parser could not read the lockfile, which is a parser
        // limitation rather than evidence of drift.
        let locked_packages = if has_supported_lockfile {
            crate::updates::npm::resolved_lockfile_names(manifest_dir)
        } else {
            HashSet::new()
        };

        if !locked_packages.is_empty() {
            for dependency in &external_installed_dependencies {
                if locked_packages.contains(dependency) {
                    continue;
                }
                let id = format!(
                    "lockfile-mismatch:{}:{}",
                    manifest.relative_path,
                    sanitize_identifier(dependency),
                );
                if seen_ids.insert(id.clone()) {
                    issues.push(CodeIssue {
                        check_id: String::new(),
                        id,
                        category: "supply-chain".into(),
                        severity: Severity::Medium,
                        title: "Declared dependency was not matched by the local lockfile parser".into(),
                        description: "A dependency declared in package.json was not returned as a resolved direct package by SiteCMD's parser for the in-scope lockfile. The manifest and lockfile may be out of sync, but workspace indirection, aliases, optional/platform-specific entries, unsupported lockfile details, or parser limitations can also cause the mismatch.".into(),
                        relative_path: manifest.relative_path.clone(),
                        absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                        line: find_line(&manifest.content, dependency),
                        source_excerpt: excerpt_for_line(&manifest.content, find_line(&manifest.content, dependency)),
                        evidence: Some(redact_evidence(format!(
                            "Declared dependency '{}' was found in package.json, but the local lockfile parser did not resolve it as an installed direct dependency.",
                            dependency
                        ))),
                        why_now: Some("A real manifest/lockfile mismatch can break frozen installs, while blindly regenerating a valid lockfile can create a large and risky dependency diff.".into()),
                        likely_fix: Some("Run the package manager's frozen install in a disposable clean environment first. If it succeeds, inspect workspace, alias, platform, and parser support before changing files. If it fails because the lockfile is stale, update it with the project's pinned package-manager version and review only the intended dependency-graph changes.".into()),
                        confidence: crate::checks::IssueConfidence::NeedsReview,
                        confidence_reason: Some("The parser did not match the declaration, but static lockfile parsing may not model every workspace, alias, platform, optional-dependency, or lockfile-version behavior.".into()),
                        verify_hint: Some("A frozen clean install must succeed without changing the lockfile. If an update was necessary, confirm the declared package resolves as intended, review the full diff and registry/integrity metadata, and run the build and tests.".into()),
                    });
                }
            }
        }

        if !resolved_registry_hosts.is_empty() {
            for dependency in &external_declared_dependencies {
                let Some(resolved_host) = resolved_registry_hosts.get(dependency) else {
                    continue;
                };
                // A Git or URL spec names its own source; the direct-url
                // finding above already reviews it.
                if manifest
                    .dependency_specs
                    .get(dependency)
                    .is_some_and(|spec| dependency_spec_uses_remote_url(spec))
                {
                    continue;
                }
                let allowed_hosts =
                    allowed_registry_hosts_for_dependency(dependency, &registry_config);
                if allowed_hosts.contains(resolved_host) {
                    continue;
                }
                let id = format!(
                    "registry-host-mismatch:{}:{}",
                    manifest.relative_path,
                    sanitize_identifier(dependency),
                );
                if seen_ids.insert(id.clone()) {
                    issues.push(CodeIssue {
                        check_id: String::new(),
                        id,
                        category: "supply-chain".into(),
                        severity: Severity::High,
                        title: "Dependency resolves from an unexpected registry host".into(),
                        description: "This dependency resolves from a registry host that does not match the npm registries this project appears to expect. The observed mismatch is real, but it does not prove tampering or a malicious package: an intentional private registry, caching proxy, mirror, or registry migration can produce it too.".into(),
                        relative_path: manifest.relative_path.clone(),
                        absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                        line: find_line(&manifest.content, dependency),
                        source_excerpt: excerpt_for_line(&manifest.content, find_line(&manifest.content, dependency)),
                        evidence: Some(redact_evidence(format!(
                            "Dependency '{}' resolved from '{}', but the expected registry hosts were {}.",
                            dependency,
                            resolved_host,
                            format_registry_host_list(&allowed_hosts)
                        ))),
                        why_now: Some("A lockfile can keep using an obsolete or unapproved registry after configuration changes. If the host is not intentional, clean installs can fetch code or send registry credentials across the wrong trust boundary.".into()),
                        likely_fix: Some("Build the approved default/scoped registry map from project configuration, CI, and organization policy. If the host is intentional, document it and mark the finding reviewed. If not, investigate the host and package before installing, pin the intended registry without credentials, regenerate only the affected lockfile entries with the project's package-manager version, and inspect the diff plus integrity metadata.".into()),
                        confidence: crate::checks::IssueConfidence::NeedsReview,
                        confidence_reason: Some("The resolved-host mismatch is directly observed, but the scanner cannot know the organization's approved mirrors, private registries, or migration history.".into()),
                        verify_hint: Some("Run an isolated frozen install using the approved configuration and confirm the dependency resolves from the intended host with expected integrity and contents. Review that unrelated lockfile entries and lifecycle scripts did not change or run unexpectedly.".into()),
                    });
                }
            }
        }

        if let Some(lockfile_dir) = lockfile_dir.as_deref() {
            // Count package.json script binaries as dependency usage even when
            // source files never import them.
            let script_referenced = collect_script_referenced_packages(
                &manifest.content,
                &external_installed_dependencies,
            );

            let used = external_installed_dependencies
                .iter()
                .filter(|dependency| {
                    imported_packages.contains(*dependency)
                        || script_referenced.contains(*dependency)
                        || should_ignore_unused_dependency(dependency)
                        || suspicious_package_match(dependency).is_some()
                        || extra_usage
                            .get_or_insert_with(|| collect_extra_usage_evidence(project_files))
                            .contains(*dependency)
                })
                .cloned()
                .collect::<HashSet<_>>();
            // A declared package that satisfies a used package's peer
            // requirement is used through that package. The covering lockfile
            // may sit at the workspace root; read it only once an unused
            // candidate actually appears.
            let mut peer_required: Option<HashSet<String>> = None;

            for dependency in &external_installed_dependencies {
                if used.contains(dependency) {
                    continue;
                }
                if peer_required
                    .get_or_insert_with(|| {
                        collect_lockfile_peer_dependencies(lockfile_dir)
                            .into_iter()
                            .filter(|(host, _)| used.contains(host))
                            .flat_map(|(_, peers)| peers)
                            .collect::<HashSet<_>>()
                    })
                    .contains(dependency)
                {
                    continue;
                }
                let id = format!(
                    "unused-dependency:{}:{}",
                    manifest.relative_path,
                    sanitize_identifier(dependency),
                );
                if seen_ids.insert(id.clone()) {
                    // Graded by the shared confidence policy. The search covers
                    // source, tests, mocks, fixtures, examples, configuration,
                    // and package scripts, but "unused" stays an inference:
                    // dynamic and external tooling loads packages by name.
                    let (confidence, confidence_reason) =
                        crate::core::confidence_policy::code_issue_confidence("unused-dependency");
                    issues.push(CodeIssue {
                        check_id: String::new(),
                        id,
                        category: "supply-chain".into(),
                        severity: Severity::Low,
                        title: "Declared dependency has no clear source usage".into(),
                        description: "This dependency is declared and locked, but there is no clear import or require usage in the scanned source files. Sometimes that is intentional, but it can also mean leftover packages, abandoned experiments, or install commands that were never cleaned up.".into(),
                        relative_path: manifest.relative_path.clone(),
                        absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                        line: find_line(&manifest.content, dependency),
                        source_excerpt: excerpt_for_line(&manifest.content, find_line(&manifest.content, dependency)),
                        evidence: Some(redact_evidence(format!(
                            "Dependency '{}' was declared, but nothing matched it in the scanned JavaScript, TypeScript, component, and stylesheet sources (tests, mocks, fixtures, and examples included), the quoted values of the tool configuration files that were read, this package.json's scripts, or the lockfile's peer requirements.",
                            dependency
                        ))),
                        why_now: Some("A truly unused installed package adds maintenance and install-time supply-chain surface, but configuration-only, plugin, CLI, stylesheet, generated, or runtime-loaded usage may not appear as a source import.".into()),
                        likely_fix: Some("Search package scripts, configuration, plugins, stylesheets, generated code, and runtime loading before deciding. If no supported path uses the package, remove it in a branch and update the lockfile intentionally; otherwise document the non-import usage and mark the finding reviewed.".into()),
                        confidence,
                        confidence_reason: confidence_reason.map(|reason| reason.to_string()),
                        verify_hint: Some("Remove the dependency in a branch, reinstall, and confirm the app still builds and tests cleanly.".into()),
                    });
                }
            }
        }
    }

    collect_config_secret_issues(&mut issues, &mut seen_ids, project_files, text_budget)?;

    // Evaluate alternatives per manifest; different workspace members may
    // legitimately choose different libraries.
    for manifest in manifests {
        for (group, label) in DUPLICATE_UTILITY_GROUPS {
            let matches: Vec<&&str> = group
                .iter()
                .filter(|pkg| manifest.dependencies.contains(**pkg))
                .collect();
            if matches.len() >= 2 {
                let names: Vec<String> = matches.iter().map(|s| format!("`{}`", s)).collect();
                let line = find_line(&manifest.content, matches[0]);
                issues.push(CodeIssue {
                    check_id: String::new(),
                    id: format!("duplicate-utility-deps:{}:{}", label.replace(' ', "-"), manifest.relative_path),
                    category: "supply-chain".into(),
                    severity: Severity::Low,
                    title: format!("Multiple {} libraries declared", label),
                    description: format!(
                        "This package declares {} {} libraries: {}. Multiple libraries may be intentional when they serve distinct APIs, migration stages, sub-bundles, or transitive integration requirements; declarations alone do not prove redundant runtime code.",
                        matches.len(), label, names.join(", ")
                    ),
                    relative_path: manifest.relative_path.clone(),
                    absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
                    line,
                    source_excerpt: excerpt_for_line(&manifest.content, line),
                    evidence: Some(redact_evidence(format!("Found {} {} libraries in this package.json's dependencies: {}.", matches.len(), label, names.join(", ")))),
                    // The merged dependency set includes devDependencies, so the
                    // bundle-size claim is scoped to runtime dependencies.
                    why_now: Some("Overlapping runtime use can increase maintenance and bundle cost, while forced consolidation can remove capabilities or destabilize a migration.".into()),
                    likely_fix: Some(format!("Map where each {} library is used and compare its required capabilities. If their roles overlap materially, choose a target deliberately, migrate and measure one slice at a time, then remove only the library with no remaining direct or configuration usage. If the roles differ, document them and keep both.", label)),
                    confidence: crate::checks::IssueConfidence::NeedsReview,
                    confidence_reason: Some("Multiple declarations are factual, but static manifest inspection cannot determine whether their responsibilities, bundles, or migration roles overlap.".into()),
                    verify_hint: Some("Search imports, package scripts, configuration, generated code, and bundle output for both libraries. After any removal, run the relevant behavior tests and compare bundle artifacts before marking the review complete.".into()),
                });
            }
        }
    }

    collect_workflow_pinning_issues(&mut issues, project_files);
    collect_workflow_permission_issues(&mut issues, project_files);
    collect_workflow_injection_issues(&mut issues, project_files);
    collect_workflow_pr_target_checkout_issues(&mut issues, project_files);
    collect_npmrc_token_issues(&mut issues, project_files);
    collect_dockerfile_pinning_issues(&mut issues, project_files);
    collect_pipe_to_shell_issues(&mut issues, project_files, manifests);
    collect_unbounded_dependency_issues(&mut issues, manifests, &local_package_names);
    collect_release_age_issues(&mut issues, project_files, manifests);
    collect_lockfile_integrity_issues(&mut issues, project_files);

    Ok(issues)
}
