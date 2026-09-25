//! Resolving imports and declared dependencies to something the project
//! already provides: a framework namespace, a workspace package, a TypeScript
//! path alias or `baseUrl` root, a DefinitelyTyped declaration package, or a
//! lockfile that actually covers the manifest.

use super::*;

/// Whether a declared framework provides an imported module namespace.
///
/// Framework-owned namespaces are not declared as separate app dependencies.
pub(super) fn is_framework_provided(package: &str, declared: &HashSet<String>) -> bool {
    let declares = |name: &str| declared.contains(name);
    if (declares("ember-source") || declares("ember-cli"))
        && (package.starts_with("@ember/") || package.starts_with("@glimmer/"))
    {
        return true;
    }
    if declares("vue") && package.starts_with("@vue/") {
        return true;
    }
    if declares("nuxt") && (package == "vue" || package.starts_with("@vue/")) {
        return true;
    }
    false
}

/// The directory of the supported lockfile that covers a manifest, searched
/// between the manifest and the scanned project root. This recognizes
/// workspace-root lockfiles without escaping scan scope.
///
/// An ancestor's lockfile only covers a manifest that the ancestor declares as
/// a workspace member. A nested project that merely sits below a monorepo (an
/// example or sample app) installs on its own and is not described by that
/// lockfile at all.
pub(super) fn lockfile_dir_in_scope(
    manifest_dir: &std::path::Path,
    root: &std::path::Path,
    workspace_members: &mut HashMap<PathBuf, Vec<PathBuf>>,
) -> Option<PathBuf> {
    const MAX_DEPTH: usize = 8;
    let mut current = manifest_dir.to_path_buf();
    for depth in 0..MAX_DEPTH {
        let has_lockfile = SUPPORTED_NPM_LOCKFILES
            .iter()
            .any(|name| current.join(name).exists());
        if has_lockfile {
            let covers_manifest = depth == 0
                || workspace_members
                    .entry(current.clone())
                    .or_insert_with(|| crate::updates::npm::workspace_member_dirs(&current))
                    .iter()
                    .any(|member| member == manifest_dir);
            if covers_manifest {
                return Some(current);
            }
        }
        // Stop after checking the repo root or the scan root; do not look higher.
        if current.join(".git").exists() || current == root {
            return None;
        }
        current = current.parent()?.to_path_buf();
    }
    None
}

/// The DefinitelyTyped package that supplies declarations for `package`,
/// following the `@scope/name` -> `@types/scope__name` convention.
pub(super) fn types_package_name(package: &str) -> Option<String> {
    if package.starts_with("@types/") {
        return None;
    }
    let Some(scoped) = package.strip_prefix('@') else {
        return Some(format!("@types/{}", package));
    };
    let (scope, name) = scoped.split_once('/')?;
    Some(format!("@types/{}__{}", scope, name))
}

/// Whether the importing file is TypeScript, where a `@types/*` declaration
/// package alone can resolve an import.
pub(super) fn importer_is_typescript(relative_path: &str) -> bool {
    let lower = relative_path.to_ascii_lowercase();
    [".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

/// Collect import prefixes provided by path aliases, Deno import maps, and
/// bundler aliases rather than `package.json` dependencies.
pub(super) fn collect_path_alias_prefixes(
    project_files: &[ProjectFile],
) -> std::collections::HashSet<String> {
    const MAX_CONFIG_BYTES: u64 = 256 * 1024;
    let mut prefixes = std::collections::HashSet::new();
    for file in project_files {
        let name = file
            .relative_path
            .rsplit('/')
            .next()
            .unwrap_or(file.relative_path.as_str());
        let is_ts_config = (name.starts_with("tsconfig") || name.starts_with("jsconfig"))
            && name.ends_with(".json");
        let is_deno_config = name == "deno.json" || name == "deno.jsonc";
        // Bundler configs declare `resolve.alias` mapping specifiers to local
        // files (e.g. Vite/Webpack/Rollup/Vitest/Next).
        let is_bundler_config = matches!(
            name.split('.').next(),
            Some("vite" | "vitest" | "webpack" | "rollup" | "next" | "rspack" | "rsbuild")
        ) && name.contains(".config.");
        if !is_ts_config && !is_deno_config && !is_bundler_config {
            continue;
        }
        let Some(bytes) = read_project_file(file, MAX_CONFIG_BYTES) else {
            continue;
        };
        let Ok(content) = String::from_utf8(bytes) else {
            continue;
        };
        for line in content.lines() {
            let prefix = if is_deno_config {
                deno_import_prefix_from_line(line)
            } else if is_bundler_config {
                bundler_alias_prefix_from_line(line)
            } else {
                path_alias_prefix_from_line(line)
            };
            if let Some(prefix) = prefix {
                prefixes.insert(prefix);
            }
        }
    }
    prefixes
}

/// Import prefixes a tsconfig `baseUrl` provides, paired with the directory
/// the config governs.
///
/// `baseUrl` makes every directory under it importable by bare specifier, with
/// no `paths` entry involved. Unlike a `paths` alias, these are scoped: a
/// tsconfig deep in a monorepo would otherwise silence an undeclared import
/// anywhere in the repository that happened to share a directory name with one
/// of its own folders.
pub(super) fn collect_base_url_prefixes(
    project_files: &[ProjectFile],
) -> Vec<(String, std::collections::HashSet<String>)> {
    const MAX_CONFIG_BYTES: u64 = 256 * 1024;
    let mut scopes = Vec::new();
    for file in project_files {
        let name = file
            .relative_path
            .rsplit('/')
            .next()
            .unwrap_or(file.relative_path.as_str());
        let is_ts_config = (name.starts_with("tsconfig") || name.starts_with("jsconfig"))
            && name.ends_with(".json");
        if !is_ts_config {
            continue;
        }
        let Some(bytes) = read_project_file(file, MAX_CONFIG_BYTES) else {
            continue;
        };
        let Ok(content) = String::from_utf8(bytes) else {
            continue;
        };
        let Some(base_url) = content.lines().find_map(base_url_from_line) else {
            continue;
        };
        let prefixes = base_url_directory_prefixes(&file.relative_path, &base_url, project_files);
        if prefixes.is_empty() {
            continue;
        }
        let scope = file
            .relative_path
            .rsplit_once('/')
            .map(|(directory, _)| format!("{}/", directory))
            .unwrap_or_default();
        scopes.push((scope, prefixes));
    }
    scopes
}

/// Extract a `compilerOptions.baseUrl` value.
fn base_url_from_line(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(r#""baseUrl""#)?;
    let value = rest.strip_prefix(':')?.trim().trim_end_matches(',').trim();
    let base_url = serde_json::from_str::<String>(value).ok()?;
    let trimmed = base_url.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Top-level directory names under a tsconfig's `baseUrl`, which resolve as
/// bare import specifiers for every file that config covers.
fn base_url_directory_prefixes(
    config_relative_path: &str,
    base_url: &str,
    project_files: &[ProjectFile],
) -> std::collections::HashSet<String> {
    let config_dir = config_relative_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("");
    let mut segments = config_dir
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for segment in base_url.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return std::collections::HashSet::new();
                }
            }
            other => segments.push(other.to_string()),
        }
    }
    let base = segments.join("/");
    let prefix = if base.is_empty() {
        String::new()
    } else {
        format!("{}/", base)
    };

    // Borrow while scanning and allocate once per distinct directory: a
    // repo-root `baseUrl` matches every project file.
    let directories = project_files
        .iter()
        .filter_map(|file| {
            let rest = file.relative_path.strip_prefix(prefix.as_str())?;
            let (directory, _) = rest.split_once('/')?;
            (!directory.is_empty()).then_some(directory)
        })
        .collect::<std::collections::HashSet<_>>();
    directories
        .into_iter()
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Extract the first import segment from a `resolve.alias` entry whose value
/// references a local filesystem path.
fn bundler_alias_prefix_from_line(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix('"').or_else(|| line.strip_prefix('\''))?;
    let quote = if line.starts_with('"') { '"' } else { '\'' };
    let end = rest.find(quote)?;
    let key = &rest[..end];
    let after = rest[end + 1..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let lower = after.to_ascii_lowercase();
    let references_local_path = lower.starts_with("path.resolve")
        || lower.starts_with("path.join")
        || lower.starts_with("__dirname")
        || lower.starts_with("fileurltopath")
        || lower.starts_with("new url(")
        || lower.starts_with("resolve(")
        || lower.starts_with("\"./")
        || lower.starts_with("\"../")
        || lower.starts_with("'./")
        || lower.starts_with("'../");
    if !references_local_path {
        return None;
    }
    // Reduce the key to its first segment, mirroring import normalization:
    // `@scope/name` keeps two segments, otherwise just the first path segment.
    let prefix = if let Some(scoped) = key.strip_prefix('@') {
        let mut segments = scoped.split('/');
        let scope = segments.next()?;
        match segments.next() {
            Some(pkg) if !pkg.is_empty() => format!("@{}/{}", scope, pkg),
            _ => format!("@{}", scope),
        }
    } else {
        key.split('/').next()?.to_string()
    };
    let prefix = prefix.trim_end_matches('*').trim_end_matches('/');
    if prefix.is_empty() {
        return None;
    }
    Some(prefix.to_ascii_lowercase())
}

/// Extract a Deno import-map alias from a module-specifier entry.
fn deno_import_prefix_from_line(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix('"')?;
    let end = rest.find('"')?;
    let key = &rest[..end];
    let after = rest[end + 1..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let value = after.strip_prefix('"')?;
    let value = &value[..value.find('"')?];
    let is_specifier = ["jsr:", "npm:", "https://", "http://", "./", "../", "node:"]
        .iter()
        .any(|scheme| value.starts_with(scheme));
    if !is_specifier {
        return None;
    }
    let prefix = key.trim_end_matches('/');
    if prefix.is_empty() {
        return None;
    }
    Some(prefix.to_ascii_lowercase())
}

/// Extract an alias-marked `compilerOptions.paths` key without its trailing glob.
fn path_alias_prefix_from_line(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix('"')?;
    let end = rest.find('"')?;
    let key = &rest[..end];
    let after = rest[end + 1..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    if !after.starts_with('[') {
        return None;
    }
    let looks_like_alias =
        key.contains('*') || key.contains('/') || key.starts_with('@') || key.starts_with('~');
    if !looks_like_alias {
        return None;
    }
    let prefix = key.trim_end_matches('*').trim_end_matches('/');
    if prefix.is_empty() {
        return None;
    }
    Some(prefix.to_ascii_lowercase())
}

#[cfg(test)]
mod path_alias_tests {
    use super::{
        base_url_directory_prefixes, base_url_from_line, importer_is_typescript,
        is_framework_provided, path_alias_prefix_from_line, types_package_name, ProjectFile,
    };
    use std::collections::HashSet;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn types_packages_follow_the_definitely_typed_naming_convention() {
        assert_eq!(
            types_package_name("express").as_deref(),
            Some("@types/express")
        );
        assert_eq!(types_package_name("mdx").as_deref(), Some("@types/mdx"));
        assert_eq!(
            types_package_name("@babel/core").as_deref(),
            Some("@types/babel__core")
        );
        // A types package does not need a types package of its own.
        assert_eq!(types_package_name("@types/node"), None);
        assert_eq!(types_package_name("@scopeonly"), None);
    }

    #[test]
    fn only_typescript_importers_resolve_through_types_packages() {
        assert!(importer_is_typescript("src/main.ts"));
        assert!(importer_is_typescript("src/App.TSX"));
        assert!(importer_is_typescript("config/build.mts"));
        assert!(!importer_is_typescript("src/main.js"));
        assert!(!importer_is_typescript("src/App.jsx"));
    }

    #[test]
    fn base_url_values_are_read_and_resolved_to_directories() {
        assert_eq!(
            base_url_from_line(r#"    "baseUrl": ".","#).as_deref(),
            Some(".")
        );
        assert_eq!(
            base_url_from_line(r#""baseUrl": "./src""#).as_deref(),
            Some("./src")
        );
        assert_eq!(base_url_from_line(r#""strict": true,"#), None);
        assert_eq!(base_url_from_line(r#""paths": {"#), None);
    }

    #[test]
    fn framework_provided_namespaces() {
        let ember = set(&["ember-source"]);
        assert!(is_framework_provided("@ember/component", &ember));
        assert!(is_framework_provided("@glimmer/tracking", &ember));
        assert!(!is_framework_provided("@vue/reactivity", &ember));

        // Vue provides its own @vue/* internals; Nuxt bundles vue itself.
        let vue = set(&["vue"]);
        assert!(is_framework_provided("@vue/reactivity", &vue));
        assert!(!is_framework_provided("vue", &vue)); // declared directly anyway
        let nuxt = set(&["nuxt"]);
        assert!(is_framework_provided("vue", &nuxt));
        assert!(is_framework_provided("@vue/runtime-core", &nuxt));

        // A real third-party package is never framework-provided.
        assert!(!is_framework_provided("lodash", &nuxt));
        assert!(!is_framework_provided("@ember/component", &set(&[])));
    }

    #[test]
    fn extracts_alias_prefixes_and_ignores_plain_keys() {
        assert_eq!(
            path_alias_prefix_from_line(r#"      "@ui/*": ["./src/*"],"#),
            Some("@ui".to_string())
        );
        assert_eq!(
            path_alias_prefix_from_line(r#""@utils/*": ["./utils/*"]"#),
            Some("@utils".to_string())
        );
        assert_eq!(
            path_alias_prefix_from_line(r#""components/*": ["src/components/*"]"#),
            Some("components".to_string())
        );
        // Non-alias tsconfig keys (arrays, but no alias marker) are ignored.
        assert_eq!(path_alias_prefix_from_line(r#""types": ["node"]"#), None);
        assert_eq!(path_alias_prefix_from_line(r#""lib": ["ESNext"]"#), None);
        // Non-paths lines are ignored.
        assert_eq!(path_alias_prefix_from_line(r#""strict": true,"#), None);
        assert_eq!(path_alias_prefix_from_line("// a comment"), None);
    }

    #[test]
    fn extracts_deno_import_map_prefixes() {
        use super::deno_import_prefix_from_line;
        assert_eq!(
            deno_import_prefix_from_line(r#"    "@std/path": "jsr:@std/path@^1.0.0","#),
            Some("@std/path".to_string())
        );
        assert_eq!(
            deno_import_prefix_from_line(r#""preact": "npm:preact@^10.0.0""#),
            Some("preact".to_string())
        );
        assert_eq!(
            deno_import_prefix_from_line(r#""$fresh/": "./fresh/""#),
            Some("$fresh".to_string())
        );
        // Tasks / config entries (value is not a module specifier) are ignored.
        assert_eq!(
            deno_import_prefix_from_line(r#""dev": "deno run -A main.ts""#),
            None
        );
        assert_eq!(deno_import_prefix_from_line(r#""name": "my-app""#), None);
    }

    #[test]
    fn extracts_bundler_alias_prefixes() {
        use super::bundler_alias_prefix_from_line;
        // Vite/Webpack alias to a local shim -- reduced to first segment so it
        // matches an import that normalizes to that segment (plane: next/link).
        assert_eq!(
            bundler_alias_prefix_from_line(
                r#"      "next/link": path.resolve(__dirname, "app/compat/next/link.tsx"),"#
            ),
            Some("next".to_string())
        );
        assert_eq!(
            bundler_alias_prefix_from_line(
                r#""@/components": path.join(__dirname, "src/components")"#
            ),
            Some("@/components".to_string())
        );
        assert_eq!(
            bundler_alias_prefix_from_line(r#"'~': './src'"#),
            Some("~".to_string())
        );
        // Non-alias config (value is not a local path) is ignored.
        assert_eq!(
            bundler_alias_prefix_from_line(
                r#""process.env.NODE_ENV": JSON.stringify("production")"#
            ),
            None
        );
        assert_eq!(bundler_alias_prefix_from_line(r#""port": 3000"#), None);
    }

    #[test]
    fn base_url_directories_become_alias_prefixes() {
        let files = [
            "types/index.d.ts",
            "config/site.ts",
            "app/page.tsx",
            "README.md",
        ]
        .iter()
        .map(|relative| ProjectFile {
            absolute_path: std::path::PathBuf::from("/tmp").join(relative),
            relative_path: (*relative).to_string(),
            size: 10,
        })
        .collect::<Vec<_>>();

        let prefixes = base_url_directory_prefixes("tsconfig.json", ".", &files);
        assert_eq!(prefixes, set(&["types", "config", "app"]));
        // A root-level file is not a directory, so it is not a prefix.
        assert!(!prefixes.contains("readme.md"));

        // A nested config's baseUrl resolves relative to that config.
        let nested = [
            "apps/web/src/lib/util.ts",
            "apps/web/src/ui/button.tsx",
            "apps/api/src/main.ts",
        ]
        .iter()
        .map(|relative| ProjectFile {
            absolute_path: std::path::PathBuf::from("/tmp").join(relative),
            relative_path: (*relative).to_string(),
            size: 10,
        })
        .collect::<Vec<_>>();
        assert_eq!(
            base_url_directory_prefixes("apps/web/tsconfig.json", "./src", &nested),
            set(&["lib", "ui"])
        );
    }
}
