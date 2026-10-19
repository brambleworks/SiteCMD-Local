use super::scan_scope::{self, GitignoreChain};
use super::types::CodeScanSkippedScopes;
use super::{is_example_like_path, is_test_like_path};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(super) struct SourceFile {
    pub(super) absolute_path: PathBuf,
    pub(super) relative_path: String,
    pub(super) content: String,
    pub(super) line_count: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ProjectFile {
    pub(super) absolute_path: PathBuf,
    pub(super) relative_path: String,
    pub(super) size: u64,
}

#[derive(Debug, Clone)]
pub(super) struct ProjectInventory {
    pub(super) source_files: Vec<SourceFile>,
    pub(super) project_files: Vec<ProjectFile>,
    /// Directories the walk refused to descend into.
    pub(super) skipped_scopes: CodeScanSkippedScopes,
}

const MAX_FILE_BYTES: u64 = 1_000_000;
const DEFAULT_COLLECTION_LIMITS: CollectionLimits = CollectionLimits {
    // Source files actually read and analyzed. Source files beyond this are
    // skipped (not fatal); non-source files never count toward it.
    max_files: 5_000,
    // Bound traversal separately from source files selected for analysis.
    max_total_files: 100_000,
    max_total_bytes: crate::constants::CODE_SCAN_MAX_TEXT_BYTES,
    max_depth: 48,
};

#[derive(Debug, Clone, Copy)]
struct CollectionLimits {
    max_files: usize,
    max_total_files: usize,
    max_total_bytes: u64,
    max_depth: usize,
}

#[derive(Debug, Default)]
struct CollectionState {
    total_bytes: u64,
    visited_files: usize,
    skipped_scopes: CodeScanSkippedScopes,
}

static IGNORED_DIRS: &[&str] = &[
    ".git",
    ".next",
    ".open-next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".vercel",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "target",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    // Drupal dev environment + generic IDE/container caches
    ".ddev",
    ".docker",
    ".idea",
    ".vscode",
    ".vagrant",
];

/// Project-relative prefixes for vendored or generated third-party code.
static IGNORED_PATH_PREFIXES: &[&str] = &[
    // Drupal (composer-managed web-root layout - the current default)
    "web/core",
    "web/modules/contrib",
    "web/themes/contrib",
    "web/profiles/contrib",
    "web/libraries",
    "web/sites/default/files",
    // Drupal (legacy docroot-at-root layout)
    "docroot/core",
    "docroot/modules/contrib",
    "docroot/themes/contrib",
    "docroot/profiles/contrib",
    "docroot/libraries",
    "docroot/sites/default/files",
    // WordPress core + generated content. We intentionally do NOT skip
    // `wp-content/plugins` or `wp-content/themes` because those directories
    // commonly hold the site's first-party code.
    "wp-admin",
    "wp-includes",
    "wp-content/uploads",
    // Generic
    "public/build",
    "public/vendor",
];

/// Returns true if `path` sits under a vendored / third-party path prefix
/// relative to the project `root`. The prefix is matched as an exact segment
/// boundary so `web/core` does not accidentally match `web/core_custom`.
pub(super) fn is_vendored_path(root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return false;
    };
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    IGNORED_PATH_PREFIXES
        .iter()
        .any(|prefix| rel_str == *prefix || rel_str.starts_with(&format!("{}/", prefix)))
}

/// Files drupal/core-composer-scaffold copies into every site unchanged. They
/// are core's documentation, not the project's code, so they stay in the
/// inventory but never receive first-party findings.
static DRUPAL_SCAFFOLD_BASENAMES: &[&str] = &[
    "default.settings.php",
    "default.services.yml",
    "example.settings.local.php",
    "example.sites.php",
];

/// Returns true for a Drupal scaffold file under a `sites/` directory.
pub(super) fn is_drupal_scaffold_file(relative_path: &str) -> bool {
    let normalized = relative_path.replace('\\', "/");
    let Some((directory, basename)) = normalized.rsplit_once('/') else {
        return false;
    };
    DRUPAL_SCAFFOLD_BASENAMES.contains(&basename)
        && directory.split('/').any(|segment| segment == "sites")
}

/// Return whether the walker must skip ignored, vendored, or disabled paths.
pub(super) fn should_skip_walker_dir(root: &Path, path: &Path, file_name: &str) -> bool {
    if IGNORED_DIRS.contains(&file_name) {
        return true;
    }
    if file_name.ends_with(".disabled") {
        return true;
    }
    is_vendored_path(root, path)
}

/// Reject symlinks and unknown entry types before reading untrusted projects.
/// This prevents filesystem escape and directory cycles.
pub(super) fn is_symlink_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_type()
        .map(|file_type| file_type.is_symlink())
        .unwrap_or(true)
}

static SOURCE_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "php", "rb", "go", "rs",
];

/// Live framework config files that remain scan inputs even when gitignored.
static DEPLOYED_CONFIG_BASENAMES: &[&str] = &[
    "wp-config.php",
    "settings.php",
    "settings.local.php",
    "settings.py",
    "local_settings.py",
];

fn is_deployed_config_basename(file_name: &str) -> bool {
    DEPLOYED_CONFIG_BASENAMES
        .iter()
        .any(|candidate| file_name.eq_ignore_ascii_case(candidate))
}

pub(super) static JS_SOURCE_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];

#[cfg(test)]
pub(super) fn collect_source_files(
    root: &Path,
    _current: &Path,
    out: &mut Vec<SourceFile>,
) -> Result<(), String> {
    let inventory = collect_project_inventory(root)?;
    out.extend(inventory.source_files);
    Ok(())
}

pub(super) fn collect_project_inventory(root: &Path) -> Result<ProjectInventory, String> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|e| format!("Could not resolve project root {}: {}", root.display(), e))?;
    let mut source_files = Vec::new();
    let mut project_files = Vec::new();
    let mut state = CollectionState::default();
    let scope = GitignoreChain::for_root(root);
    collect_project_inventory_with_limits(
        root,
        &canonical_root,
        root,
        &scope,
        &mut source_files,
        &mut project_files,
        DEFAULT_COLLECTION_LIMITS,
        &mut state,
        0,
    )?;
    Ok(ProjectInventory {
        source_files,
        project_files,
        skipped_scopes: state.skipped_scopes,
    })
}

/// The scan-root-relative directory name used in the skipped-scope sample, so
/// the note reads "skipped: apps/api" rather than an absolute path. Falls back
/// to the final path component when the path is not under `root`.
fn skipped_dir_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .filter(|label| !label.is_empty())
        .or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_default()
}

fn collect_project_inventory_with_limits(
    root: &Path,
    canonical_root: &Path,
    current: &Path,
    scope: &GitignoreChain<'_>,
    source_files: &mut Vec<SourceFile>,
    project_files: &mut Vec<ProjectFile>,
    limits: CollectionLimits,
    state: &mut CollectionState,
    depth: usize,
) -> Result<(), String> {
    if depth > limits.max_depth {
        return Err(format!(
            "Code Scan stopped because the project folder is nested deeper than {} directories. Choose a smaller project root or exclude generated folders.",
            limits.max_depth
        ));
    }
    let entries = fs::read_dir(current)
        .map_err(|e| format!("Could not read {}: {}", current.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
        let path = entry.path();
        if is_symlink_entry(&entry) {
            continue;
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if path.is_dir() {
            if should_skip_walker_dir(root, &path, &file_name) {
                continue;
            }
            // Do not descend into nested repositories; only the scan root is
            // part of this project.
            if scan_scope::has_git_entry(&path) {
                state
                    .skipped_scopes
                    .record_nested_repository(skipped_dir_label(root, &path));
                continue;
            }
            // Skip ignored directory trees before traversal to preserve walk
            // budgets; individually ignored files remain inventoried.
            if scope.is_ignored(&path, true) {
                state
                    .skipped_scopes
                    .record_gitignored_directory(skipped_dir_label(root, &path));
                continue;
            }
            let child_scope = scope.enter(root, &path);
            collect_project_inventory_with_limits(
                root,
                canonical_root,
                &path,
                &child_scope,
                source_files,
                project_files,
                limits,
                state,
                depth + 1,
            )?;
            continue;
        }

        if state.visited_files >= limits.max_total_files {
            return Err(format!(
                "Code Scan stopped after reaching the {} project-file budget. Choose a smaller project root or exclude generated folders.",
                limits.max_total_files
            ));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let canonical_path = match fs::canonicalize(&path) {
            Ok(path) if path.starts_with(canonical_root) => path,
            _ => continue,
        };
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        state.visited_files += 1;
        let project_file = ProjectFile {
            absolute_path: canonical_path.clone(),
            relative_path: relative_path.clone(),
            size: metadata.len(),
        };
        project_files.push(project_file.clone());

        // Keep ignored files in inventory for manifest and opted-in database checks,
        // but do not analyze them as source. Deployed config files are exempt.
        if scope.is_ignored(&path, false) && !is_deployed_config_basename(&file_name) {
            continue;
        }

        let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !SOURCE_EXTENSIONS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(ext))
        {
            continue;
        }
        if file_name.contains(".min.")
            || file_name.ends_with(".d.ts")
            || is_test_like_path(&path)
            || is_example_like_path(&path)
            || is_drupal_scaffold_file(&relative_path)
        {
            continue;
        }

        // Stop reading source at the budget while continuing the inventory walk.
        if source_files.len() >= limits.max_files {
            continue;
        }

        if metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let bytes = match read_project_file(&project_file, MAX_FILE_BYTES) {
            Some(bytes) => bytes,
            None => continue,
        };
        if bytes.contains(&0) {
            continue;
        }

        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) => continue,
        };
        let content = sanitize_source_content(&path, content);

        // A Rust file that is entirely `#![cfg(test)]` (the #[path] sibling
        // test-file convention) is test code whatever its name; excluded the
        // same way path-named test files are (see is_test_like_path).
        if scan_scope::is_rust_test_only_file(&path, &content) {
            continue;
        }

        // Keep vendored bundles in inventory but exclude them from first-party
        // analysis, including unminified bundles and minified files without `.min.`.
        if super::vendored::looks_like_vendored_library(&content) {
            continue;
        }

        state.total_bytes = state.total_bytes.saturating_add(content.capacity() as u64);
        if state.total_bytes > limits.max_total_bytes {
            return Err(format!(
                "Code Scan stopped after reaching the {} byte source budget. Choose a smaller project root or exclude generated folders.",
                limits.max_total_bytes
            ));
        }

        source_files.push(SourceFile {
            absolute_path: canonical_path,
            relative_path,
            line_count: content.lines().count(),
            content,
        });
    }
    Ok(())
}

pub(super) fn read_project_file(file: &ProjectFile, max_bytes: u64) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(&file.absolute_path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    if fs::canonicalize(&file.absolute_path).ok()? != file.absolute_path {
        return None;
    }
    crate::core::safe_fs::read_bounded_file(&file.absolute_path, max_bytes)
}

/// Test-only byte-level wrapper for the shared bounded project reader.
/// Production fixed-path text reads use `read_text_under_root` below.
#[cfg(test)]
pub(super) fn read_under_root(root: &Path, path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    crate::core::safe_fs::read_bounded_file_under_root(root, path, max_bytes)
}

/// `read_under_root` for UTF-8 text, capped at `MAX_FILE_BYTES`. Returns `None`
/// for non-UTF-8 or oversized content.
pub(super) fn read_text_under_root(root: &Path, path: &Path) -> Option<String> {
    crate::core::safe_fs::read_bounded_text_under_root(root, path, MAX_FILE_BYTES)
}

fn sanitize_source_content(path: &Path, content: String) -> String {
    let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
        return content;
    };
    if !ext.eq_ignore_ascii_case("rs") {
        return content;
    }
    strip_rust_test_module(&content).unwrap_or(content)
}

fn strip_rust_test_module(content: &str) -> Option<String> {
    let mut offset = 0usize;
    let mut cfg_test_offset: Option<usize> = None;

    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let trimmed = trimmed.trim_end_matches(['\r', '\n']);

        if trimmed.starts_with("#[cfg(test)]") {
            cfg_test_offset = Some(offset);
            offset += line.len();
            continue;
        }

        if trimmed.starts_with("mod tests") && trimmed.contains('{') {
            let start = cfg_test_offset.unwrap_or(offset);
            return Some(content[..start].to_string());
        }

        if !trimmed.is_empty() && !trimmed.starts_with("//") {
            cfg_test_offset = None;
        }

        offset += line.len();
    }

    None
}

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
