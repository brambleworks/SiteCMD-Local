//! Names and path prefixes pruned from project walks.

use std::path::Path;

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

/// Returns true if a project-relative path sits under a vendored path prefix.
/// The prefix is matched as an exact segment
/// boundary so `web/core` does not accidentally match `web/core_custom`.
pub fn is_vendored_path(relative: &Path) -> bool {
    let rel_str = relative.to_string_lossy().replace('\\', "/");
    IGNORED_PATH_PREFIXES
        .iter()
        .any(|prefix| rel_str == *prefix || rel_str.starts_with(&format!("{}/", prefix)))
}

/// Return whether the walker must skip ignored, vendored, or disabled paths.
pub fn should_skip_walker_dir(relative: &Path, file_name: &str) -> bool {
    if IGNORED_DIRS.contains(&file_name) {
        return true;
    }
    if file_name.ends_with(".disabled") {
        return true;
    }
    is_vendored_path(relative)
}
