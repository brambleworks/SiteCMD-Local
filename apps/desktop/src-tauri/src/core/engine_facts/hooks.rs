//! Whether a checked-in hook configuration is actually active in this clone.
//!
//! Husky, Lefthook, pre-commit, and simple-git-hooks all need an install step
//! that writes into `.git/hooks` or points `core.hooksPath` at their runtime
//! directory. A committed config without that step protects nothing.

use crate::core::project_listing::ProjectListing;
use sitecmd_protocol::engine_abi::{AuditHooks, AuditPathKind, AUDIT_MAX_FILE_BYTES};
use std::path::Path;

const NATIVE_HOOK_NAMES: &[&str] = &["pre-commit", "pre-push", "commit-msg", "pre-merge-commit"];

pub(super) fn inspect_hook_install(listing: &ProjectListing) -> AuditHooks {
    let root = listing.root();
    let git = root.join(".git");
    // An unresolved link counts only at the hook marker itself.
    if !matches!(
        listing.observed_kind(&git),
        Some(AuditPathKind::Directory | AuditPathKind::Symlink)
    ) {
        return AuditHooks::default();
    }
    let hooks_dir = git.join("hooks");
    let native_hooks = NATIVE_HOOK_NAMES
        .iter()
        .copied()
        .filter(|name| {
            matches!(
                listing.observed_kind(&hooks_dir.join(name)),
                Some(AuditPathKind::File | AuditPathKind::Symlink)
            )
        })
        .map(str::to_owned)
        .collect();
    let husky_runtime = matches!(
        listing.observed_kind(&root.join(".husky/_")),
        Some(AuditPathKind::Directory | AuditPathKind::Symlink)
    );
    // Only the presence of the key is inspected; the config text is never
    // surfaced because remote URLs can embed credentials.
    let hooks_path_configured = listing
        .read_relative_file(Path::new(".git/config"), AUDIT_MAX_FILE_BYTES)
        .ok()
        .filter(|bytes| bytes.len() as u64 <= AUDIT_MAX_FILE_BYTES)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|config| config.to_ascii_lowercase().contains("hookspath"));
    AuditHooks {
        git_dir: true,
        native_hooks,
        husky_runtime,
        hooks_path_configured,
    }
}
