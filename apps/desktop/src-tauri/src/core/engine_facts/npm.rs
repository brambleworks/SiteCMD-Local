use crate::core::engine_facts::inventory::{offer_path, FileOffers, NativeOffer};
use crate::core::project_listing::ProjectListing;
use crate::core::safe_fs::open_project_dir;
use crate::core::scan_scope::has_git_entry;
use sitecmd_protocol::engine_abi::{
    AuditFailure, AuditFileKind, AuditNpmAncestor, EntryKind, RelPath,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

const LOCKFILE_DEPTH: usize = 8;
const ROOT_ONLY_FILES: &[&str] = &[".npmrc"];
const WORKSPACE_MANIFESTS: &[&str] = &["package.json", "pnpm-workspace.yaml", "pnpm-workspace.yml"];
const TEXT_LOCKFILES: &[&str] = &["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];
const BUN_LOCKFILES: &[&str] = &["bun.lock", "bun.lockb"];
const GIT_MARKER: &str = ".git";

pub(super) fn npm_facts(
    listing: &ProjectListing,
    files: &mut FileOffers<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<AuditNpmAncestor>, AuditFailure> {
    let root = listing.root();
    let mut dirs: BTreeSet<_> = listing
        .wire()
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .map(|entry| root.join(entry.path.as_str()))
        .chain(
            listing
                .unlisted_files()
                .map(|(_, file)| root.join(&file.relative)),
        )
        .filter(|path| path.file_name().is_some_and(|name| name == "package.json"))
        .filter_map(|path| path.parent().map(Path::to_owned))
        .collect();
    let has_manifests = !dirs.is_empty();
    dirs.insert(root.to_owned());
    let candidates: BTreeSet<_> = dirs
        .iter()
        .flat_map(|dir| {
            dir.ancestors()
                .take(LOCKFILE_DEPTH)
                .take_while(|path| path.starts_with(root))
        })
        .collect();
    for directory in candidates {
        check_cancelled(cancelled)?;
        let readable = ROOT_ONLY_FILES
            .iter()
            .chain(WORKSPACE_MANIFESTS)
            .chain(TEXT_LOCKFILES);
        for name in readable {
            let path = directory.join(name);
            if !listing.is_omitted(&path) {
                continue;
            }
            files.path(listing, &path);
            if let Some(metadata) = regular_file(&path) {
                let Ok(relative) = path.strip_prefix(root) else {
                    continue;
                };
                files.add(
                    &offer_path(relative),
                    AuditFileKind::Dependency {},
                    metadata.len(),
                    NativeOffer::Dependency(relative.to_owned()),
                );
            }
        }
        for name in BUN_LOCKFILES.iter().copied().chain([GIT_MARKER]) {
            files.path(listing, &directory.join(name));
        }
    }

    let mut ancestors = Vec::new();
    if !has_manifests || listing.has_git_entry() {
        return Ok(ancestors);
    }
    for (levels, directory) in root.ancestors().enumerate().take(LOCKFILE_DEPTH).skip(1) {
        check_cancelled(cancelled)?;
        let Ok(dir) = open_project_dir(directory) else {
            break;
        };
        let dir = Arc::new(dir);
        let lockfiles = TEXT_LOCKFILES.iter().chain(BUN_LOCKFILES);
        if lockfiles
            .clone()
            .any(|name| dir.symlink_metadata(name).is_ok_and(|m| m.is_file()))
        {
            let mut present = Vec::new();
            let readable = WORKSPACE_MANIFESTS.iter().chain(TEXT_LOCKFILES);
            for name in readable {
                if let Ok(metadata) = dir.symlink_metadata(name) {
                    if metadata.is_file() {
                        present.extend(RelPath::parse(name));
                        files.add(
                            &format!("{}{name}", "../".repeat(levels)),
                            AuditFileKind::Dependency {},
                            metadata.len(),
                            NativeOffer::Ancestor {
                                directory: Arc::clone(&dir),
                                path: directory.join(name),
                            },
                        );
                    }
                }
            }
            for name in BUN_LOCKFILES {
                if dir
                    .symlink_metadata(name)
                    .is_ok_and(|metadata| metadata.is_file())
                {
                    present.extend(RelPath::parse(name));
                }
            }
            ancestors.push(AuditNpmAncestor {
                levels: levels as u8,
                present,
            });
        }
        if has_git_entry(&dir) {
            break;
        }
    }
    Ok(ancestors)
}

fn regular_file(path: &Path) -> Option<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).ok()?;
    metadata.is_file().then_some(metadata)
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), AuditFailure> {
    if cancelled() {
        Err(AuditFailure::Cancelled)
    } else {
        Ok(())
    }
}
