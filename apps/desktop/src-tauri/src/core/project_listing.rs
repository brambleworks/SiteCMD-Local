//! Bounded inventories of local project trees.

use crate::core::safe_fs::{
    open_project_dir, open_project_subdir, project_path_is_symlink, project_path_type,
    read_project_path,
};
use crate::core::scan_scope::{has_git_entry, GitignoreChain};
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use sitecmd_engine_host::walker_pruning::should_skip_walker_dir;
use sitecmd_protocol::engine_abi::{
    AuditPathKind, EntryKind, Listing, ListingEntry, RelPath, SkippedScopes,
};
use sitecmd_protocol::project_paths::{ListedPaths, OmittedPaths, ProjectPaths};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{fs, io};

mod file_order;
mod probe_facts;
use crate::core::project_listing::probe_facts::disk_children;

pub(super) const MAX_PROJECT_FILES: usize = 100_000;
pub(super) const MAX_PROJECT_DEPTH: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum ListingError {
    #[error("Could not resolve project root {path}: {source}")]
    Root { path: PathBuf, source: io::Error },
    #[error("Could not read {path}: {source}")]
    Directory { path: PathBuf, source: io::Error },
    #[error("Directory entry error: {0}")]
    Entry(io::Error),
    #[error("Code Scan stopped because the project folder is nested deeper than {0} directories. Choose a smaller project root or exclude generated folders.")]
    Depth(usize),
    #[error("Code Scan stopped after reaching the {0} project-file budget. Choose a smaller project root or exclude generated folders.")]
    Files(usize),
}

#[derive(Debug)]
pub struct ProjectListing {
    wire: Listing,
    root: PathBuf,
    dir: Dir,
    files: Vec<NativeFile>,
    listed_files: HashMap<RelPath, usize>,
    omitted: HashMap<PathBuf, HashSet<OsString>>,
    native_aliases: HashMap<RelPath, PathBuf>,
    skipped_scopes: SkippedScopes,
}

impl ProjectListing {
    pub fn wire(&self) -> &Listing {
        &self.wire
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn observed_kind(&self, path: &Path) -> Option<AuditPathKind> {
        self.paths().kind(path)
    }

    pub(super) fn observed_children(&self, path: &Path) -> Vec<PathBuf> {
        self.paths().children(path)
    }

    pub(super) fn observed_safe_directory(&self, path: &Path) -> bool {
        self.paths().safe_directory(path)
    }

    pub(super) fn read_relative_file(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        read_project_path(&self.dir, path, limit)
    }

    pub(crate) fn contains_symlink(&self, path: &RelPath) -> bool {
        let relative = Path::new(path.as_str());
        (self.wire.get(path).is_some() || self.is_omitted(&self.root.join(relative)))
            && project_path_is_symlink(&self.dir, relative)
    }

    pub(super) fn probe_path(&self, path: &RelPath) -> Option<AuditPathKind> {
        project_path_type(&self.dir, &self.root, Path::new(path.as_str())).ok()
    }

    pub(super) fn audit_skipped_scopes(&self) -> SkippedScopes {
        self.skipped_scopes.clone()
    }

    pub(super) fn has_git_entry(&self) -> bool {
        has_git_entry(&self.dir)
    }

    fn paths(&self) -> ListedPaths<'_> {
        ListedPaths::new(self.wire(), self.root(), self)
    }

    #[cfg(feature = "test-support")]
    pub(super) fn has_file(&self, path: &Path) -> bool {
        self.paths().kind(path) == Some(AuditPathKind::File)
    }

    pub(super) fn is_omitted(&self, path: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return true;
        };
        !relative.as_os_str().is_empty()
            && (listing_path(relative).is_none()
                || relative.ancestors().any(|ancestor| {
                    ancestor
                        .parent()
                        .zip(ancestor.file_name())
                        .is_some_and(|(parent, name)| {
                            self.omitted
                                .get(parent)
                                .is_some_and(|children| children.contains(name))
                        })
                }))
    }

    #[cfg(feature = "test-support")]
    pub(super) fn native_relative(&self, path: &RelPath) -> Option<&Path> {
        let index = *self.listed_files.get(path)?;
        Some(&self.files.get(index)?.relative)
    }

    #[cfg(feature = "test-support")]
    pub(super) fn files(&self) -> &[NativeFile] {
        &self.files
    }

    pub(super) fn unlisted_files(&self) -> impl Iterator<Item = (usize, &NativeFile)> {
        let listed: HashSet<_> = self.listed_files.values().copied().collect();
        self.files
            .iter()
            .enumerate()
            .filter(move |(index, _)| !listed.contains(index))
    }

    pub(super) fn read_file(&self, path: &RelPath, limit: u64) -> io::Result<Vec<u8>> {
        let index = self.listed_files.get(path).ok_or(io::ErrorKind::NotFound)?;
        self.read_native_file(&self.files[*index], limit)
    }

    pub(super) fn read_listed_bytes(&self, path: &Path, limit: u64) -> Option<Vec<u8>> {
        let relative = path.strip_prefix(&self.root).ok()?;
        let path = listing_path(relative)?;
        let file = &self.files[*self.listed_files.get(&path)?];
        if file.relative != relative || file.size > limit {
            return None;
        }
        let bytes = self.read_file(&path, limit).ok()?;
        if bytes.len() as u64 > limit {
            return None;
        }
        Some(bytes)
    }

    pub(super) fn read_native_file(&self, file: &NativeFile, limit: u64) -> io::Result<Vec<u8>> {
        read_project_path(&self.dir, &file.relative, limit)
    }
}

impl OmittedPaths for ProjectListing {
    fn kind(&self, path: &Path) -> Option<AuditPathKind> {
        let relative = path.strip_prefix(&self.root).ok()?;
        self.is_omitted(path)
            .then(|| project_path_type(&self.dir, &self.root, relative).ok())
            .flatten()
    }

    fn children(&self, path: &Path) -> Vec<PathBuf> {
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return Vec::new();
        };
        if self.is_omitted(path) {
            return disk_children(&self.dir, relative, path);
        }
        self.omitted
            .get(relative)
            .into_iter()
            .flatten()
            .map(|child| path.join(child))
            .collect()
    }

    fn safe_directory(&self, path: &Path) -> bool {
        self.is_omitted(path)
            && path
                .strip_prefix(&self.root)
                .is_ok_and(|relative| open_project_subdir(&self.dir, relative).is_ok())
    }

    fn native_alias(&self, path: &RelPath) -> Option<PathBuf> {
        self.native_aliases
            .get(path)
            .map(|relative| self.root.join(relative))
    }
}

/// List regular files and directories in path order, honoring the project's ignore rules.
pub fn list_project(root: &Path) -> Result<ProjectListing, ListingError> {
    list_project_with_limits(root, MAX_PROJECT_FILES, MAX_PROJECT_DEPTH)
}

pub(super) fn list_project_with_limits(
    root: &Path,
    max_files: usize,
    max_depth: usize,
) -> Result<ProjectListing, ListingError> {
    let root_error = |source| ListingError::Root {
        path: root.to_owned(),
        source,
    };
    let canonical_root = fs::canonicalize(root).map_err(root_error)?;
    let dir = open_project_dir(&canonical_root).map_err(|source| ListingError::Directory {
        path: root.to_owned(),
        source,
    })?;
    let scope = GitignoreChain::for_root(&dir);
    let mut walker = Walker {
        root: &canonical_root,
        max_files,
        max_depth,
        files: Vec::new(),
        skipped_paths: 0,
        skipped_scopes: SkippedScopes::default(),
        entries: Vec::new(),
        omitted: HashSet::new(),
    };
    walker.visit(&dir, Path::new(""), &scope, 0)?;

    Ok(walker.into_listing(dir))
}

fn listing_path(relative: &Path) -> Option<RelPath> {
    let mut name = String::new();
    for component in relative.iter() {
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(&component.to_string_lossy());
    }
    let path = RelPath::parse(&name).ok()?;
    #[cfg(windows)]
    if !sitecmd_engine_host::wants::is_portable_path(&path) {
        return None;
    }
    Some(path)
}

#[derive(Debug)]
pub(super) struct NativeFile {
    pub(super) relative: PathBuf,
    pub(super) size: u64,
    pub(super) ignored: bool,
}

enum PendingEntry {
    Dir(PathBuf),
    File(usize),
}

impl PendingEntry {
    fn relative<'a>(&'a self, files: &'a [NativeFile]) -> &'a Path {
        match self {
            Self::Dir(relative) => relative,
            Self::File(index) => &files[*index].relative,
        }
    }
}

struct Walker<'a> {
    root: &'a Path,
    max_files: usize,
    max_depth: usize,
    files: Vec<NativeFile>,
    skipped_paths: u64,
    skipped_scopes: SkippedScopes,
    entries: Vec<(RelPath, PendingEntry)>,
    omitted: HashSet<PathBuf>,
}

impl Walker<'_> {
    fn into_listing(mut self, dir: Dir) -> ProjectListing {
        self.sort_host_paths();
        self.entries.sort_unstable_by(|(a, a_entry), (b, b_entry)| {
            a.cmp(b).then_with(|| {
                let a = a_entry.relative(&self.files).as_os_str();
                let b = b_entry.relative(&self.files).as_os_str();
                a.as_encoded_bytes().cmp(b.as_encoded_bytes())
            })
        });
        let mut entries: Vec<ListingEntry> = Vec::with_capacity(self.entries.len());
        let mut listed_files = HashMap::new();
        let mut listed_dirs = HashSet::new();
        let mut native_aliases = HashMap::new();
        for (path, pending) in self.entries {
            let parent = pending
                .relative(&self.files)
                .parent()
                .unwrap_or(Path::new(""));
            // Parents sort before their children. Only the selected on-disk
            // directory may contribute children under its wire path.
            if (!parent.as_os_str().is_empty() && !listed_dirs.contains(parent))
                || entries.last().is_some_and(|entry| entry.path == path)
            {
                self.skipped_paths += 1;
                self.omitted
                    .insert(pending.relative(&self.files).to_owned());
                continue;
            }
            let relative = pending.relative(&self.files);
            if relative.to_str().is_none() {
                native_aliases.insert(path.clone(), relative.to_owned());
            }
            let (kind, size, ignored) = match pending {
                PendingEntry::Dir(relative) => {
                    listed_dirs.insert(relative);
                    (EntryKind::Dir, 0, false)
                }
                PendingEntry::File(index) => {
                    listed_files.insert(path.clone(), index);
                    let file = &self.files[index];
                    (EntryKind::File, file.size, file.ignored)
                }
            };
            entries.push(ListingEntry {
                path,
                kind,
                size,
                ignored,
            });
        }
        // Index omitted direct children by parent for bounded framework detection.
        let mut omitted: HashMap<PathBuf, HashSet<OsString>> = HashMap::new();
        for path in self.omitted {
            if let Some((parent, name)) = path.parent().zip(path.file_name()) {
                omitted
                    .entry(parent.to_owned())
                    .or_default()
                    .insert(name.to_owned());
            }
        }

        ProjectListing {
            wire: Listing {
                entries,
                skipped_paths: self.skipped_paths,
            },
            root: self.root.to_owned(),
            dir,
            files: self.files,
            listed_files,
            omitted,
            native_aliases,
            skipped_scopes: self.skipped_scopes,
        }
    }

    fn visit(
        &mut self,
        dir: &Dir,
        relative: &Path,
        scope: &GitignoreChain<'_>,
        depth: usize,
    ) -> Result<(), ListingError> {
        if depth > self.max_depth {
            return Err(ListingError::Depth(self.max_depth));
        }
        let entries = dir.entries().map_err(|source| ListingError::Directory {
            path: self.root.join(relative),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(ListingError::Entry)?;
            let name = entry.file_name();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let relative = relative.join(&name);
            if kind.is_symlink() {
                self.omitted.insert(relative);
                continue;
            }
            if kind.is_dir() {
                if should_skip_walker_dir(&relative, &name.to_string_lossy()) {
                    self.omitted.insert(relative);
                    continue;
                }
                let child = dir.open_dir_nofollow(&name);
                if child.as_ref().is_ok_and(has_git_entry) {
                    self.skipped_scopes
                        .record_nested_repository(native_path(&relative));
                    self.omitted.insert(relative);
                    continue;
                }
                if scope.is_ignored(&relative, true) {
                    self.skipped_scopes
                        .record_gitignored_directory(native_path(&relative));
                    self.omitted.insert(relative);
                    continue;
                }
                let child = match child {
                    Ok(child) => child,
                    Err(_) if !dir.symlink_metadata(&name).is_ok_and(|m| m.is_dir()) => continue,
                    Err(source) => {
                        return Err(ListingError::Directory {
                            path: self.root.join(&relative),
                            source,
                        })
                    }
                };
                let child_scope = scope.enter(&relative, &child);
                self.visit(&child, &relative, &child_scope, depth + 1)?;
                self.record(PendingEntry::Dir(relative));
            } else {
                if self.files.len() >= self.max_files {
                    return Err(ListingError::Files(self.max_files));
                }
                if !kind.is_file() {
                    self.omitted.insert(relative);
                    continue;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                if !metadata.is_file() {
                    continue;
                }
                let index = self.files.len();
                self.files.push(NativeFile {
                    ignored: scope.is_ignored(&relative, false),
                    relative,
                    size: metadata.len(),
                });
                self.record(PendingEntry::File(index));
            }
        }
        Ok(())
    }

    fn record(&mut self, entry: PendingEntry) {
        if let Some(path) = listing_path(entry.relative(&self.files)) {
            self.entries.push((path, entry));
        } else {
            self.omitted.insert(entry.relative(&self.files).to_owned());
            self.skipped_paths += 1;
        }
    }
}

pub(super) fn native_path(relative: &Path) -> String {
    relative.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
#[path = "project_listing_tests.rs"]
mod tests;
