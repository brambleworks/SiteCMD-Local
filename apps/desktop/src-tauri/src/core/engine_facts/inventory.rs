use crate::core::project_listing::{NativeFile, ProjectListing};
use crate::core::safe_fs::read_project_path;
use sitecmd_protocol::database_env::is_private_dotenv;
use sitecmd_protocol::engine_abi::{
    AuditFailure, AuditFileKind, AuditFileOffer, AuditPathFact, AuditPathKind, DisplayPath,
    FileOfferId,
};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(in crate::core) enum NativeOffer<'a> {
    Inventory(&'a NativeFile),
    Dependency(PathBuf),
    Ancestor {
        directory: Arc<cap_std::fs::Dir>,
        path: PathBuf,
    },
    Metadata(PathBuf),
    DatabaseLocation(PathBuf),
}

#[derive(Default)]
pub(super) struct FileOffers<'a> {
    pub(super) wire: Vec<AuditFileOffer>,
    pub(super) native: Vec<NativeOffer<'a>>,
    pub(super) paths: Vec<AuditPathFact>,
    pub(super) probe_order: Vec<DisplayPath>,
    observed_files: HashSet<PathBuf>,
}

impl<'a> FileOffers<'a> {
    pub(super) fn add(
        &mut self,
        display: &str,
        kind: AuditFileKind,
        size: u64,
        file: NativeOffer<'a>,
    ) {
        if let Ok(path) = DisplayPath::parse(display) {
            if !self.observed_files.insert(file.key().to_owned()) {
                return;
            }
            let id = self.wire.len() as FileOfferId;
            self.wire.push(AuditFileOffer {
                id,
                path,
                kind,
                size,
            });
            self.native.push(file);
        }
    }

    pub(super) fn inventory(
        &mut self,
        listing: &'a ProjectListing,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AuditFailure> {
        for (walk_index, file) in listing.unlisted_files() {
            if cancelled() {
                return Err(AuditFailure::Cancelled);
            }
            self.add(
                &offer_path(&file.relative),
                AuditFileKind::Inventory {
                    walk_index,
                    ignored: file.ignored,
                },
                file.size,
                NativeOffer::Inventory(file),
            );
        }
        Ok(())
    }

    pub(super) fn path(&mut self, listing: &ProjectListing, path: &Path) -> Option<AuditPathKind> {
        let kind = listing.observed_kind(path)?;
        if listing.is_omitted(path) {
            if let Some(display) = path
                .strip_prefix(listing.root())
                .ok()
                .and_then(|path| DisplayPath::parse(&offer_path(path)).ok())
            {
                self.paths.push(AuditPathFact {
                    path: display,
                    kind,
                    safe_directory: listing.observed_safe_directory(path),
                });
            }
        }
        Some(kind)
    }

    pub(super) fn metadata(
        &mut self,
        listing: &ProjectListing,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AuditFailure> {
        let root = listing.root();
        for relative in [
            ".git",
            "app/Http",
            "app/Providers",
            "web/core/lib/Drupal.php",
            "core/lib/Drupal.php",
            "docroot/core/lib/Drupal.php",
            "web/modules/custom",
            "web/themes/custom",
            "wp-content/plugins",
            "wp-content/themes",
        ] {
            self.path(listing, &root.join(relative));
        }
        for relative in [
            "CLAUDE.md",
            "AGENTS.md",
            "GEMINI.md",
            ".cursorrules",
            ".windsurfrules",
            ".github/copilot-instructions.md",
            ".mcp.json",
            ".cursor/mcp.json",
            ".vscode/mcp.json",
        ] {
            self.metadata_path(listing, &root.join(relative));
        }
        let mut candidates = vec![root.to_owned()];
        for parent in ["", "apps", "packages"] {
            let dir = root.join(parent);
            if !parent.is_empty() && !listing.observed_safe_directory(&dir) {
                continue;
            }
            let children = listing.observed_children(&dir);
            for child in children {
                if cancelled() {
                    return Err(AuditFailure::Cancelled);
                }
                if let Ok(relative) = child.strip_prefix(root) {
                    if let Ok(display) = DisplayPath::parse(&offer_path(relative)) {
                        self.probe_order.push(display);
                    }
                }
                if self.path(listing, &child) == Some(AuditPathKind::Directory)
                    && listing.observed_safe_directory(&child)
                {
                    candidates.push(child);
                }
            }
        }
        for dir in candidates {
            if cancelled() {
                return Err(AuditFailure::Cancelled);
            }
            for name in [
                "composer.json",
                "package.json",
                "hugo.toml",
                "hugo.yaml",
                "config.toml",
                "_config.yml",
                "_layouts",
                "_posts",
                ".eleventy.js",
                "eleventy.config.js",
                "netlify.toml",
                "wrangler.toml",
            ] {
                self.metadata_path(listing, &dir.join(name));
            }
            // Only root-level and immediate child Drupal manifests are probed.
            if dir == root || dir.parent() == Some(root) {
                for path in listing.observed_children(&dir) {
                    if path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with(".info.yml"))
                    {
                        self.metadata_path(listing, &path);
                    }
                }
            }
        }
        Ok(())
    }

    fn metadata_path(&mut self, listing: &ProjectListing, path: &Path) {
        if !listing.is_omitted(path)
            || !matches!(
                self.path(listing, path),
                Some(AuditPathKind::File | AuditPathKind::Symlink)
            )
        {
            return;
        }
        let Ok(relative) = path.strip_prefix(listing.root()) else {
            return;
        };
        if let Some(metadata) = metadata_target(listing.root(), relative)
            .ok()
            .and_then(|target| listing.root().join(target).metadata().ok())
            .filter(|metadata| metadata.is_file())
        {
            self.add(
                &offer_path(relative),
                AuditFileKind::Metadata {},
                metadata.len(),
                NativeOffer::Metadata(relative.to_owned()),
            );
        }
    }
}

impl NativeOffer<'_> {
    fn key(&self) -> &Path {
        match self {
            Self::Inventory(file) => &file.relative,
            Self::Dependency(path)
            | Self::Metadata(path)
            | Self::DatabaseLocation(path)
            | Self::Ancestor { path, .. } => path,
        }
    }

    pub(in crate::core) fn tracking_path(&self) -> Option<&Path> {
        match self {
            Self::Inventory(file) => Some(&file.relative),
            Self::Dependency(path) | Self::Metadata(path) => Some(path),
            Self::Ancestor { .. } | Self::DatabaseLocation(_) => None,
        }
    }

    pub(in crate::core) fn read(
        &self,
        listing: &ProjectListing,
        limit: u64,
    ) -> io::Result<Vec<u8>> {
        match self {
            Self::DatabaseLocation(_) => Err(io::ErrorKind::Unsupported.into()),
            Self::Inventory(file) => listing.read_native_file(file, limit),
            Self::Dependency(path) => listing.read_relative_file(path, limit),
            Self::Ancestor { directory, path } => {
                let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
                read_project_path(directory, Path::new(name), limit)
            }
            Self::Metadata(path) => {
                // An in-root link resolves to its target once; the target is then read
                // without following any link, so a later swap fails instead of escaping.
                let target = metadata_target(listing.root(), path)?;
                listing.read_relative_file(&target, limit)
            }
        }
    }
}

fn metadata_target(root: &Path, relative: &Path) -> io::Result<PathBuf> {
    let target = root.join(relative).canonicalize()?;
    let relative = target
        .strip_prefix(root)
        .map_err(|_| io::Error::from(io::ErrorKind::NotFound))?;
    if relative
        .file_name()
        .is_some_and(|name| is_private_dotenv(&name.to_string_lossy()))
    {
        return Err(io::ErrorKind::NotFound.into());
    }
    Ok(relative.to_owned())
}

pub(super) fn offer_path(path: &Path) -> String {
    if cfg!(windows) {
        path.to_string_lossy().replace('\\', "/")
    } else {
        path.to_string_lossy().into_owned()
    }
}
