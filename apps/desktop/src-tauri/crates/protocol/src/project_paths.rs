//! Look up native paths in a project listing and its omitted entries.

pub use crate::engine_abi::AuditPathKind as PathKind;
use crate::engine_abi::{EntryKind, Listing, RelPath};
use std::path::{Component, Path, PathBuf};

pub trait ProjectPaths {
    fn kind(&self, path: &Path) -> Option<PathKind>;
    fn children(&self, path: &Path) -> Vec<PathBuf>;

    fn safe_directory(&self, path: &Path) -> bool {
        self.kind(path) == Some(PathKind::Directory)
    }
}

pub trait OmittedPaths {
    fn kind(&self, _path: &Path) -> Option<PathKind> {
        None
    }

    fn children(&self, _path: &Path) -> Vec<PathBuf> {
        Vec::new()
    }

    fn native_alias(&self, _path: &RelPath) -> Option<PathBuf> {
        None
    }

    fn order_children(&self, _path: &Path, _children: &mut [PathBuf]) {}

    fn safe_directory(&self, path: &Path) -> bool {
        self.kind(path) == Some(PathKind::Directory)
    }
}

impl OmittedPaths for () {}

pub struct ListedPaths<'a> {
    listing: &'a Listing,
    root: &'a Path,
    omitted: &'a dyn OmittedPaths,
}

impl<'a> ListedPaths<'a> {
    pub fn new(listing: &'a Listing, root: &'a Path, omitted: &'a dyn OmittedPaths) -> Self {
        Self {
            listing,
            root,
            omitted,
        }
    }

    fn listed_kind(&self, path: &Path) -> Option<PathKind> {
        let relative = path.strip_prefix(self.root).ok()?;
        if relative.as_os_str().is_empty() {
            return Some(PathKind::Directory);
        }
        let key = listing_key(relative)?;
        let entries = &self.listing.entries;
        let index = entries
            .binary_search_by(|entry| entry.path.as_str().cmp(&key))
            .ok()?;
        let entry = &entries[index];
        let matches_native_name = self
            .omitted
            .native_alias(&entry.path)
            .map_or_else(|| relative.to_str().is_some(), |native| native == path);
        if !matches_native_name {
            return None;
        }
        Some(match entry.kind {
            EntryKind::File => PathKind::File,
            EntryKind::Dir => PathKind::Directory,
        })
    }
}

impl ProjectPaths for ListedPaths<'_> {
    fn kind(&self, path: &Path) -> Option<PathKind> {
        self.listed_kind(path).or_else(|| self.omitted.kind(path))
    }

    fn children(&self, path: &Path) -> Vec<PathBuf> {
        let mut children = self.omitted.children(path);
        if let Some(relative) = path.strip_prefix(self.root).ok().and_then(listing_key) {
            let prefix = if relative.is_empty() {
                relative
            } else {
                format!("{relative}/")
            };
            let entries = &self.listing.entries;
            let start = entries.partition_point(|entry| entry.path.as_str() < prefix.as_str());
            children.extend(
                entries[start..]
                    .iter()
                    .map_while(|entry| {
                        Some((entry.path.as_str().strip_prefix(&prefix)?, &entry.path))
                    })
                    .filter(|(child, _)| !child.contains('/'))
                    .map(|(child, key)| {
                        self.omitted
                            .native_alias(key)
                            .unwrap_or_else(|| path.join(child))
                    }),
            );
        }
        children.sort_unstable();
        children.dedup();
        self.omitted.order_children(path, &mut children);
        children
    }

    fn safe_directory(&self, path: &Path) -> bool {
        self.listed_kind(path).map_or_else(
            || self.omitted.safe_directory(path),
            |kind| kind == PathKind::Directory,
        )
    }
}

fn listing_key(path: &Path) -> Option<String> {
    path_key(path, |name| Some(name.to_string_lossy()))
}

fn relative_key(path: &Path) -> Option<String> {
    path_key(path, |name| name.to_str().map(std::borrow::Cow::Borrowed))
}

fn path_key<'a>(
    path: &'a Path,
    encode: impl Fn(&'a std::ffi::OsStr) -> Option<std::borrow::Cow<'a, str>>,
) -> Option<String> {
    let mut key = String::new();
    for component in path
        .components()
        .filter(|component| *component != Component::CurDir)
    {
        let Component::Normal(name) = component else {
            return None;
        };
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(&encode(name)?);
    }
    Some(key)
}

pub fn manifest_text<'a>(manifests: &'a [(RelPath, String)], path: &Path) -> Option<&'a str> {
    let key = relative_key(path)?;
    manifests
        .iter()
        .find_map(|(path, text)| (path.as_str() == key).then_some(text.as_str()))
}
