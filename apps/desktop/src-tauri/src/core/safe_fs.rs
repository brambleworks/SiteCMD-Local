//! Bounded reads from untrusted project trees.

#![forbid(unsafe_code)]

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use sitecmd_protocol::engine_abi::AuditPathKind;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

pub(super) fn open_project_dir(root: &Path) -> io::Result<Dir> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY);
    }
    let file = File::open_ambient_with(root, &options, cap_std::ambient_authority())?;
    if !file.metadata()?.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    Ok(Dir::from_std_file(file.into_std()))
}

pub(super) fn read_project_path(root: &Dir, relative: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let ProjectPath::Entry(parent, name) = project_path(root, relative)? else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    read_file_nofollow(parent.as_ref().unwrap_or(root), name, limit)
}

pub(super) fn open_writable_project_file(root: &Dir, relative: &Path) -> io::Result<File> {
    let ProjectPath::Entry(parent, name) = project_path(root, relative)? else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    open_file_nofollow(parent.as_ref().unwrap_or(root), name, true)
}

pub(super) fn project_path_is_symlink(root: &Dir, relative: &Path) -> bool {
    match project_path(root, relative) {
        Ok(ProjectPath::Symlink(_)) => true,
        Ok(ProjectPath::Entry(parent, name)) => parent
            .as_ref()
            .unwrap_or(root)
            .symlink_metadata(name)
            .is_ok_and(|entry| entry.is_symlink()),
        Err(_) => false,
    }
}

pub(super) fn open_project_subdir(root: &Dir, relative: &Path) -> io::Result<Dir> {
    let ProjectPath::Entry(parent, name) = project_path(root, relative)? else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    parent.as_ref().unwrap_or(root).open_dir_nofollow(name)
}

pub(super) fn project_path_type(
    root: &Dir,
    canonical_root: &Path,
    relative: &Path,
) -> io::Result<AuditPathKind> {
    let depth = match project_path(root, relative)? {
        ProjectPath::Entry(parent, name) => {
            let kind = metadata_kind(&parent.as_ref().unwrap_or(root).symlink_metadata(name)?);
            if kind != AuditPathKind::Symlink {
                return Ok(kind);
            }
            relative.components().count()
        }
        ProjectPath::Symlink(depth) => depth,
    };
    linked_path_type(root, canonical_root, relative, depth)
}

fn linked_path_type(
    root: &Dir,
    canonical_root: &Path,
    relative: &Path,
    depth: usize,
) -> io::Result<AuditPathKind> {
    let mut components = relative.components();
    let mut path: PathBuf = components.by_ref().take(depth).collect();
    let mut components = components.peekable();
    let mut kind = AuditPathKind::Symlink;
    loop {
        if kind == AuditPathKind::Symlink {
            // Check the link target before looking up any remaining component.
            let target = canonical_root.join(&path).canonicalize();
            let Some(target) = target
                .as_ref()
                .ok()
                .and_then(|target| target.strip_prefix(canonical_root).ok())
            else {
                return Ok(if components.peek().is_some() {
                    AuditPathKind::Unknown
                } else {
                    AuditPathKind::Symlink
                });
            };
            path = target.to_owned();
            kind = if path.as_os_str().is_empty() {
                AuditPathKind::Directory
            } else {
                metadata_kind(&root.symlink_metadata(&path)?)
            };
        }
        match components.next() {
            None => return Ok(kind),
            Some(Component::Normal(name)) => path.push(name),
            Some(_) => return Err(io::ErrorKind::InvalidInput.into()),
        }
        kind = metadata_kind(&root.symlink_metadata(&path)?);
    }
}

fn metadata_kind(metadata: &Metadata) -> AuditPathKind {
    if metadata.is_symlink() {
        AuditPathKind::Symlink
    } else if metadata.is_file() {
        AuditPathKind::File
    } else if metadata.is_dir() {
        AuditPathKind::Directory
    } else {
        AuditPathKind::Other
    }
}

enum ProjectPath<'a> {
    Entry(Option<Dir>, &'a OsStr),
    Symlink(usize),
}

fn project_path<'a>(root: &Dir, relative: &'a Path) -> io::Result<ProjectPath<'a>> {
    let mut components = relative.components();
    let Some(Component::Normal(name)) = components.next_back() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let mut parent = None;
    for (index, component) in components.enumerate() {
        let Component::Normal(component) = component else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let dir = parent.as_ref().unwrap_or(root);
        parent = Some(match dir.open_dir_nofollow(component) {
            Ok(child) => child,
            Err(_)
                if dir
                    .symlink_metadata(component)
                    .is_ok_and(|entry| entry.is_symlink()) =>
            {
                return Ok(ProjectPath::Symlink(index + 1));
            }
            Err(error) => return Err(error),
        });
    }
    Ok(ProjectPath::Entry(parent, name))
}

pub(super) fn read_file_nofollow(dir: &Dir, name: &OsStr, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = open_file_nofollow(dir, name, false)?;
    read_file_limited(&mut file, limit)
}

fn open_file_nofollow(dir: &Dir, name: &OsStr, writable: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        // A file replaced by a FIFO must not block before the metadata check.
        options.custom_flags(libc::O_NONBLOCK);
    }
    dir.open_with(name, &options)
}

pub(super) fn read_file_limited(file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let bound = limit.saturating_add(1);
    let capacity =
        usize::try_from(metadata.len().min(bound)).map_err(|_| io::ErrorKind::OutOfMemory)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    file.take(bound).read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn read_bounded_file(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let initial_metadata = fs::symlink_metadata(path).ok()?;
    if initial_metadata.file_type().is_symlink()
        || !initial_metadata.is_file()
        || initial_metadata.len() > max_bytes
    {
        return None;
    }

    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .ok()?
    };
    #[cfg(not(unix))]
    let opened = fs::File::open(path).ok()?;

    let opened_metadata = opened.metadata().ok()?;
    if !opened_metadata.is_file() || opened_metadata.len() > max_bytes {
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if initial_metadata.dev() != opened_metadata.dev()
            || initial_metadata.ino() != opened_metadata.ino()
        {
            return None;
        }
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    opened
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= max_bytes).then_some(bytes)
}

pub(crate) fn read_bounded_file_under_root(
    root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Option<Vec<u8>> {
    let canonical_root = fs::canonicalize(root).ok()?;
    let canonical_path = fs::canonicalize(path).ok()?;
    if !canonical_path.starts_with(&canonical_root) {
        return None;
    }
    // Read the verified canonical target so in-root symlinks work without
    // re-resolving an untrusted caller path during the bounded read.
    read_bounded_file(&canonical_path, max_bytes)
}

pub(crate) fn read_bounded_text_under_root(
    root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Option<String> {
    String::from_utf8(read_bounded_file_under_root(root, path, max_bytes)?).ok()
}

#[cfg(test)]
mod tests {
    use crate::core::safe_fs::{read_bounded_file_under_root, read_bounded_text_under_root};
    use std::fs;

    #[test]
    fn bounded_project_read_accepts_regular_file_and_rejects_oversize() {
        let project = tempfile::tempdir().expect("project");
        let manifest = project.path().join("package.json");
        fs::write(&manifest, b"{\"name\":\"site\"}").expect("write manifest");

        assert_eq!(
            read_bounded_text_under_root(project.path(), &manifest, 64).as_deref(),
            Some("{\"name\":\"site\"}")
        );
        assert!(read_bounded_file_under_root(project.path(), &manifest, 4).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_project_read_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().expect("project");
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        fs::write(outside.path(), b"APP_URL=https://private.example").expect("write outside file");
        let linked = project.path().join(".env");
        symlink(outside.path(), &linked).expect("create symlink");

        assert!(
            read_bounded_text_under_root(project.path(), &linked, 1024).is_none(),
            "repository metadata reads must not follow symlinks outside the project"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_project_read_follows_in_project_symlink() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().expect("project");
        let real = project.path().join("config.real.json");
        fs::write(&real, b"{\"name\":\"linked\"}").expect("write real target");
        let linked = project.path().join("package.json");
        symlink(&real, &linked).expect("create in-project symlink");

        assert_eq!(
            read_bounded_text_under_root(project.path(), &linked, 1024).as_deref(),
            Some("{\"name\":\"linked\"}"),
            "an in-project symlink must resolve to its in-project target so monorepo layouts still detect config"
        );
    }
}
