use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const STORAGE_DIR_NAME: &str = "com.sitecmd.app";
pub const APP_DB_FILENAME: &str = "sitecmd.db";

fn default_app_data_root() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("Library").join("Application Support"))
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(PathBuf::from)
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".local").join("share"))
            })
    }
}

pub fn default_storage_dir() -> Option<PathBuf> {
    default_app_data_root().map(|root| root.join(STORAGE_DIR_NAME))
}

pub fn default_app_db_path() -> Option<PathBuf> {
    default_storage_dir().map(|dir| dir.join(APP_DB_FILENAME))
}

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(
            "private storage path must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Reject an existing private-storage target unless it is a regular file.
/// A missing target is safe for a caller that will create it with `O_NOFOLLOW`.
pub fn validate_private_file_target(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(io::Error::other("private storage file must be a real file"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Apply and verify private-file permissions through the opened handle. This
/// avoids changing a replacement path if another process swaps the directory
/// entry after `OpenOptions::open`.
pub fn restrict_open_private_file(file: &std::fs::File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("private storage file must be a real file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("private storage file has no parent directory"))?;
    ensure_private_directory(parent)?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    validate_private_file_target(path)?;

    let mut file = options.open(path)?;
    restrict_open_private_file(&file)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_dir_name_stays_on_legacy_namespace() {
        assert_eq!(STORAGE_DIR_NAME, "com.sitecmd.app");
    }

    #[cfg(unix)]
    #[test]
    fn private_storage_is_owner_only_and_rejects_symlink_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let private_dir = temp.path().join("private");
        ensure_private_directory(&private_dir).expect("private directory");
        let dir_mode = std::fs::metadata(&private_dir)
            .expect("directory metadata")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);

        let private_file = private_dir.join("state.json");
        write_private_file(&private_file, b"private").expect("private file");
        let file_mode = std::fs::metadata(&private_file)
            .expect("file metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600);

        let target = private_dir.join("target.json");
        std::fs::write(&target, "keep").expect("target");
        let link = private_dir.join("link.json");
        symlink(&target, &link).expect("symlink");
        assert!(write_private_file(&link, b"replace").is_err());
        assert_eq!(
            std::fs::read_to_string(target).expect("target contents"),
            "keep"
        );
    }
}
