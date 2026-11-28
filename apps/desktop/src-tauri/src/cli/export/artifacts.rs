use cap_std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use crate::core::safe_fs::open_project_dir;

use crate::core::scan_types::ScanResult;

pub(in crate::cli) fn write_file(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    let path = dir.join(name);
    replace_artifact(dir, name, contents)
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))
}

fn replace_artifact(dir: &Path, name: &str, contents: &str) -> io::Result<()> {
    let dir = open_project_dir(dir)?;
    let mut random = [0; 16];
    getrandom::fill(&mut random)
        .map_err(|_| io::Error::other("could not generate artifact name"))?;
    let temp = format!(".sitecmd-{}.tmp", hex::encode(random));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = dir.open_with(&temp, &options)?;
    let written = file.write_all(contents.as_bytes());
    drop(file);
    let result = written.and_then(|()| dir.rename(&temp, &dir, name));
    if result.is_err() {
        let _ = dir.remove_file(&temp);
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn artifact_writer_replaces_the_link_without_changing_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join(".sitecmd");
        std::fs::create_dir(&dir).unwrap();
        let target = temp.path().join("fixture.txt");
        std::fs::write(&target, "original").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("issues.md")).unwrap();

        write_file(&dir, "issues.md", "report").unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
        assert_eq!(
            std::fs::read_to_string(dir.join("issues.md")).unwrap(),
            "report"
        );
    }

    #[test]
    fn artifact_writer_refuses_a_linked_config_directory() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join(".sitecmd");
        let target = temp.path().join("fixture");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &dir).unwrap();

        assert!(write_file(&dir, "issues.md", "report").is_err());
        assert!(!target.join("issues.md").exists());
    }
}

pub(super) fn build_last_scan_json(result: &ScanResult) -> Result<String, String> {
    serde_json::to_string_pretty(result)
        .map_err(|e| format!("failed to serialize scan result: {}", e))
}
