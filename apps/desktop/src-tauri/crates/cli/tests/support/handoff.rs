use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

pub(super) struct Project {
    pub(super) dir: tempfile::TempDir,
    db_path: PathBuf,
    launches: PathBuf,
}

impl Project {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sitecmd.db");
        let launches = dir.path().join("launches.log");
        drop(sitecmd_runtime::db::Database::open(db_path.clone()).unwrap());
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        for launcher in ["open", "xdg-open"] {
            let path = bin.join(launcher);
            std::fs::write(
                &path,
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$LAUNCH_LOG\"\n",
            )
            .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            dir,
            db_path,
            launches,
        }
    }

    pub(super) fn command(&self) -> Command {
        let mut command = Command::new(super::cli_binary());
        let mut paths = vec![self.dir.path().join("bin")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        command
            .current_dir(self.dir.path())
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("SITECMD_DB_PATH", &self.db_path)
            .env("LAUNCH_LOG", &self.launches);
        command
    }

    pub(super) fn configure(&self, url: &str) {
        sitecmd_runtime::cli::write_config(
            &self.dir.path().join(".sitecmd"),
            &sitecmd_runtime::cli::CliConfig::new(url, "Fixture"),
        )
        .unwrap();
    }

    pub(super) fn assert_no_handoff(&self, output: &str) {
        let launches = std::fs::read_to_string(&self.launches).unwrap_or_default();
        let db = sitecmd_runtime::db::Database::open(self.db_path.clone()).unwrap();
        let projects: i64 = db
            .execute(|conn| {
                conn.query_row("SELECT count(*) FROM projects", [], |row| row.get(0))
                    .unwrap()
            })
            .unwrap();
        assert!(
            launches.is_empty()
                && projects == 0
                && !output.to_lowercase().contains("desktop")
                && !output.contains("sitecmd://"),
            "launches: {launches:?}; imported projects: {}; output: {output}",
            projects
        );
    }
}

pub(super) fn rendered(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
