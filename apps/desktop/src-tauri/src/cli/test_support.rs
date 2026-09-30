//! Fixtures the connected command tests share: a clean checkout to audit, a
//! site's connection export with its secrets, and clients built against a
//! local double of the connected service.

use std::path::{Path, PathBuf};

use crate::connected_service::ConnectedServiceClient;

pub(crate) const ENVIRONMENT_URL: &str = "https://example.com";
pub(crate) const CI_TOKEN: &str = "sitecmd_ci_0123456789abcdef0123456789abcdef";
const PASSPHRASE: &str = "correct horse battery staple";

/// Build every client against the local double instead of the endpoint this
/// build was configured with.
pub(crate) fn through(
    origin: &str,
) -> impl Fn(&str) -> Result<ConnectedServiceClient, String> + '_ {
    move |token| ConnectedServiceClient::for_test_endpoint(origin, token)
}

/// `site_id`'s connection export as the desktop app writes one, with its
/// passphrase and the CI token set under variables only the calling test
/// reads, so parallel tests never see each other's values.
pub(crate) fn exported_site(
    directory: &Path,
    site_id: &str,
    variable_prefix: &str,
) -> (PathBuf, String, String) {
    let export = directory.join("connection.json");
    let rendered = crate::connected_export::encrypt_site_connection(
        site_id,
        ENVIRONMENT_URL,
        1,
        [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
        PASSPHRASE,
    )
    .expect("export");
    std::fs::write(&export, rendered).expect("write export");
    let passphrase_env = format!("{variable_prefix}_PASSPHRASE");
    let token_env = format!("{variable_prefix}_TOKEN");
    std::env::set_var(&passphrase_env, PASSPHRASE);
    std::env::set_var(&token_env, CI_TOKEN);
    (export, passphrase_env, token_env)
}

/// A one-commit git checkout with a finding for the audit to report, clean so
/// its basis can be exact. Answers the checkout and isolated HOME guards, the
/// checkout root and its head commit.
pub(crate) fn clean_checkout() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, String) {
    let home_root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME must be set for tests");
    let repo = tempfile::tempdir_in(&home_root).expect("repo tempdir");
    // Outside the working tree: an isolated HOME inside it would leave the
    // checkout dirty, and a dirty tree is never an exact basis.
    let home = tempfile::tempdir().expect("home tempdir");
    let root = repo.path().to_path_buf();
    std::fs::write(
        root.join("package.json"),
        "{\"name\": \"cli-submit-fixture\", \"version\": \"1.0.0\"}\n",
    )
    .expect("project marker");
    std::fs::write(
        root.join("app.js"),
        "export function render(input) {\n  return eval(input);\n}\n",
    )
    .expect("source file");

    let environment = [
        ("HOME", home.path().to_string_lossy().to_string()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_string()),
        ("GIT_CONFIG_SYSTEM", "/dev/null".to_string()),
    ];
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&root)
            .envs(
                environment
                    .iter()
                    .map(|(key, value)| (*key, value.as_str())),
            )
            .output()
            .expect("git command");
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "Test User"]);
    git(&["config", "commit.gpgsign", "false"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "one commit"]);

    let status = crate::core::git::get_git_status(&root.to_string_lossy(), 1);
    assert!(status.is_git_repo && !status.has_uncommitted, "{status:?}");
    let head = status.commits[0].hash.clone();
    (repo, home, root, head)
}
