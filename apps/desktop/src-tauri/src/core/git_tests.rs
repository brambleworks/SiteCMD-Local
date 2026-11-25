use super::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct TestRepo {
    path: PathBuf,
    _dir: tempfile::TempDir, // dropped when TestRepo drops, cleaning the dir
}

impl std::ops::Deref for TestRepo {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

fn make_repo(name: &str) -> TestRepo {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    // Set HOME and GIT_CONFIG_GLOBAL so the test isn't tainted by the
    // user's git config (e.g. signing keys, custom hooks).
    let isolated = path.join("isolated_home");
    fs::create_dir_all(&isolated).expect("home");
    let env = [
        ("HOME", isolated.to_string_lossy().to_string()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_string()),
        ("GIT_CONFIG_SYSTEM", "/dev/null".to_string()),
    ];

    let run = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(&path)
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .output()
            .expect("git command")
    };

    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "user.name", "Test User"]);
    run(&["config", "commit.gpgsign", "false"]);

    fs::write(path.join("fixture.txt"), name).expect("write fixture");
    run(&["add", "fixture.txt"]);
    run(&["commit", "-q", "-m", name]);

    TestRepo { path, _dir: dir }
}

#[cfg(unix)]
#[test]
fn hardened_git_ignores_a_planted_fsmonitor_hook() {
    use std::os::unix::fs::PermissionsExt;

    let repo = make_repo("fsmonitor");
    let sentinel = repo.join("fsmonitor-ran.sentinel");
    let hook = repo.join("fsmonitor-hook.sh");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\nprintf '/'\n", sentinel.display()),
    )
    .expect("write hook");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("chmod hook");

    // The same isolated environment make_repo used, so the user's own git
    // config never participates; the repository-local config is the vector.
    let isolated_home = repo.join("isolated_home");
    let unhardened = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&*repo)
            .env("HOME", &isolated_home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    unhardened(&["config", "core.fsmonitor", &hook.to_string_lossy()]);

    // Control: the first status writes the fsmonitor index extension, the
    // second consults the hook. If this fails the installed git does not
    // honor hook-style fsmonitor and the test proves nothing.
    unhardened(&["status", "--porcelain"]);
    unhardened(&["status", "--porcelain"]);
    assert!(
        sentinel.exists(),
        "control failed: the installed git did not run the planted core.fsmonitor hook"
    );
    fs::remove_file(&sentinel).expect("reset sentinel");

    assert!(run_git(&repo, &["status", "--porcelain"]).is_some());
    assert!(run_git(&repo, &["log", "-1", "--format=%H"]).is_some());
    assert!(
        checkout_head_and_clean(&repo.to_string_lossy()).is_some(),
        "hardened git must still read the repository"
    );

    assert!(
        !sentinel.exists(),
        "hardened git spawn ran the repository's planted core.fsmonitor hook"
    );
}

#[test]
fn hardened_command_neutralizes_config_and_rebuilds_the_environment() {
    let repo = make_repo("hardened-env");
    let command = hardened_git_command(&repo, &["status", "--porcelain"]);
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let expected_prefix = [
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=",
        "-c",
        "core.sshCommand=",
        "-c",
        "diff.external=",
        "-c",
        "protocol.allow=never",
        "status",
        "--porcelain",
    ];
    assert_eq!(args, expected_prefix);

    let env: std::collections::BTreeMap<String, Option<String>> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert_eq!(env.get("GIT_CONFIG_NOSYSTEM"), Some(&Some("1".to_string())));
    assert_eq!(
        env.get("GIT_CONFIG_GLOBAL"),
        Some(&Some(GIT_NULL_CONFIG_FILE.to_string()))
    );
    assert_eq!(env.get("GIT_TERMINAL_PROMPT"), Some(&Some("0".to_string())));
    assert!(
        env.contains_key("PATH"),
        "PATH must be re-added after env_clear or git cannot be found"
    );
    let allowed: std::collections::BTreeSet<&str> = GIT_INHERITED_ENV
        .iter()
        .copied()
        .chain(GIT_FIXED_ENV.iter().map(|(key, _)| *key))
        .collect();
    for key in env.keys() {
        assert!(
            allowed.contains(key.as_str()),
            "{key} leaked into the git environment"
        );
    }
}

#[test]
fn checkout_provenance_names_a_merge_head() {
    let path = make_repo("merge-head");
    let run = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&*path)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&["checkout", "-q", "-b", "feature"]);
    fs::write(path.join("feature.txt"), "feature\n").expect("feature file");
    run(&["add", "feature.txt"]);
    run(&["commit", "-q", "-m", "feature"]);
    run(&["checkout", "-q", "main"]);
    fs::write(path.join("main.txt"), "main\n").expect("main file");
    run(&["add", "main.txt"]);
    run(&["commit", "-q", "-m", "main"]);
    run(&["merge", "--no-ff", "-q", "feature", "-m", "merge"]);

    let expected = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&*path)
        .output()
        .expect("head")
        .stdout;
    let expected = String::from_utf8(expected)
        .expect("utf8 head")
        .trim()
        .to_string();
    let (head, clean) = checkout_head_and_clean(&path.to_string_lossy()).expect("checkout");

    assert_eq!(head, expected);
    assert!(clean);
    assert_ne!(
        run_git(&path, &["log", "-1", "--no-merges", "--format=%H"])
            .expect("non-merge history")
            .trim(),
        head
    );
}

#[test]
fn run_git_command_captures_stderr_and_the_exit_status() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run = super::run_git_command(
        temp.path(),
        &["rev-parse", "HEAD"],
        std::time::Duration::from_secs(5),
        None,
    )
    .expect("git ran");
    assert!(!run.ok());
    assert!(
        run.stderr.contains("not a git repository"),
        "{}",
        run.stderr
    );
}

#[test]
fn run_git_command_returns_stdout_on_success() {
    let temp = tempfile::tempdir().expect("tempdir");
    super::run_git_command(
        temp.path(),
        &["init", "-q"],
        std::time::Duration::from_secs(5),
        None,
    )
    .expect("init");
    let run = super::run_git_command(
        temp.path(),
        &["rev-parse", "--is-inside-work-tree"],
        std::time::Duration::from_secs(5),
        None,
    )
    .expect("ran");
    assert!(run.ok());
    assert_eq!(run.stdout.trim(), "true");
}

#[test]
fn https_transport_encodes_the_installation_token_as_basic_auth() {
    let transport = super::HttpsTransport::for_token("ghs_abc");
    assert_eq!(
        transport.authorization_header,
        "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYw=="
    );
}

#[test]
fn run_git_command_with_transport_allows_only_https() {
    let temp = tempfile::tempdir().expect("tempdir");
    super::run_git_command(
        temp.path(),
        &["init", "-q"],
        std::time::Duration::from_secs(5),
        None,
    )
    .expect("init");
    let transport = super::HttpsTransport::for_token("ghs_abc");
    let run = super::run_git_command(
        temp.path(),
        &["ls-remote", "ssh://git@example.invalid/repo.git"],
        std::time::Duration::from_secs(5),
        Some(&transport),
    )
    .expect("ran");
    assert!(!run.ok());
    assert!(
        run.stderr.contains("protocol") || run.stderr.contains("not allowed"),
        "{}",
        run.stderr
    );
}

#[test]
fn run_git_command_with_transport_reopens_https_through_the_config_environment() {
    let temp = tempfile::tempdir().expect("tempdir");
    super::run_git_command(
        temp.path(),
        &["init", "-q"],
        std::time::Duration::from_secs(5),
        None,
    )
    .expect("init");
    let transport = super::HttpsTransport::for_token("ghs_abc");

    let configured = super::run_git_command(
        temp.path(),
        &["config", "--get", "http.extraheader"],
        std::time::Duration::from_secs(5),
        Some(&transport),
    )
    .expect("ran");
    assert!(configured.ok(), "{}", configured.stderr);
    assert_eq!(configured.stdout.trim(), transport.authorization_header);

    // The same invocation blanks every way git could reach a stored
    // credential, so an authenticated fetch or push uses the header alone.
    for key in ["credential.helper", "core.askPass"] {
        let blanked = super::run_git_command(
            temp.path(),
            &["config", "--get", key],
            std::time::Duration::from_secs(5),
            Some(&transport),
        )
        .expect("ran");
        assert!(blanked.ok(), "{key}: {}", blanked.stderr);
        assert_eq!(blanked.stdout.trim(), "", "{key} must be blank");
    }

    let run = super::run_git_command(
        temp.path(),
        &["ls-remote", "https://127.0.0.1:1/repo.git"],
        std::time::Duration::from_secs(5),
        Some(&transport),
    )
    .expect("ran");
    assert!(!run.ok());
    assert!(
        !run.stderr.contains("not allowed"),
        "https must clear the transport hardening: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("unable to access") || run.stderr.contains("Failed to connect"),
        "https must reach a connection attempt: {}",
        run.stderr
    );
}
