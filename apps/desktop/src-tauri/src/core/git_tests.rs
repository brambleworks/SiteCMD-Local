use super::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Build a single log line with the same separator the production code uses.
fn log_line(fields: &[&str]) -> String {
    fields.join("\x1f")
}

#[test]
fn commit_to_deploy_event_builds_expected_shape() {
    let commit = GitCommit {
        hash: "abc123def456".to_string(),
        short_hash: "abc123d".to_string(),
        message: "Fix login bug\n\nLonger body text".to_string(),
        author: "Kyle Piontek".to_string(),
        date: "2026-04-19T10:00:00Z".to_string(),
        relative_date: "3 hours ago".to_string(),
    };
    let event = commit_to_deploy_event(&commit, 7);

    assert_eq!(event.id, 0, "id must be 0 so insert auto-assigns");
    assert_eq!(event.project_id, 7);
    assert_eq!(event.event_type, crate::db::EventType::Deploy);
    assert_eq!(event.severity, crate::db::EventSeverity::Info);
    assert_eq!(event.source, crate::db::EventSource::Git);
    assert_eq!(event.source_id.as_deref(), Some("abc123def456"));
    // Title is the first line of the message only.
    assert_eq!(event.title, "Fix login bug");
    assert_eq!(event.summary, "abc123d - Kyle Piontek");
    // The author date parses to epoch ms (not the now fallback).
    assert_eq!(
        event.occurred_at_ms,
        crate::db::timestamp_text_to_ms("2026-04-19T10:00:00Z").unwrap()
    );
    // detail carries the full commit payload verbatim.
    let detail: serde_json::Value = serde_json::from_str(event.detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["hash"], "abc123def456");
    assert_eq!(detail["short_hash"], "abc123d");
    assert_eq!(detail["author"], "Kyle Piontek");
    assert_eq!(detail["message"], "Fix login bug\n\nLonger body text");
    assert!(event.affected_check_ids.is_none());
    assert!(event.metadata.is_none());
}

#[test]
fn commit_to_deploy_event_falls_back_to_now_on_unparseable_date() {
    let before = chrono::Utc::now().timestamp_millis();
    let commit = GitCommit {
        hash: "deadbeef".to_string(),
        short_hash: "deadbee".to_string(),
        message: "single line".to_string(),
        author: "A".to_string(),
        date: "not-a-date".to_string(),
        relative_date: "just now".to_string(),
    };
    let event = commit_to_deploy_event(&commit, 1);
    let after = chrono::Utc::now().timestamp_millis();
    assert!(
        event.occurred_at_ms >= before && event.occurred_at_ms <= after,
        "unparseable date must fall back to Utc::now()"
    );
    // A single-line message becomes the title unchanged.
    assert_eq!(event.title, "single line");
}

#[test]
fn parse_log_line_accepts_well_formed_input() {
    let line = log_line(&[
        "abc123def456",
        "abc123d",
        "Initial commit",
        "Kyle Piontek",
        "2026-04-19T10:00:00Z",
        "3 hours ago",
    ]);
    let commit = parse_log_line(&line).expect("should parse");
    assert_eq!(commit.hash, "abc123def456");
    assert_eq!(commit.short_hash, "abc123d");
    assert_eq!(commit.message, "Initial commit");
    assert_eq!(commit.author, "Kyle Piontek");
    assert_eq!(commit.date, "2026-04-19T10:00:00Z");
    assert_eq!(commit.relative_date, "3 hours ago");
}

#[test]
fn parse_log_line_preserves_pipes_inside_message() {
    let line = log_line(&[
        "h",
        "s",
        "fix: foo | bar | baz",
        "me",
        "2026-04-19T10:00:00Z",
        "1d ago",
    ]);
    let commit = parse_log_line(&line).expect("should parse");
    assert_eq!(commit.message, "fix: foo | bar | baz");
    assert_eq!(commit.author, "me");
    assert_eq!(commit.relative_date, "1d ago");
}

#[test]
fn parse_log_line_rejects_malformed_input() {
    // Fewer than 6 fields = malformed log output, skip rather than panic.
    assert!(parse_log_line(&log_line(&["only", "three", "fields"])).is_none());
    assert!(parse_log_line("").is_none());
    assert!(
        parse_log_line(&log_line(&["h", "s", "m", "a", "d"])).is_none(),
        "5 fields = missing relative_date",
    );
}

#[test]
fn parse_log_output_skips_blank_and_malformed_lines() {
    let line1 = log_line(&[
        "hash1",
        "h1",
        "msg1",
        "author1",
        "2026-04-19T10:00:00Z",
        "1h ago",
    ]);
    let line2 = log_line(&[
        "hash2",
        "h2",
        "msg2",
        "author2",
        "2026-04-19T11:00:00Z",
        "2h ago",
    ]);
    let output = format!("{}\n\nmalformed line\n{}\n\n", line1, line2);
    let commits = parse_log_output(&output);
    assert_eq!(commits.len(), 2, "blanks + malformed lines must be dropped");
    assert_eq!(commits[0].hash, "hash1");
    assert_eq!(commits[1].hash, "hash2");
}

#[test]
fn parse_log_output_returns_empty_for_empty_string() {
    assert!(parse_log_output("").is_empty());
}

/// Owns a tempdir + its path so the dir is cleaned up when the test ends.
/// Derefs to `Path` so call sites can use `path.to_string_lossy`,
/// `path.join(...)`, etc. directly.
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

/// Init a git repo in a tempdir + create `commit_count` commits with
/// distinct messages. Returns a `TestRepo` that cleans up on drop.
fn make_repo(name: &str, commit_count: usize) -> TestRepo {
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

    for i in 1..=commit_count {
        let file = path.join(format!("file_{}_{}.txt", name, i));
        fs::write(&file, format!("contents {}\n", i)).expect("write");
        run(&["add", "."]);
        // Sleep 1s between commits so git's per-second timestamps differ.
        // The git log --format=%aI uses second-resolution ISO 8601.
        if i > 1 {
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        run(&["commit", "-q", "-m", &format!("commit {} from {}", i, name)]);
    }

    TestRepo { path, _dir: dir }
}

/// Init a git repo in a tempdir + create one commit per entry in `dates`,
/// pinning GIT_AUTHOR_DATE/GIT_COMMITTER_DATE so window assertions are
/// deterministic. Returns a `TestRepo` that cleans up on drop.
fn make_repo_with_dates(name: &str, dates: &[&str]) -> TestRepo {
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

    let run = |args: &[&str], extra_env: &[(&str, &str)]| {
        Command::new("git")
            .args(args)
            .current_dir(&path)
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .envs(extra_env.iter().copied())
            .output()
            .expect("git command")
    };

    run(&["init", "-q", "-b", "main"], &[]);
    run(&["config", "user.email", "test@example.com"], &[]);
    run(&["config", "user.name", "Test User"], &[]);
    run(&["config", "commit.gpgsign", "false"], &[]);

    for (i, date) in dates.iter().enumerate() {
        let file = path.join(format!("file_{}_{}.txt", name, i + 1));
        fs::write(&file, format!("contents {}\n", i + 1)).expect("write");
        run(&["add", "."], &[]);
        run(
            &[
                "commit",
                "-q",
                "-m",
                &format!("commit {} from {}", i + 1, name),
            ],
            &[("GIT_AUTHOR_DATE", *date), ("GIT_COMMITTER_DATE", *date)],
        );
    }

    TestRepo { path, _dir: dir }
}

/// Git runs `core.fsmonitor` as a hook command during index refresh when
/// the value is a path, so a repository's own `.git/config` is an
/// arbitrary-command vector. The control proves the installed git honors
/// the planted hook; the assertion proves the hardened spawn never does.
#[cfg(unix)]
#[test]
fn hardened_git_ignores_a_planted_fsmonitor_hook() {
    use std::os::unix::fs::PermissionsExt;

    let repo = make_repo("fsmonitor", 1);
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

    let status = get_git_status(&repo.to_string_lossy(), 5);
    assert!(
        status.is_git_repo,
        "hardened git must still read the repository"
    );
    assert!(run_git(&repo, &["status", "--porcelain"]).is_some());
    assert!(run_git(&repo, &["log", "-1", "--format=%H"]).is_some());
    assert!(checkout_head_and_clean(&repo.to_string_lossy()).is_some());

    assert!(
        !sentinel.exists(),
        "hardened git spawn ran the repository's planted core.fsmonitor hook"
    );
}

#[test]
fn hardened_command_neutralizes_config_and_rebuilds_the_environment() {
    let repo = make_repo("hardened-env", 1);
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
fn get_git_status_on_non_git_dir_returns_inactive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let status = get_git_status(&dir.path().to_string_lossy(), 10);
    assert!(
        !status.is_git_repo,
        "non-git dir must report is_git_repo=false"
    );
    assert!(status.commits.is_empty());
    assert!(status.branch.is_none());
    assert_eq!(status.total_commits, 0);
    assert!(!status.has_uncommitted);
}

#[test]
fn get_git_status_reports_branch_and_commits() {
    let path = make_repo("status", 3);
    let status = get_git_status(&path.to_string_lossy(), 10);

    assert!(status.is_git_repo);
    assert_eq!(status.branch.as_deref(), Some("main"));
    assert_eq!(status.commits.len(), 3);
    assert_eq!(status.total_commits, 3);
    assert!(
        !status.has_uncommitted,
        "no untracked files after every add+commit"
    );

    // Newest first: commit 3 is the most recent.
    assert_eq!(status.commits[0].message, "commit 3 from status");
    assert_eq!(status.commits[2].message, "commit 1 from status");

    // Each commit has hash + short hash + author populated.
    for commit in &status.commits {
        assert_eq!(commit.author, "Test User");
        assert_eq!(commit.hash.len(), 40, "full SHA should be 40 hex chars");
        assert!(!commit.short_hash.is_empty());
        assert!(!commit.date.is_empty());
        assert!(!commit.relative_date.is_empty());
    }
}

#[test]
fn get_git_status_respects_commit_limit() {
    let path = make_repo("limit", 5);
    let status = get_git_status(&path.to_string_lossy(), 2);

    // total_commits reflects the whole repo even when commits is capped.
    assert_eq!(status.total_commits, 5);
    assert_eq!(status.commits.len(), 2);
    assert_eq!(status.commits[0].message, "commit 5 from limit");
}

#[test]
fn get_git_status_detects_uncommitted_changes() {
    let path = make_repo("dirty", 1);
    // Create an untracked file.
    fs::write(path.join("dirty.txt"), "uncommitted\n").expect("write");

    let status = get_git_status(&path.to_string_lossy(), 10);
    assert!(
        status.has_uncommitted,
        "untracked file must register as dirty"
    );
}

#[test]
fn checkout_provenance_names_a_merge_head() {
    let path = make_repo("merge-head", 1);
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
        get_git_status(&path.to_string_lossy(), 1).commits[0].hash,
        head
    );
}

#[test]
fn get_commits_since_filters_by_date() {
    let path = make_repo("since", 2);
    // Capture the date of the first commit so we can ask for commits
    // strictly after it.
    let first_status = get_git_status(&path.to_string_lossy(), 10);
    // commits[1] is older (newest first), so use its date as the cut.
    let cut = &first_status.commits[1].date;

    let after = get_commits_since(&path.to_string_lossy(), cut);
    assert!(
        !after.is_empty(),
        "at least one commit should be at-or-after the cut date"
    );
    assert!(
        after.iter().any(|c| c.message == "commit 2 from since"),
        "newest commit must be present",
    );
}

#[test]
fn get_commits_between_filters_to_the_window() {
    let path = make_repo_with_dates(
        "window",
        &[
            "2026-01-01T10:00:00Z",
            "2026-01-03T10:00:00Z",
            "2026-01-05T10:00:00Z",
        ],
    );

    let (commits, total) = get_commits_between(
        &path.to_string_lossy(),
        "2026-01-02T00:00:00.123456+00:00",
        "2026-01-04T00:00:00.123456+00:00",
    );

    assert_eq!(total, 1, "only the middle commit falls inside the window");
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].message, "commit 2 from window");
    assert_eq!(
        total,
        commits.len() as u32,
        "rev-list-backed total must agree with the listed commits when under the cap"
    );
}

#[test]
fn get_commits_between_on_non_repo_returns_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (commits, total) = get_commits_between(
        &dir.path().to_string_lossy(),
        "2026-01-01T00:00:00",
        "2026-01-02T00:00:00",
    );
    assert!(commits.is_empty(), "non-repo dir must yield no commits");
    assert_eq!(total, 0);
}

#[test]
fn get_recent_commits_delegates_to_get_git_status() {
    let path = make_repo("recent", 4);
    let recent = get_recent_commits(&path.to_string_lossy(), 3);
    let status = get_git_status(&path.to_string_lossy(), 3);

    assert_eq!(recent.len(), status.commits.len());
    assert_eq!(recent.len(), 3);
    for (a, b) in recent.iter().zip(status.commits.iter()) {
        assert_eq!(a.hash, b.hash);
    }
}

#[test]
fn get_recent_commits_on_non_git_dir_returns_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let commits = get_recent_commits(&dir.path().to_string_lossy(), 10);
    assert!(commits.is_empty());
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
