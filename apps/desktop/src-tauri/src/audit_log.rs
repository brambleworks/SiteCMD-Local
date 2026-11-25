//! Best-effort JSONL audit log for sensitive operations.
//!
//! Write failures never block the user operation; this is observability, not a
//! security boundary.

use crate::time::now_utc;

use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

const AUDIT_LOG_FILENAME: &str = "audit.log";

#[derive(Serialize)]
struct Entry<'a> {
    ts: String,
    op: &'a str,
    detail: serde_json::Value,
    result: &'a str,
}

/// Append a redacted audit entry without failing the caller.
/// Writes use a blocking task when a Tokio runtime is available and run inline
/// otherwise, including from the panic hook.
pub fn record(op: &str, detail: serde_json::Value, result: &str) {
    let Some(path) = audit_log_path() else { return };
    let op = op.to_string();
    let result = result.to_string();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || {
                record_to(&path, &op, detail, &result);
            });
        }
        Err(_) => {
            record_to(&path, &op, detail, &result);
        }
    }
}

/// Append to a specific path. Used for tests and for the public `record`
/// wrapper. Best-effort.
fn record_to(path: &Path, op: &str, detail: serde_json::Value, result: &str) {
    if let Some(parent) = path.parent() {
        if crate::app_identity::ensure_private_directory(parent).is_err() {
            return;
        }
    }
    let entry = Entry {
        ts: now_utc().to_rfc3339(),
        op,
        detail,
        result,
    };
    let Ok(line) = serde_json::to_string(&entry) else {
        return;
    };
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let Ok(mut file) = options.open(path) else {
        return;
    };
    if crate::app_identity::restrict_open_private_file(&file).is_err() {
        return;
    }
    let _ = writeln!(file, "{line}");
}

fn audit_log_path() -> Option<PathBuf> {
    let mut p = crate::app_identity::default_storage_dir()?;
    p.push(AUDIT_LOG_FILENAME);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_to_appends_jsonl_entry_with_op_and_result() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit.log");

        record_to(&path, "test.op", serde_json::json!({"k": 1}), "ok");

        let log = std::fs::read_to_string(&path).expect("read audit log");
        assert!(log.contains(r#""op":"test.op""#), "missing op: {log}");
        assert!(log.contains(r#""result":"ok""#), "missing result: {log}");
        assert!(log.contains(r#""k":1"#), "missing detail payload: {log}");
        assert!(log.ends_with('\n'), "expected trailing newline: {log:?}");
    }

    #[test]
    fn record_to_appends_multiple_entries_on_separate_lines() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit.log");

        record_to(&path, "a", serde_json::json!({}), "ok");
        record_to(&path, "b", serde_json::json!({}), "fail");

        let log = std::fs::read_to_string(&path).expect("read audit log");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "expected two JSONL lines, got {lines:?}");
        assert!(lines[0].contains(r#""op":"a""#));
        assert!(lines[0].contains(r#""result":"ok""#));
        assert!(lines[1].contains(r#""op":"b""#));
        assert!(lines[1].contains(r#""result":"fail""#));
    }

    #[test]
    fn record_to_creates_parent_directory_if_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nested").join("dir").join("audit.log");

        record_to(&path, "x", serde_json::json!({}), "ok");

        assert!(path.exists(), "audit log not created: {}", path.display());
    }

    #[cfg(unix)]
    #[test]
    fn record_to_creates_an_owner_only_log() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit.log");
        record_to(&path, "x", serde_json::json!({}), "ok");

        let mode = std::fs::metadata(path)
            .expect("audit metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The writer persists caller-provided detail verbatim; callers own redaction.
    #[test]
    fn record_to_does_not_redact_callers_payload_so_callers_must_redact() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit.log");
        let raw_secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        record_to(
            &path,
            "test.canary",
            serde_json::json!({ "raw_token": raw_secret }),
            "ok",
        );

        let log = std::fs::read_to_string(&path).expect("read audit log");
        assert!(
            log.contains(raw_secret),
            "audit_log writes detail verbatim; if you change that contract, every existing call site needs auditing for redaction. log={log}"
        );
    }
}
