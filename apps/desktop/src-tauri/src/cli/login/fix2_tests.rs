use super::interrupt::Interrupt;
use super::test_support::ConnectDouble;
use super::tests::{fixture, stored};
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Condvar, Mutex,
};

#[derive(Clone)]
struct LateSave {
    store: Arc<CredentialStore>,
    interrupt: Interrupt,
    release: Arc<(Mutex<bool>, Condvar)>,
    resolved: Arc<AtomicBool>,
    deletes: Arc<AtomicUsize>,
    commits: bool,
    reason: &'static str,
}
impl LoginStore for LateSave {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.store.read_stored_all()
    }
    fn save(
        &self,
        token: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.interrupt.trigger();
        let (lock, event) = &*self.release;
        let (released, _) = event
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |value| {
                !*value
            })
            .unwrap();
        assert!(*released, "waiting acknowledgement never released the save");
        let result = if self.commits {
            self.store.save(token, &|_| {})
        } else {
            Err(self.reason.into())
        };
        self.resolved.store(true, Ordering::SeqCst);
        result
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.store.delete()
    }
}

struct OutcomeWriter {
    bytes: Vec<u8>,
    resolved: Arc<AtomicBool>,
    early: Arc<AtomicBool>,
    waiting: Arc<AtomicBool>,
    response_sent: Arc<AtomicBool>,
    release: Arc<(Mutex<bool>, Condvar)>,
}
impl Write for OutcomeWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.resolved.load(Ordering::SeqCst)
            && (bytes.starts_with(b"Signed in") || bytes.starts_with(b"Couldn't sign you in"))
        {
            self.early.store(true, Ordering::SeqCst);
        }
        if bytes.starts_with(b"Stopping once your keychain responds.") {
            assert!(
                self.response_sent.load(Ordering::SeqCst),
                "waiting printed before cleanup's response"
            );
            assert!(
                !self.resolved.load(Ordering::SeqCst),
                "waiting printed after save resolution"
            );
            self.waiting.store(true, Ordering::SeqCst);
            let (lock, signal) = &*self.release;
            *lock.lock().unwrap() = true;
            signal.notify_all();
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn interrupted_save_case(commits: bool, reason: &'static str, expected: &str) {
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let response_sent = Arc::new(AtomicBool::new(false));
    let event = response_sent.clone();
    let mut responses = vec![
        fixture("issued"),
        fixture("login"),
        fixture("secrets-unavailable"),
    ];
    if commits {
        responses.extend([
            (String::new(), "204 No Content"),
            (String::new(), "204 No Content"),
        ]);
    }
    let double = ConnectDouble::serve_with_after_delete_hook(
        responses,
        Arc::new(move || {
            event.store(true, Ordering::SeqCst);
        }),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let store = Arc::new(CredentialStore::for_test(
        &double.origin,
        OriginSource::Command,
        None,
        Some(path.clone()),
    ));
    store.save(&stored("old-bearer"), &|_| {}).unwrap();
    let resolved = Arc::new(AtomicBool::new(false));
    let early = Arc::new(AtomicBool::new(false));
    let deletes = Arc::new(AtomicUsize::new(0));
    let interrupt = Interrupt::new();
    let waiting = Arc::new(AtomicBool::new(false));
    let wrapped = LateSave {
        store: store.clone(),
        interrupt: interrupt.clone(),
        release: release.clone(),
        resolved: resolved.clone(),
        deletes: deletes.clone(),
        commits,
        reason,
    };
    let mut stdout = OutcomeWriter {
        bytes: Vec::new(),
        resolved: resolved.clone(),
        early: early.clone(),
        waiting: waiting.clone(),
        response_sent: response_sent.clone(),
        release: release.clone(),
    };
    let mut stderr = OutcomeWriter {
        bytes: Vec::new(),
        resolved,
        early: early.clone(),
        waiting: waiting.clone(),
        response_sent: response_sent.clone(),
        release: release.clone(),
    };
    let error = login_with_output(
        &double.origin,
        &wrapped,
        &mut stdout,
        &mut stderr,
        |_| Box::pin(async {}),
        &interrupt,
    )
    .await
    .unwrap_err();
    assert_eq!(failure_exit_code(&error), 130);
    assert!(
        waiting.load(Ordering::SeqCst),
        "blocked save never acknowledged the interrupt"
    );
    assert_eq!(
        deletes.load(Ordering::SeqCst),
        0,
        "failed cleanup deleted a credential"
    );
    assert!(
        !early.load(Ordering::SeqCst),
        "outcome printed before the save resolved"
    );
    let stdout = String::from_utf8(stdout.bytes).unwrap();
    let stderr = String::from_utf8(stderr.bytes).unwrap();
    let waiting_lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("Stopping once your keychain responds."))
        .collect();
    assert_eq!(
        waiting_lines,
        ["Stopping once your keychain responds. Press Ctrl-C again to stop now."]
    );
    if commits {
        assert!(
            store
                .read_stored()
                .unwrap()
                .is_some_and(|saved| saved.token.as_str() == "sitecmd_pat_FIXTURE"),
            "live committed token was forgotten"
        );
        let suffix = if cfg!(unix) {
            ", which only your user account can read"
        } else {
            ""
        };
        assert_eq!(
            stdout,
            format!(
                "Signed in to your SiteCMD account. The token is saved in {}{suffix}.\n",
                path.display()
            )
        );
        assert!(!stderr.contains("Couldn't sign you in"));
        assert!(stderr.contains("Revoked this computer's earlier SiteCMD token."));
        assert_eq!(double.live.lock().unwrap().len(), 1);
        let logout = logout_with(&double.origin, &store, &mut Vec::new())
            .await
            .unwrap();
        assert!(logout.starts_with("Signed out."));
        assert!(store.read_stored_all().unwrap().is_empty());
    } else {
        assert!(stdout.is_empty());
        assert!(stderr.ends_with(&format!("{expected}\n")));
        assert_eq!(stderr.matches("Couldn't sign you in").count(), 1);
        assert!(
            store
                .read_stored()
                .unwrap()
                .is_some_and(|saved| saved.token.as_str() == "old-bearer"),
            "failed save changed the earlier sign-in"
        );
    }
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), if commits { 5 } else { 3 });
    assert!(
        requests[2].contains("Bearer sitecmd_pat_FIXTURE"),
        "cleanup used the wrong bearer"
    );
    if commits {
        assert!(
            requests[3].contains("Bearer old-bearer"),
            "earlier bearer was not retired"
        );
        assert!(
            requests[4].contains("Bearer sitecmd_pat_FIXTURE"),
            "later logout could not revoke the saved token"
        );
        assert!(double.live.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn login_interrupted_committed_save_keeps_live_token_and_prints_w3() {
    // Bug: a blocked save can misquote its waiting line, remain silent or lose a committed token.
    interrupted_save_case(true, "could not save to the system credential store", "").await;
}

#[tokio::test]
async fn login_interrupted_failed_save_prints_approved_recovery_after_resolution() {
    // Bug: failed cleanup can print an unapproved reason or an outcome before the save resolves.
    for (reason, expected) in [
        ("private credential storage is unavailable", "Couldn't sign you in, because this computer couldn't save your sign-in (the credentials file couldn't be written). Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again."),
        ("could not write the private credential file", "Couldn't sign you in, because this computer couldn't save your sign-in (the credentials file couldn't be written). Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again."),
        ("could not save to the system credential store", "Couldn't sign you in, because this computer couldn't save your sign-in. Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again."),
    ] { interrupted_save_case(false, reason, expected).await; }
}

#[tokio::test]
async fn login_file_commit_survives_post_persist_sync_failure() {
    // Bug: a post-persist sync failure can revoke committed N and forget the overwritten F1.
    let double = ConnectDouble::serve(
        vec![
            fixture("issued"),
            fixture("login"),
            (String::new(), "204 No Content"),
        ],
        None,
        &["old-bearer"],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(CredentialStore::for_test(
        &double.origin,
        OriginSource::Command,
        None,
        Some(dir.path().join("credentials.json")),
    ));
    store.save(&stored("old-bearer"), &|_| {}).unwrap();
    store.test_faults.post_persist.store(true, Ordering::SeqCst);
    let mut stderr = Vec::new();
    let result = login_with(&double.origin, &store, &mut stderr, |_| Box::pin(async {})).await;
    assert!(
        result.is_ok(),
        "completed file persist was reported as a failed save"
    );
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[2].contains("Bearer old-bearer"),
        "overwritten F1 was not retired"
    );
    assert!(
        !requests[2].contains("Bearer sitecmd_pat_FIXTURE"),
        "committed N was revoked"
    );
    assert!(
        store
            .read_stored()
            .unwrap()
            .is_some_and(|saved| saved.token.as_str() == "sitecmd_pat_FIXTURE"),
        "committed file token was shadowed or lost"
    );
    assert_eq!(double.live.lock().unwrap().len(), 1);
    assert!(String::from_utf8(stderr)
        .unwrap()
        .contains("Revoked this computer's earlier SiteCMD token."));
}
