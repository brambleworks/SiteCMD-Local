use super::interrupt::Interrupt;
use super::test_support::ConnectDouble;
use super::tests::fixture;
use super::*;
use crate::cli::credential_store::test_support::seed_pair;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone)]
struct NoSaveStore {
    store: Arc<CredentialStore>,
    saves: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
}
impl LoginStore for NoSaveStore {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.store.read_stored_all()
    }
    fn save(
        &self,
        _: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        Err("save was not expected".into())
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Err("delete was not expected".into())
    }
}

fn guarded(store: Arc<CredentialStore>) -> NoSaveStore {
    NoSaveStore {
        store,
        saves: Arc::new(AtomicUsize::new(0)),
        deletes: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn login_interrupt_during_pending_sleep_stops_before_another_poll() {
    // Bug: an interrupted pending sleep can hang when its cancellation arm is missing.
    let double = ConnectDouble::serve(
        vec![fixture("issued"), fixture("pending"), fixture("expired")],
        None,
        &["old-bearer", "file-bearer"],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let store = guarded(seed_pair(
        &double.origin,
        &dir.path().join("credentials.json"),
    ));
    let interrupt = Interrupt::new();
    let event = interrupt.clone();
    let once = AtomicBool::new(false);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        login_with_output(
            &double.origin,
            &store,
            &mut stdout,
            &mut stderr,
            move |_| {
                if !once.swap(true, Ordering::SeqCst) {
                    event.trigger();
                }
                Box::pin(std::future::pending())
            },
            &interrupt,
        ),
    )
    .await
    .expect("Ctrl-C did not cancel the pending poll sleep")
    .unwrap_err();
    assert_eq!(failure_exit_code(&error), 130);
    assert_eq!(store.saves.load(Ordering::SeqCst), 0);
    assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(store.store.read_stored_all().unwrap().len(), 2);
    assert!(stdout.is_empty());
    assert!(!String::from_utf8(stderr)
        .unwrap()
        .contains("Couldn't sign you in"));
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST /v1/cli/token "));
}

async fn interrupted_final_poll(failed_revoke: bool) {
    let interrupt = Interrupt::new();
    let event = interrupt.clone();
    let response = if failed_revoke {
        fixture("secrets-unavailable")
    } else {
        (String::new(), "204 No Content")
    };
    let double = ConnectDouble::serve_with_poll_hook(
        vec![fixture("issued"), fixture("login"), response],
        Arc::new(move || event.trigger()),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let store = guarded(seed_pair(
        &double.origin,
        &dir.path().join("credentials.json"),
    ));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = login_with_output(
        &double.origin,
        &store,
        &mut stdout,
        &mut stderr,
        |_| Box::pin(async {}),
        &interrupt,
    )
    .await
    .unwrap_err();
    assert_eq!(failure_exit_code(&error), 130);
    assert_eq!(
        store.saves.load(Ordering::SeqCst),
        0,
        "pre-save interruption still attempted a save"
    );
    assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(store.store.read_stored_all().unwrap().len(), 2);
    assert!(stdout.is_empty());
    let stderr = String::from_utf8(stderr).unwrap();
    if failed_revoke {
        assert!(stderr.ends_with("Couldn't sign you in, because this computer couldn't save your sign-in. Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again.\n"));
        assert_eq!(stderr.matches("Couldn't sign you in").count(), 1);
    } else {
        assert!(!stderr.contains("Couldn't sign you in"));
    }
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].starts_with("DELETE /v1/account/tokens/current "));
    assert!(
        requests[2].contains("Bearer sitecmd_pat_FIXTURE"),
        "cleanup did not use N"
    );
    assert!(
        requests[2..]
            .iter()
            .all(|request| !request.contains("Bearer old-bearer")
                && !request.contains("Bearer file-bearer")),
        "pre-save interruption retired an earlier bearer"
    );
    assert_eq!(
        double.live.lock().unwrap().len(),
        if failed_revoke { 3 } else { 2 }
    );
}

#[tokio::test]
async fn login_interrupt_in_final_poll_revokes_n_without_saving_or_losing_earlier_tokens() {
    // Bug: dropping or ignoring an interrupted final poll can strand N or discard an earlier sign-in.
    interrupted_final_poll(false).await;
}

#[tokio::test]
async fn login_interrupt_in_final_poll_prints_approved_recovery_when_revoke_fails() {
    // Bug: a failed pre-save cleanup can leave a live token without the approved recovery instruction.
    interrupted_final_poll(true).await;
}

#[derive(Clone)]
struct ImmediateFailure {
    interrupt: Interrupt,
    reason: &'static str,
}
impl LoginStore for ImmediateFailure {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        Ok(Vec::new())
    }
    fn save(
        &self,
        _: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.interrupt.trigger();
        Err(self.reason.into())
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        panic!("failed save cannot delete an earlier sign-in")
    }
}

#[tokio::test]
async fn login_recovery_prints_exact_approved_text_with_optional_reason() {
    // Bug: recovery output can expose an unapproved store reason or retain an empty parenthesis.
    for (reason, expected) in [
        ("private credential storage is unavailable", "Couldn't sign you in, because this computer couldn't save your sign-in (the credentials file couldn't be written). Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again."),
        ("could not write the private credential file", "Couldn't sign you in, because this computer couldn't save your sign-in (the credentials file couldn't be written). Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again."),
        ("could not save to the system credential store", "Couldn't sign you in, because this computer couldn't save your sign-in. Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again."),
    ] {
        let double = ConnectDouble::serve(vec![fixture("issued"), fixture("login"), fixture("secrets-unavailable")], None, &[]).await;
        let interrupt = Interrupt::new();
        let store = ImmediateFailure { interrupt: interrupt.clone(), reason };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let error = login_with_output(&double.origin, &store, &mut stdout, &mut stderr, |_| Box::pin(async {}), &interrupt).await.unwrap_err();
        assert_eq!(failure_exit_code(&error), 130);
        assert!(stdout.is_empty());
        let stderr = String::from_utf8(stderr).unwrap();
        assert_eq!(stderr.lines().last(), Some(expected));
        assert_eq!(stderr.matches("Couldn't sign you in").count(), 1);
        assert!(!stderr.contains(reason), "raw store reason escaped its approved mapping");
        assert_eq!(double.captured.await.unwrap().len(), 3);
    }
}
