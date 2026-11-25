use super::interrupt::Interrupt;
use super::test_support::ConnectDouble;
use super::tests::{fixture, stored};
use super::*;
use std::sync::Arc;

#[derive(Clone)]
struct InterruptedSave {
    store: Arc<CredentialStore>,
    interrupt: Interrupt,
    commits: bool,
    deletion_fails: bool,
}

impl LoginStore for InterruptedSave {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.store.read_stored_all()
    }
    fn save(
        &self,
        token: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.interrupt.trigger();
        if self.commits {
            self.store.save(token, &|_| {})
        } else {
            Err("could not save to the system credential store".into())
        }
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        if self.deletion_fails {
            Err("could not remove stored SiteCMD credentials".into())
        } else {
            self.store.delete()
        }
    }
}

#[tokio::test]
async fn login_interrupt_before_save_finishes_retires_the_minted_token() {
    // Bug: Ctrl-C during a blocked save can strand N or lose exit 130 after local cleanup fails.
    for (commits, deletion_fails) in [(false, false), (true, false), (true, true)] {
        let responses = if commits {
            vec![
                fixture("issued"),
                fixture("login"),
                (String::new(), "204 No Content"),
                (String::new(), "204 No Content"),
            ]
        } else {
            vec![
                fixture("issued"),
                fixture("login"),
                (String::new(), "204 No Content"),
            ]
        };
        let double = ConnectDouble::serve(responses, None, &["old-bearer"]).await;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(CredentialStore::for_test(
            &double.origin,
            OriginSource::Command,
            None,
            Some(dir.path().join("credentials.json")),
        ));
        store.save(&stored("old-bearer"), &|_| {}).unwrap();
        let interrupt = Interrupt::new();
        let wrapped = InterruptedSave {
            store: store.clone(),
            interrupt: interrupt.clone(),
            commits,
            deletion_fails,
        };
        let error = login_with_interrupt(
            &double.origin,
            &wrapped,
            &mut Vec::new(),
            |_| Box::pin(async {}),
            &interrupt,
        )
        .await
        .unwrap_err();
        assert_eq!(failure_exit_code(&error), 130);
        let requests = double.captured.await.unwrap();
        assert!(
            requests[2].contains("Bearer sitecmd_pat_FIXTURE"),
            "interrupted save did not retire N"
        );
        if commits {
            assert!(
                double.live.lock().unwrap().is_empty(),
                "a committed interrupted save stranded a prior bearer"
            );
            assert_eq!(store.read_stored_all().unwrap().is_empty(), !deletion_fails);
        } else {
            assert_eq!(requests.len(), 3);
            assert!(
                store.read_stored().unwrap().unwrap().token.as_str() == "old-bearer",
                "failed interrupted save lost the earlier sign-in"
            );
        }
    }
}

#[tokio::test]
async fn login_interrupt_after_save_finishes_old_revoke_and_warns_on_failure() {
    // Bug: Ctrl-C after persistence can hide the saved sign-in or forget its earlier-token revocation.
    for failed_revoke in [false, true] {
        let interrupt = Interrupt::new();
        let event = interrupt.clone();
        let response = if failed_revoke {
            fixture("secrets-unavailable")
        } else {
            (String::new(), "204 No Content")
        };
        let double = ConnectDouble::serve_with_delete_hook(
            vec![fixture("issued"), fixture("login"), response],
            Arc::new(move || event.trigger()),
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
        let suffix = if cfg!(unix) {
            ", which only your user account can read"
        } else {
            ""
        };
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            format!(
                "Signed in to your SiteCMD account. The token is saved in {}{suffix}.\n",
                dir.path().join("credentials.json").display()
            )
        );
        assert!(
            store.read_stored().unwrap().unwrap().token.as_str() == "sitecmd_pat_FIXTURE",
            "post-save interruption removed the committed token"
        );
        let requests = double.captured.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(
            requests[2].contains("Bearer old-bearer"),
            "earlier revocation was abandoned"
        );
        if failed_revoke {
            assert!(String::from_utf8(stderr).unwrap().contains("SiteCMD could not revoke this computer's earlier token. Revoke it on your account's Personal tokens page."));
        }
    }
}

#[derive(Clone)]
struct BlockedSave {
    interrupt: Interrupt,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    revoked_before_return: Arc<std::sync::atomic::AtomicBool>,
}
impl LoginStore for BlockedSave {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        Ok(Vec::new())
    }
    fn save(
        &self,
        _: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.interrupt.trigger();
        let (lock, event) = &*self.release;
        let (released, _) = event
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(2), |released| {
                !*released
            })
            .unwrap();
        self.revoked_before_return
            .store(*released, std::sync::atomic::Ordering::SeqCst);
        Err("could not save to the system credential store".into())
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        panic!("save never committed")
    }
}

#[tokio::test]
async fn login_interrupt_revokes_while_a_blocking_save_is_unresolved() {
    // Bug: Ctrl-C can leave N live for as long as a keychain prompt remains blocked.
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let complete = release.clone();
    let double = ConnectDouble::serve_with_delete_hook(
        vec![
            fixture("issued"),
            fixture("login"),
            (String::new(), "204 No Content"),
        ],
        Arc::new(move || {
            let (lock, event) = &*complete;
            *lock.lock().unwrap() = true;
            event.notify_all();
        }),
    )
    .await;
    let interrupt = Interrupt::new();
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = BlockedSave {
        interrupt: interrupt.clone(),
        release,
        revoked_before_return: observed.clone(),
    };
    let error = login_with_interrupt(
        &double.origin,
        &store,
        &mut Vec::new(),
        |_| Box::pin(async {}),
        &interrupt,
    )
    .await
    .unwrap_err();
    assert_eq!(failure_exit_code(&error), 130);
    assert!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        "cleanup waited for the blocked save to finish"
    );
    let requests = double.captured.await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[2].contains("Bearer sitecmd_pat_FIXTURE"),
        "blocked save did not retire the minted token"
    );
}
