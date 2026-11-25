use super::force_exit_tests::{raise_interrupt, wait_for_child};
use super::interrupt::Interrupt;
use super::test_support::ConnectDouble;
use super::tests::{fixture, stored};
use super::*;
use std::sync::Mutex;

#[derive(Clone)]
struct CommittingSave {
    store: Arc<CredentialStore>,
    interrupt: Interrupt,
    during_save: bool,
    blocked_tidy: bool,
}
impl LoginStore for CommittingSave {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.store.read_stored_all()
    }
    fn save(
        &self,
        token: &StoredToken,
        on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        let location = self.store.save(token, on_commit)?;
        if self.during_save {
            raise_interrupt();
            await_first_signal(&self.interrupt);
            if self.blocked_tidy {
                std::thread::park_timeout(Duration::from_secs(30));
            }
        }
        Ok(location)
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        panic!("forced exit must leave the committed record available")
    }
}

fn await_first_signal(interrupt: &Interrupt) {
    let started = std::time::Instant::now();
    while !interrupt.triggered() {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "signal listener did not receive SIGINT"
        );
        std::thread::yield_now();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_second_interrupt_reports_committed_custody() {
    // Bug: a forced exit during committed but blocked tidy-up can report W246 and strand the earlier token silently.
    const CHILD: &str = "SITECMD_COMMITTED_INTERRUPT_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = std::path::PathBuf::from(path);
        let mode = std::env::var("SITECMD_COMMITTED_INTERRUPT_MODE").unwrap();
        let during_save = mode != "after-save";
        let blocked_tidy = mode == "blocked-tidy";
        let interrupt = Interrupt::new();
        let _listener = interrupt.listen().await.unwrap();
        let signal = interrupt.clone();
        let observed = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = observed.clone();
        let requests_path = path.join("requests.json");
        let mut responses = vec![fixture("issued"), fixture("login")];
        if during_save {
            responses.push(if mode == "cleanup-failed" {
                fixture("secrets-unavailable")
            } else {
                (String::new(), "204 No Content")
            });
        }
        responses.push((String::new(), "204 No Content"));
        let double = ConnectDouble::serve_with_delete_observer(
            responses,
            Arc::new(move |request| {
                let mut requests = captured.lock().unwrap();
                requests.push(request.to_owned());
                std::fs::write(&requests_path, serde_json::to_vec(&*requests).unwrap()).unwrap();
                if blocked_tidy
                    || request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer old-bearer")
                {
                    // Keep the earlier DELETE unresolved while the listener handles the second signal.
                    tokio::task::block_in_place(|| {
                        if !during_save {
                            raise_interrupt();
                            await_first_signal(&signal);
                        }
                        raise_interrupt();
                        std::thread::park_timeout(Duration::from_secs(30));
                    });
                }
            }),
        )
        .await;
        std::fs::write(path.join("origin"), &double.origin).unwrap();
        let concrete = Arc::new(CredentialStore::for_test(
            &double.origin,
            OriginSource::Command,
            None,
            Some(path.join("credentials.json")),
        ));
        concrete.save(&stored("old-bearer"), &|_| {}).unwrap();
        let store = CommittingSave {
            store: concrete,
            interrupt: interrupt.clone(),
            during_save,
            blocked_tidy,
        };
        let _ = login_with_output(
            &double.origin,
            &store,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
            |_| Box::pin(async {}),
            &interrupt,
        )
        .await;
        panic!("second interrupt returned instead of exiting");
    }
    for mode in [
        "blocked-tidy",
        "cleanup-failed",
        "cleanup-succeeded",
        "after-save",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cli::login::committed_exit_tests::login_second_interrupt_reports_committed_custody"])
            .env(CHILD, dir.path())
            .env("SITECMD_COMMITTED_INTERRUPT_MODE", mode)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let output = wait_for_child(child).await;
        assert_eq!(
            output.status.code(),
            Some(130),
            "force-exit variant: {mode}"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stderr.contains("SiteCMD could not revoke this computer's earlier token. Revoke it on your account's Personal tokens page.\n"), "missing earlier-token recovery instruction");
        assert!(
            !stderr.contains("Couldn't sign you in"),
            "committed save claimed to have failed"
        );
        let origin = std::fs::read_to_string(dir.path().join("origin")).unwrap();
        let store = CredentialStore::for_test(
            &origin,
            OriginSource::Command,
            None,
            Some(dir.path().join("credentials.json")),
        );
        assert!(
            store
                .read_stored()
                .unwrap()
                .unwrap()
                .token
                .as_str()
                .starts_with("sitecmd_pat_FIXTURE"),
            "replacement was not stored"
        );
        let requests: Vec<String> =
            serde_json::from_slice(&std::fs::read(dir.path().join("requests.json")).unwrap())
                .unwrap();
        assert_eq!(
            requests.len(),
            if mode == "after-save" || mode == "blocked-tidy" {
                1
            } else {
                2
            }
        );
        assert!(requests
            .iter()
            .all(|request| request.starts_with("DELETE /v1/account/tokens/current ")));
        if mode != "blocked-tidy" {
            assert!(
                requests
                    .last()
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("authorization: bearer old-bearer"),
                "earlier credential was not used for its revoke"
            );
        }
        if mode != "after-save" {
            assert!(
                requests[0]
                    .to_ascii_lowercase()
                    .contains("authorization: bearer sitecmd_pat_fixture"),
                "cleanup used the wrong credential"
            );
        }
        if mode == "cleanup-succeeded" {
            assert!(
                !stdout.contains("Signed in"),
                "revoked replacement claimed to be live"
            );
        } else {
            let expected = format!("Signed in to your SiteCMD account. The token is saved in {}, which only your user account can read.\n", dir.path().join("credentials.json").display());
            assert!(
                stdout.contains(&expected),
                "committed live token was not reported"
            );
        }
    }
}
