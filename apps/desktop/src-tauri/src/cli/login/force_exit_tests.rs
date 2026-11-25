use super::interrupt::Interrupt;
use super::test_support::ConnectDouble;
use super::tests::{fixture, stored};
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Condvar, Mutex,
};

#[derive(Clone)]
struct UnresolvedSave {
    store: Arc<CredentialStore>,
}
impl LoginStore for UnresolvedSave {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.store.read_stored_all()
    }
    fn save(
        &self,
        _: &StoredToken,
        _on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        raise_interrupt();
        let mutex = Mutex::new(false);
        let _waited = Condvar::new()
            .wait_timeout(mutex.lock().unwrap(), Duration::from_secs(30))
            .unwrap();
        Err("save never resolved".into())
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        panic!("unresolved save cannot delete the earlier sign-in")
    }
}

struct SecondInterruptWriter {
    response_sent: Arc<AtomicBool>,
}
impl Write for SecondInterruptWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().write_all(bytes)?;
        if bytes.starts_with(b"Stopping once your keychain responds.") {
            assert!(
                self.response_sent.load(Ordering::SeqCst),
                "waiting preceded cleanup's response"
            );
            raise_interrupt();
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

#[tokio::test]
async fn login_second_interrupt_exits_without_waiting_for_save() {
    // Bug: a signal listener that is not re-armed ignores the second real Ctrl-C during a blocked save.
    const CHILD: &str = "SITECMD_SECOND_INTERRUPT_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let sent = Arc::new(AtomicBool::new(false));
        let observed = sent.clone();
        let double = ConnectDouble::serve_with_after_delete_hook(
            vec![
                fixture("issued"),
                fixture("login"),
                fixture("secrets-unavailable"),
            ],
            Arc::new(move || {
                observed.store(true, Ordering::SeqCst);
            }),
        )
        .await;
        let concrete = Arc::new(CredentialStore::for_test(
            &double.origin,
            OriginSource::Command,
            None,
            Some(path.into()),
        ));
        concrete.save(&stored("old-bearer"), &|_| {}).unwrap();
        let interrupt = Interrupt::new();
        let _listener = interrupt.listen().await.unwrap();
        let store = UnresolvedSave { store: concrete };
        let mut stderr = SecondInterruptWriter {
            response_sent: sent,
        };
        let _ = login_with_output(
            &double.origin,
            &store,
            &mut Vec::new(),
            &mut stderr,
            |_| Box::pin(async {}),
            &interrupt,
        )
        .await;
        panic!("second interrupt returned instead of exiting");
    }
    let dir = tempfile::tempdir().unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::login::force_exit_tests::login_second_interrupt_exits_without_waiting_for_save",
        ])
        .env(CHILD, dir.path().join("credentials.json"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let output = wait_for_child(child).await;
    assert_eq!(output.status.code(), Some(130));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stderr.contains("Stopping once your keychain responds. Press Ctrl-C again to stop now.\n")
    );
    assert!(stderr.ends_with("Couldn't sign you in, because this computer couldn't save your sign-in. Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again.\n"));
    assert!(!stdout.contains("Signed in"));
    assert!(!stderr.contains("Signed in"));
    assert_eq!(stderr.matches("Couldn't sign you in").count(), 1);
}

pub(super) fn raise_interrupt() {
    // Only subprocess children call this, so the test runner never receives SIGINT.
    assert_eq!(
        unsafe { libc::raise(libc::SIGINT) },
        0,
        "could not send child SIGINT"
    );
}

pub(super) async fn wait_for_child(mut child: std::process::Child) -> std::process::Output {
    let started = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("second interrupt did not exit promptly");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    child.wait_with_output().unwrap()
}
