//! Complete credential custody even when the caller interrupts a blocking save.

use super::interrupt::Interrupt;
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

#[derive(Default)]
struct Custody {
    committed: Mutex<Option<StoreLocation>>,
    cleanup_succeeded: AtomicBool,
}

pub(super) struct ApprovedLogin {
    pub replacement: StoredToken,
    pub account: String,
    pub previous: Vec<StoredToken>,
}

pub(super) async fn finish_login(
    origin: &str,
    store: &impl LoginStore,
    approved: ApprovedLogin,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    interrupt: &Interrupt,
) -> Result<String, String> {
    let custody = Arc::new(Custody::default());
    let account = approved.account.clone();
    let earlier = approved
        .previous
        .iter()
        .any(|token| token.token.as_str() != approved.replacement.token.as_str());
    let completed = tokio::select! {
        biased;
        _ = interrupt.forced() => None,
        result = complete_login(origin, store, approved, stdout, stderr, interrupt, &custody) => Some(result),
    };
    if let Some(result) = completed {
        return result;
    }
    let committed = custody.committed.lock().unwrap().clone();
    if let Some(location) = committed {
        if earlier {
            let _ = writeln!(stderr, "{}", words::LOGIN_EARLIER_REVOKE_FAILED_WORDS);
        }
        if !custody.cleanup_succeeded.load(Ordering::SeqCst) {
            let _ = writeln!(stdout, "{}", signed_in(&account, &location));
        }
    } else {
        let _ = writeln!(stderr, "{}", words::recovery(None));
    }
    let _ = stdout.flush();
    let _ = stderr.flush();
    std::process::exit(130);
}

async fn complete_login(
    origin: &str,
    store: &impl LoginStore,
    approved: ApprovedLogin,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    interrupt: &Interrupt,
    custody: &Arc<Custody>,
) -> Result<String, String> {
    let ApprovedLogin {
        replacement,
        account,
        previous,
    } = approved;
    if interrupt.triggered() {
        if !revoke(origin, std::slice::from_ref(&replacement)).await {
            let _ = writeln!(stderr, "{}", words::recovery(None));
        }
        return Err(String::new());
    }
    interrupt.begin_save();
    let saving = store.clone();
    let token = replacement.clone();
    let signal = interrupt.clone();
    let saving_custody = custody.clone();
    let mut saving_task = tokio::task::spawn_blocking(move || {
        let on_commit = |location: &StoreLocation| {
            *saving_custody.committed.lock().unwrap() = Some(location.clone());
        };
        let result = saving.save(&token, &on_commit);
        if let Ok(location) = &result {
            on_commit(location);
        }
        signal.finish_save();
        result
    });
    let mut cleaned = false;
    let mut cleanup_succeeded = true;
    let saved = tokio::select! {
        biased;
        _ = interrupt.cancelled() => {
            if interrupt.during_save() {
                cleanup_succeeded = revoke(origin, std::slice::from_ref(&replacement)).await;
                custody.cleanup_succeeded.store(cleanup_succeeded, Ordering::SeqCst);
                cleaned = true;
                if !cleanup_succeeded && !saving_task.is_finished() {
                    let _ = writeln!(stderr, "{}", words::LOGIN_WAITING_FOR_SAVE_WORDS);
                    let _ = stderr.flush();
                }
            }
            saving_task.await
        }
        saved = &mut saving_task => saved,
    }
    .map_err(|_| "credential save did not complete".to_string())
    .and_then(|result| result);
    if interrupt.during_save() {
        if !cleaned {
            cleanup_succeeded = revoke(origin, std::slice::from_ref(&replacement)).await;
            custody
                .cleanup_succeeded
                .store(cleanup_succeeded, Ordering::SeqCst);
        }
        match saved {
            Ok(location) => {
                let _ = retire_earlier(origin, &replacement, previous, stderr).await;
                if cleanup_succeeded {
                    if let Err(reason) = store.delete() {
                        let _ = writeln!(stderr, "{reason}");
                    }
                } else {
                    let _ = writeln!(stdout, "{}", signed_in(&account, &location));
                }
            }
            Err(reason) if !cleanup_succeeded => {
                let _ = writeln!(stderr, "{}", words::recovery(Some(&reason)));
            }
            Err(_) => {}
        }
        return Err(String::new());
    }
    let location = match saved {
        Ok(location) => location,
        Err(reason) => {
            let revoked = revoke(origin, std::slice::from_ref(&replacement)).await;
            let error = if revoked {
                reason
            } else {
                words::recovery(Some(&reason))
            };
            if interrupt.triggered() {
                if !revoked {
                    let _ = writeln!(stderr, "{error}");
                }
                return Err(String::new());
            }
            return Err(error);
        }
    };
    let retired = retire_earlier(origin, &replacement, previous, stderr).await;
    if interrupt.triggered() {
        let _ = writeln!(stdout, "{}", signed_in(&account, &location));
        return Err(String::new());
    }
    retired?;
    Ok(signed_in(&account, &location))
}

fn signed_in(account: &str, location: &StoreLocation) -> String {
    let mut name = store_name(location);
    if cfg!(unix) && matches!(location, StoreLocation::File(_)) {
        name.push_str(", which only your user account can read");
    }
    format!("Signed in to {account}. The token is saved in {name}.")
}

async fn retire_earlier(
    origin: &str,
    replacement: &StoredToken,
    previous: Vec<StoredToken>,
    stderr: &mut impl Write,
) -> Result<(), String> {
    let earlier: Vec<_> = previous
        .into_iter()
        .filter(|stored| stored.token.as_str() != replacement.token.as_str())
        .collect();
    if !earlier.is_empty() {
        let notice = if revoke(origin, &earlier).await {
            "Revoked this computer's earlier SiteCMD token."
        } else {
            words::LOGIN_EARLIER_REVOKE_FAILED_WORDS
        };
        writeln!(stderr, "{notice}")
            .map_err(|_| "could not display SiteCMD token revocation status")?;
    }
    Ok(())
}
