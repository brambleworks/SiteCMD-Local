//! One origin's in-flight limit for the probe seam: at most
//! `PROBE_HOST_CONCURRENCY` requests to an origin at a time, released as each
//! exchange ends.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// One origin's limiter and the number of probes currently claiming it. The
/// count is what decides when the entry can go, so a probe cancelled while
/// it is still queued for a slot releases its claim just like one that ran.
pub(super) struct OriginEntry {
    limiter: Arc<Semaphore>,
    pub(super) claims: usize,
}

/// Per-origin limiters, created on first use and dropped again once the last
/// probe to that origin finishes, so link probing that touches hundreds of
/// hosts does not leave hundreds of idle semaphores behind.
static ORIGIN_LIMITERS: LazyLock<Mutex<HashMap<String, OriginEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// One of the `PROBE_HOST_CONCURRENCY` in-flight slots for an origin, held
/// for the lifetime of the exchange.
pub(super) struct OriginSlot {
    origin: String,
    permit: Option<OwnedSemaphorePermit>,
}

impl OriginSlot {
    pub(super) async fn acquire(url: &str) -> Self {
        let origin = origin_key(url);
        let limiter = {
            let mut limiters = lock_limiters();
            let entry = limiters
                .entry(origin.clone())
                .or_insert_with(|| OriginEntry {
                    limiter: Arc::new(Semaphore::new(crate::constants::PROBE_HOST_CONCURRENCY)),
                    claims: 0,
                });
            entry.claims += 1;
            entry.limiter.clone()
        };
        // The claim is registered and the slot exists before the first await,
        // so a probe dropped while it is still queued still runs `Drop` and
        // gives the claim back.
        let mut slot = Self {
            origin,
            permit: None,
        };
        // The semaphore is never closed, so acquisition cannot fail; if it
        // somehow did, running unbounded is the pre-existing behavior rather
        // than a reason to drop the probe.
        slot.permit = limiter.acquire_owned().await.ok();
        slot
    }
}

impl Drop for OriginSlot {
    fn drop(&mut self) {
        // Give the permit back before the entry can be removed, so a waiter
        // is never left holding a limiter this slot has already abandoned.
        self.permit.take();
        let mut limiters = lock_limiters();
        let Some(entry) = limiters.get_mut(&self.origin) else {
            return;
        };
        entry.claims -= 1;
        if entry.claims == 0 {
            limiters.remove(&self.origin);
        }
    }
}

pub(super) fn lock_limiters() -> std::sync::MutexGuard<'static, HashMap<String, OriginEntry>> {
    ORIGIN_LIMITERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The origin a request will open its connection to: scheme, host, and the
/// effective port, which is also how the connection pool keys connections.
/// A URL that does not parse still gets a key of its own; the send will
/// report the parse failure.
pub(super) fn origin_key(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(parsed) => format!(
            "{}://{}:{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or_default(),
            parsed.port_or_known_default().unwrap_or_default()
        ),
        Err(_) => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_keys_share_a_connection_target_not_a_path() {
        assert_eq!(
            origin_key("https://Example.com/a?x=1"),
            origin_key("https://example.com/b")
        );
        assert_eq!(
            origin_key("https://example.com/"),
            "https://example.com:443"
        );
        assert_eq!(
            origin_key("http://example.com:8080/"),
            "http://example.com:8080"
        );
        assert_ne!(
            origin_key("http://example.com/"),
            origin_key("https://example.com/")
        );
        assert_eq!(origin_key("not a url"), "not a url");
    }
}
