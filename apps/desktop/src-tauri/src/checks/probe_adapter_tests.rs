use super::*;
use crate::http_client::BodyReadError;

pub(crate) mod testing {
    //! A loopback origin for transport tests that reports the peak number of
    //! requests it had accepted and not yet answered.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    pub(crate) struct CountingOrigin {
        pub(crate) url: String,
        peak: Arc<AtomicUsize>,
        answered: Arc<AtomicUsize>,
        server: tokio::task::JoinHandle<()>,
    }

    impl CountingOrigin {
        /// Serve `response` to every request. The first `hold_until`
        /// requests are held open, unanswered, until that many are open at
        /// once, which makes the peak a deterministic measurement of how many
        /// the client was willing to put in flight rather than a race.
        pub(crate) async fn serve(response: &'static str, hold_until: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind counting origin");
            let addr = listener.local_addr().expect("counting origin address");
            let peak = Arc::new(AtomicUsize::new(0));
            let answered = Arc::new(AtomicUsize::new(0));
            let open = Arc::new(AtomicUsize::new(0));
            let (accepted_tx, accepted_rx) = tokio::sync::watch::channel(0usize);
            let server = tokio::spawn({
                let peak = peak.clone();
                let answered = answered.clone();
                async move {
                    // Owned by this task so that aborting it (on drop) also
                    // aborts every connection task, including ones parked on
                    // a request this origin never intends to answer.
                    let mut connections = tokio::task::JoinSet::new();
                    let mut accepted = 0usize;
                    loop {
                        let Ok((mut stream, _)) = listener.accept().await else {
                            break;
                        };
                        accepted += 1;
                        let _ = accepted_tx.send(accepted);
                        let now_open = open.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now_open, Ordering::SeqCst);
                        let open = open.clone();
                        let answered = answered.clone();
                        let mut accepted_rx = accepted_rx.clone();
                        connections.spawn(async move {
                            let mut head = [0u8; 4096];
                            let _ = stream.read(&mut head).await;
                            let _ = accepted_rx.wait_for(|count| *count >= hold_until).await;
                            // Count the request as answered before a single
                            // response byte leaves, so a request the client
                            // opens because it received this answer can never
                            // overlap with it in the tally.
                            open.fetch_sub(1, Ordering::SeqCst);
                            answered.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                        // Reap finished connections so a long-lived origin
                        // does not accumulate completed join handles.
                        while connections.try_join_next().is_some() {}
                    }
                }
            });
            Self {
                url: format!("http://{addr}"),
                peak,
                answered,
                server,
            }
        }

        /// The most requests this origin ever had open at once.
        pub(crate) fn peak_in_flight(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        pub(crate) fn answered(&self) -> usize {
            self.answered.load(Ordering::SeqCst)
        }
    }

    impl Drop for CountingOrigin {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
}

#[test]
fn body_read_errors_classify_by_kind() {
    let too_large = failure_from_body_error(BodyReadError::TooLarge {
        max_bytes: 10,
        received_bytes: 11,
    });
    assert_eq!(too_large.class, ProbeFailureClass::BodyCapExceeded);
    let timed_out = failure_from_body_error(BodyReadError::TimedOut {
        timeout: std::time::Duration::from_secs(5),
    });
    assert_eq!(timed_out.class, ProbeFailureClass::Timeout);
    assert!(!too_large.detail.is_empty() && !timed_out.detail.is_empty());
}

#[tokio::test]
async fn refused_connection_classifies_as_transport_failure() {
    let outcome = probe_get(crate::http_client::for_url(false), "http://127.0.0.1:1/").await;
    match outcome {
        ProbeOutcome::Failure(failure) => {
            assert_eq!(failure.class, ProbeFailureClass::Transport);
        }
        ProbeOutcome::Response(_) => panic!("closed port cannot respond"),
    }
}

const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
const OK_EMPTY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A generous polling wait: every caller below is waiting on a loopback
/// exchange that settles in milliseconds, so reaching the cap means the
/// condition will never hold, not that the machine was slow.
async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..2_000 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for {what}");
}

fn claims_on(origin: &str) -> usize {
    lock_limiters()
        .get(origin)
        .map(|entry| entry.claims)
        .unwrap_or(0)
}

#[tokio::test]
async fn one_origin_never_sees_more_than_the_per_host_bound_in_flight() {
    let bound = crate::constants::PROBE_HOST_CONCURRENCY;
    // Hold the first `bound` requests until that many are open at once:
    // the adapter must be willing to put a full bound in flight (or the
    // held requests time out and the outcomes below are failures), and
    // it must never put one more (or the peak exceeds the bound).
    let origin = testing::CountingOrigin::serve(NO_CONTENT, bound).await;
    let client = crate::http_client::for_url(true);
    let probes: Vec<_> = (0..bound * 3)
        .map(|index| {
            let url = format!("{}/probe/{index}", origin.url);
            tokio::spawn(async move { probe_get(client, &url).await })
        })
        .collect();
    let mut answered = 0;
    for probe in probes {
        match probe.await.expect("probe task completes") {
            ProbeOutcome::Response(response) => {
                assert_eq!(response.status, 204);
                answered += 1;
            }
            ProbeOutcome::Failure(failure) => {
                panic!("every probe must be answered, got {failure:?}")
            }
        }
    }
    assert_eq!(answered, bound * 3);
    assert_eq!(
        origin.peak_in_flight(),
        bound,
        "the origin must see exactly the bound in flight: never more, and the full bound while work is queued"
    );
}

#[tokio::test]
async fn the_origin_limiter_is_released_once_the_last_probe_finishes() {
    let origin = testing::CountingOrigin::serve(NO_CONTENT, 1).await;
    let key = origin_key(&format!("{}/x", origin.url));
    let outcome = probe_get(
        crate::http_client::for_url(true),
        &format!("{}/x", origin.url),
    )
    .await;
    assert!(matches!(outcome, ProbeOutcome::Response(_)));
    assert!(
        !lock_limiters().contains_key(&key),
        "an idle origin must not keep a limiter registered"
    );
}

#[tokio::test]
async fn a_probe_cancelled_while_queued_gives_its_claim_back() {
    let bound = crate::constants::PROBE_HOST_CONCURRENCY;
    // Nothing is ever answered, so every slot stays taken and the extra
    // probe below can only be waiting in the queue.
    let origin = testing::CountingOrigin::serve(NO_CONTENT, usize::MAX).await;
    let key = origin_key(&format!("{}/x", origin.url));
    let client = crate::http_client::for_url(true);
    let holding: Vec<_> = (0..bound)
        .map(|index| {
            let url = format!("{}/holding/{index}", origin.url);
            tokio::spawn(async move { probe_get(client, &url).await })
        })
        .collect();
    wait_until("every slot to be taken", || claims_on(&key) == bound).await;

    let queued = tokio::spawn({
        let url = format!("{}/queued", origin.url);
        async move { probe_get(client, &url).await }
    });
    wait_until("the extra probe to queue", || claims_on(&key) == bound + 1).await;
    queued.abort();
    let _ = queued.await;
    assert_eq!(
        claims_on(&key),
        bound,
        "a probe cancelled while queued must release its claim"
    );

    for handle in holding {
        handle.abort();
        let _ = handle.await;
    }
    assert!(
        !lock_limiters().contains_key(&key),
        "an idle origin must not keep a limiter registered"
    );
}

#[tokio::test]
async fn a_raw_request_through_the_decoding_seam_is_refused_unsent() {
    let origin = testing::CountingOrigin::serve(NO_CONTENT, 1).await;
    let request = ProbeRequest::head(&origin.url).coding(ContentCoding::Raw);
    let outcome = probe(crate::http_client::for_url(true), request).await;
    assert!(matches!(
        outcome,
        ProbeOutcome::Failure(ref failure) if failure.class == ProbeFailureClass::Transport
    ));
    assert_eq!(origin.answered(), 0, "nothing was sent");
}

/// What a [`ResettingOrigin`] does with a connection once it is past the
/// connections it closes unanswered.
#[derive(Clone, Copy)]
enum AfterResets {
    /// Write this response and close.
    Answer(&'static str),
    /// Accept the request and never answer it.
    Hold,
}

/// A loopback server that closes its first `resets` connections without
/// answering. Every connection task belongs to the accept loop's join set,
/// so dropping the origin shuts the whole server down.
struct ResettingOrigin {
    url: String,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl ResettingOrigin {
    /// Close the first `resets` connections without answering, `reset_after`
    /// into each one, and treat every connection after those as `then`. The
    /// delay is how a first attempt is made to spend most of a probe's budget
    /// before it fails.
    async fn serve(resets: usize, reset_after: Duration, then: AfterResets) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind resetting origin");
        let addr = listener.local_addr().expect("resetting origin address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let seen = accepted.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let mut index = 0usize;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let closes_unanswered = index < resets;
                index += 1;
                seen.fetch_add(1, Ordering::SeqCst);
                connections.spawn(async move {
                    let mut head = [0u8; 2048];
                    let _ = stream.read(&mut head).await;
                    if closes_unanswered {
                        tokio::time::sleep(reset_after).await;
                        // Dropping the stream closes it, which is a reset
                        // from the client's point of view.
                        return;
                    }
                    match then {
                        AfterResets::Answer(response) => {
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        AfterResets::Hold => std::future::pending::<()>().await,
                    }
                });
                while connections.try_join_next().is_some() {}
            }
        });
        Self {
            url: format!("http://{addr}"),
            accepted,
            server,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for ResettingOrigin {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[test]
fn a_retry_is_a_fair_test_of_the_origin_only_above_half_the_budget() {
    let budget = Duration::from_secs(10);
    assert!(retry_had_a_fair_share(budget, budget));
    assert!(retry_had_a_fair_share(Duration::from_secs(5), budget));
    assert!(!retry_had_a_fair_share(
        Duration::from_millis(4_999),
        budget
    ));
    assert!(!retry_had_a_fair_share(Duration::from_millis(1), budget));
}

#[tokio::test]
async fn a_connection_closed_before_any_response_is_retried_once() {
    let origin = ResettingOrigin::serve(1, Duration::ZERO, AfterResets::Answer(OK_EMPTY)).await;
    let outcome = probe_get(
        crate::http_client::for_url(true),
        &format!("{}/retry", origin.url),
    )
    .await;
    match outcome {
        ProbeOutcome::Response(response) => assert_eq!(response.status, 200),
        ProbeOutcome::Failure(failure) => {
            panic!("the second attempt must carry the answer, got {failure:?}")
        }
    }
    assert_eq!(origin.accepted(), 2);
}

#[tokio::test]
async fn a_second_connection_failure_is_reported_not_retried_again() {
    let origin = ResettingOrigin::serve(2, Duration::ZERO, AfterResets::Answer(OK_EMPTY)).await;
    let outcome = probe_get(
        crate::http_client::for_url(true),
        &format!("{}/twice", origin.url),
    )
    .await;
    match outcome {
        ProbeOutcome::Failure(failure) => {
            assert_eq!(failure.class, ProbeFailureClass::Transport)
        }
        ProbeOutcome::Response(_) => panic!("two failed attempts must not become a third"),
    }
    assert_eq!(origin.accepted(), 2);
}

#[tokio::test]
async fn a_retry_that_only_runs_out_of_budget_reports_the_failure_that_was_observed() {
    // The first connection is held for three quarters of the budget and then
    // closed unanswered, so the retry gets a quarter and can only end by
    // running out of it. What was observed of the origin is the reset.
    //
    // The 3 s the origin sleeps is a floor, so a slow machine can only make
    // the retry's share smaller, never push it back over the half that would
    // make it a fair attempt; the assertion is not racing that clock.
    let origin = ResettingOrigin::serve(1, Duration::from_secs(3), AfterResets::Hold).await;
    let outcome = probe_with_timeout(
        crate::http_client::for_url(true),
        ProbeRequest::get(format!("{}/stall-then-reset", origin.url)),
        Some(Duration::from_secs(4)),
    )
    .await;
    match outcome {
        ProbeOutcome::Failure(failure) => assert_eq!(
            failure.class,
            ProbeFailureClass::Transport,
            "a retry left a quarter of the budget must not downgrade the observed reset"
        ),
        ProbeOutcome::Response(_) => panic!("a held request cannot answer"),
    }
    assert_eq!(origin.accepted(), 2);
}

#[tokio::test]
async fn a_retry_given_a_fair_share_of_the_budget_reports_its_own_timeout() {
    // The mirror image: the first connection is closed without any delay, so
    // the retry gets the 2 s budget less a loopback connect, and still does
    // not finish. That is a real observation of the origin, and the timeout is
    // the honest verdict.
    let origin = ResettingOrigin::serve(1, Duration::ZERO, AfterResets::Hold).await;
    let outcome = probe_with_timeout(
        crate::http_client::for_url(true),
        ProbeRequest::get(format!("{}/reset-then-stall", origin.url)),
        Some(Duration::from_secs(2)),
    )
    .await;
    match outcome {
        ProbeOutcome::Failure(failure) => assert_eq!(
            failure.class,
            ProbeFailureClass::Timeout,
            "a retry that had the budget and did not finish is a timeout"
        ),
        ProbeOutcome::Response(_) => panic!("a held request cannot answer"),
    }
    assert_eq!(origin.accepted(), 2);
}

#[tokio::test]
async fn a_timeout_is_not_retried() {
    // Hold every request open forever: the first attempt times out, and
    // a retry would only be a second request that also never answers. Two
    // seconds is far more than the loopback connect and accept this waits
    // on, so the assertion below is about the retry, not about timing.
    let origin = testing::CountingOrigin::serve(NO_CONTENT, usize::MAX).await;
    let outcome = probe_with_timeout(
        crate::http_client::for_url(true),
        ProbeRequest::get(format!("{}/slow", origin.url)),
        Some(Duration::from_secs(2)),
    )
    .await;
    match outcome {
        ProbeOutcome::Failure(failure) => assert_eq!(failure.class, ProbeFailureClass::Timeout),
        ProbeOutcome::Response(_) => panic!("a held request cannot answer"),
    }
    assert_eq!(origin.answered(), 0);
    assert_eq!(
        origin.peak_in_flight(),
        1,
        "a timed-out probe must not be sent again"
    );
}

/// One layer of a synthetic error chain shaped like reqwest's.
#[derive(Debug)]
struct Layer {
    message: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for Layer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

fn chain(connect_message: &'static str, cause: std::io::Error) -> Layer {
    Layer {
        message: "error sending request",
        source: Some(Box::new(Layer {
            message: "client error (Connect)",
            source: Some(Box::new(Layer {
                message: connect_message,
                source: Some(Box::new(cause)),
            })),
        })),
    }
}

#[test]
fn a_resolver_failure_is_recognised_through_the_error_chain() {
    let unresolved = chain(
        "dns error",
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not resolve URL host 'www.example.invalid'.",
        ),
    );
    assert_eq!(
        dns_failure_in_chain(&unresolved),
        Some(DnsFailure::Unresolved)
    );

    let lookup_error = chain(
        "dns error",
        std::io::Error::other("failed to lookup address information"),
    );
    assert_eq!(
        dns_failure_in_chain(&lookup_error),
        Some(DnsFailure::Unresolved)
    );

    let refused = chain(
        "dns error",
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "loopback refused"),
    );
    assert_eq!(dns_failure_in_chain(&refused), Some(DnsFailure::Refused));

    let connect = chain(
        "tcp connect error",
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
    );
    assert_eq!(dns_failure_in_chain(&connect), None);
}

#[tokio::test]
async fn a_real_resolver_failure_is_recognised_from_the_error_reqwest_actually_returns() {
    // The synthetic chains above pin the classifier's logic; this pins the
    // wrapper string it keys on to the one hyper-util really produces, so a
    // dependency bump that renames it fails here instead of silently putting
    // unresolvable hosts back in the retry path. `.invalid` is reserved by
    // RFC 2606 and has no authoritative server, so this asks nothing of the
    // network beyond the resolver saying no.
    let error = send(
        crate::http_client::for_url(false),
        &ProbeRequest::get("http://does-not-resolve.invalid/"),
        Duration::from_secs(10),
    )
    .await
    .expect_err("a reserved-TLD host cannot resolve");
    assert_eq!(
        dns_failure(&error),
        Some(DnsFailure::Unresolved),
        "unrecognised resolver failure: {error:?}"
    );
    assert!(
        !send_failure_is_retryable(&error),
        "a host that does not resolve must not be retried"
    );
}

#[tokio::test]
async fn a_host_that_does_not_resolve_is_classified_as_dns_unresolved_not_transport() {
    // The classifier above is what the class is derived from; this pins the
    // outcome a verdict actually receives, so `config.www_redirect` can tell
    // "this host does not exist" from "this host did not reply" on the same
    // reserved-TLD host the resolver really refuses.
    let outcome = probe_get(
        crate::http_client::for_url(false),
        "http://does-not-resolve.invalid/",
    )
    .await;
    match outcome {
        ProbeOutcome::Failure(failure) => assert_eq!(
            failure.class,
            ProbeFailureClass::DnsUnresolved,
            "got {failure:?}"
        ),
        ProbeOutcome::Response(response) => {
            panic!("a reserved-TLD host cannot answer, got {response:?}")
        }
    }
}
