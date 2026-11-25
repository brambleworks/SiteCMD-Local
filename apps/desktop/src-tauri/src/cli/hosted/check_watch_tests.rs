use super::*;

fn requests_at(requests: &[String]) -> Vec<&str> {
    requests
        .iter()
        .map(|request| request_line(request))
        .collect()
}

fn baseline(dir: &Path, origin: &str) {
    let artifact = json!({"hosted": {
        "connectOrigin": origin, "siteId": "site_a", "scanId": "hs_old", "url": TARGET,
        "overallScore": 70, "timestamp": PREVIOUS, "categoryScores": {},
        "issues": [{
            "checkId": "seo.title", "title": "Old issue", "category": "seo",
            "severity": "high", "occurrences": 1
        }]
    }});
    std::fs::write(dir.join("last-scan.json"), artifact.to_string()).unwrap();
}

async fn check(
    origin: &str,
    dir: &Path,
    strict: bool,
    threshold: u32,
    output: &mut Vec<u8>,
) -> Result<u8, HostedError> {
    super::super::check::run_with(
        &client(origin),
        &Url::parse(TARGET).unwrap(),
        dir,
        strict,
        threshold,
        &FakeClock::default(),
        output,
    )
    .await
}

#[tokio::test]
async fn check_without_a_threshold_skips_sign_in_and_connect() {
    // Bug: A public hook with no threshold needs credentials or contacts Connect.
    use crate::cli::check::{run, CheckArgs};
    use crate::connected_service::CLIENT_CONSTRUCTION_ATTEMPTS;
    use std::sync::atomic::Ordering::Relaxed;

    const CHILD: &str = "SITECMD_THRESHOLDLESS_CHECK_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let (origin, requests) =
            respond_in_sequence_with_headers(vec![page(json!([]), None)]).await;
        std::env::set_var("SITECMD_CONNECT_ORIGIN", origin);
        let check = |threshold| {
            run(CheckArgs {
                install: false,
                strict: false,
                threshold,
            })
        };
        assert!(std::env::var_os("SITECMD_TOKEN").is_none());
        assert_eq!(check(None).await, Ok(0));

        std::env::set_var("SITECMD_TOKEN", "thresholdless-fixture");
        assert_eq!(check(None).await, Ok(0));
        assert_eq!(CLIENT_CONSTRUCTION_ATTEMPTS.load(Relaxed), 0);
        assert!(
            !requests.is_finished(),
            "a thresholdless check contacted Connect"
        );

        std::env::set_var("SITECMD_TOKEN", "threshold-control-fixture");
        assert!(check(Some(80))
            .await
            .unwrap_err()
            .starts_with("site_not_in_account\n"));
        let requests = requests.await.unwrap();
        assert_eq!(requests_at(&requests), ["GET /v1/sites HTTP/1.1"]);
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer threshold-control-fixture"));
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".sitecmd");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(
        config.join("config.json"),
        r#"{"version":1,"url":"https://93.184.215.14","name":"Public site"}"#,
    )
    .unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .current_dir(dir.path())
        .env(CHILD, "1")
        .env_remove("SITECMD_TOKEN")
        .args([
            "--exact",
            "cli::hosted::tests::check_watch_tests::check_without_a_threshold_skips_sign_in_and_connect",
            "--nocapture",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(
        result.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{stderr}"
    );
    let notice = concat!(
        "sitecmd check: no threshold configured; passing. Set fail_under in ",
        ".sitecmd/config.json or pass --threshold to enforce a minimum score, ",
        "or use --strict to fail on new issues.\n",
    );
    assert_eq!(stderr, notice.repeat(2));
    assert!(!config.join("last-scan.json").exists());
}

#[tokio::test]
async fn check_never_requests_a_scan_by_default() {
    // Bug: A public hook spends scan quota or judges a stale cached score.
    let mut answers = vec![site_page(), page(json!([applied()]), None)];
    answers.extend(report_pages(
        FINISHED,
        80,
        json!([group("seo.description", "seo", "high")]),
    ));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let dir = tempfile::tempdir().unwrap();
    baseline(dir.path(), &origin);
    assert_eq!(
        check(&origin, dir.path(), false, 80, &mut Vec::new()).await,
        Ok(0)
    );
    assert_eq!(
        requests_at(&requests.await.unwrap()),
        [
            "GET /v1/sites HTTP/1.1",
            "GET /v1/sites/site_a/scans HTTP/1.1",
            "GET /v1/sites/site_a/score HTTP/1.1",
            "GET /v1/sites/site_a/groups HTTP/1.1",
            "GET /v1/sites/site_a/score HTTP/1.1"
        ],
    );
    let artifact = report::read_artifact(dir.path()).unwrap();
    assert_eq!(artifact.hosted.scan_id, "hs_a");
    assert_eq!(
        artifact.older_than(&artifact.hosted).unwrap().scan_id,
        "hs_old"
    );
}

#[tokio::test]
async fn strict_requests_a_fresh_scan() {
    // Bug: Strict check reads a cached scan or misses a new failing check ID.
    let mut answers = vec![site_page(), started(), ok(applied())];
    answers.extend(report_pages(
        FINISHED,
        80,
        json!([
            group("seo.title", "seo", "high"),
            group("seo.description", "seo", "high")
        ]),
    ));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let dir = tempfile::tempdir().unwrap();
    baseline(dir.path(), &origin);
    let mut output = Vec::new();
    assert_eq!(
        check(&origin, dir.path(), true, 80, &mut output).await,
        Ok(1)
    );
    let output = String::from_utf8(output).unwrap();
    assert!(
        output.contains("Check failed: 1 new issue since the last scan:"),
        "{output}"
    );
    assert!(
        output.contains("seo.description") && !output.contains("seo.title"),
        "{output}"
    );
    let requests = requests.await.unwrap();
    assert_eq!(
        &requests_at(&requests)[..3],
        [
            "GET /v1/sites HTTP/1.1",
            "POST /v1/sites/site_a/scans HTTP/1.1",
            "GET /v1/sites/site_a/scans/hs_a HTTP/1.1"
        ],
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1
    );
    assert!(requests[1]
        .to_ascii_lowercase()
        .contains("\r\nidempotency-key: "));
}

fn exhausted() -> Reply {
    reply(
        json!({"code": "scan_budget_exhausted"}),
        "429 Too Many Requests",
    )
}

#[tokio::test]
async fn strict_judges_the_latest_scan_when_quota_is_spent() {
    // Bug: Quota exhaustion fails a push or skips score and regression checks on the fallback.
    let finished = "2026-11-20T16:00:01.000Z";
    for (threshold, issue, failure) in [
        (80, "seo.title", None),
        (81, "seo.title", Some("score 80/100 is below threshold 81")),
        (
            80,
            "seo.description",
            Some("Check failed: 1 new issue since the last scan:"),
        ),
    ] {
        let mut answers = vec![
            site_page(),
            exhausted(),
            page(
                json!([scan("hs_fallback", "applied", Some(finished))]),
                None,
            ),
        ];
        answers.extend(report_pages(
            finished,
            80,
            json!([group(issue, "seo", "high")]),
        ));
        let (origin, requests) = respond_in_sequence_with_headers(answers).await;
        let dir = tempfile::tempdir().unwrap();
        baseline(dir.path(), &origin);
        let mut output = Vec::new();
        assert_eq!(
            check(&origin, dir.path(), true, threshold, &mut output).await,
            Ok(u8::from(failure.is_some()))
        );
        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output
                .lines()
                .filter(|line| line.contains("23 hours old"))
                .count(),
            1,
            "{output}"
        );
        if let Some(failure) = failure {
            assert!(output.contains(failure), "{output}");
        }
        if issue == "seo.description" {
            assert!(
                output.contains("  [High] seo.description - Title for seo.description"),
                "{output}"
            );
            assert!(!output.contains("seo.title"), "{output}");
        }
        assert_eq!(
            report::read_artifact(dir.path()).unwrap().hosted.scan_id,
            "hs_fallback"
        );
        assert_eq!(
            &requests_at(&requests.await.unwrap())[..3],
            [
                "GET /v1/sites HTTP/1.1",
                "POST /v1/sites/site_a/scans HTTP/1.1",
                "GET /v1/sites/site_a/scans HTTP/1.1"
            ],
        );
    }
}

#[tokio::test]
async fn strict_falls_back_when_scan_starts_are_rate_limited() {
    // Bug: A rate limit on starting a scan fails the hook despite an available finished scan.
    let mut answers = vec![
        site_page(),
        (
            r#"{"code":"rate_limited"}"#.into(),
            "429 Too Many Requests",
            &["Retry-After: 120"][..],
        ),
        page(json!([scan("hs_old", "applied", Some(PREVIOUS))]), None),
    ];
    answers.extend(report_pages(
        PREVIOUS,
        80,
        json!([group("seo.title", "seo", "high")]),
    ));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let dir = tempfile::tempdir().unwrap();
    baseline(dir.path(), &origin);
    let mut output = Vec::new();
    assert_eq!(
        check(&origin, dir.path(), true, 80, &mut output).await,
        Ok(0)
    );
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("{RATE_LIMITED} The latest finished hosted scan is 1 day old.\n")
    );
    assert_eq!(
        requests_at(&requests.await.unwrap()),
        [
            "GET /v1/sites HTTP/1.1",
            "POST /v1/sites/site_a/scans HTTP/1.1",
            "GET /v1/sites/site_a/scans HTTP/1.1",
            "GET /v1/sites/site_a/score HTTP/1.1",
            "GET /v1/sites/site_a/groups HTTP/1.1",
            "GET /v1/sites/site_a/score HTTP/1.1"
        ]
    );
}

#[tokio::test]
async fn check_exits_2_on_an_outage() {
    // Bug: The hook passes using cached results while Connect is unavailable.
    let refusal = reply(
        json!({"code": "internal_error"}),
        "500 Internal Server Error",
    );
    for (answers, count) in [(vec![site_page(), refusal], 2), (vec![site_page()], 1)] {
        let (origin, requests) = respond_in_sequence_with_headers(answers).await;
        let dir = tempfile::tempdir().unwrap();
        baseline(dir.path(), &origin);
        let error = check(&origin, dir.path(), false, 80, &mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "service_unavailable");
        let requests = requests.await.unwrap();
        assert_eq!(requests.len(), count);
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
    }
}

#[tokio::test]
async fn check_requires_a_finished_scan() {
    // Bug: A hook passes with no hosted result, including after exhausting quota.
    for strict in [false, true] {
        let mut answers = vec![site_page()];
        if strict {
            answers.push(exhausted());
        }
        answers.push(page(json!([scan("hs_running", "running", None)]), None));
        let (origin, requests) = respond_in_sequence_with_headers(answers).await;
        let dir = tempfile::tempdir().unwrap();
        let mut output = Vec::new();
        assert_eq!(
            check(&origin, dir.path(), strict, 80, &mut output).await,
            Err(HostedError::NoFinishedScan)
        );
        assert!(output.is_empty());
        assert!(!dir.path().join("last-scan.json").exists());
        assert_eq!(requests.await.unwrap().len(), if strict { 3 } else { 2 });
    }
}

const SERVER_DATE: &str = "Date: Sat, 21 Nov 2026 16:00:00 GMT";

fn dated(mut response: Reply) -> Reply {
    response.2 = &[SERVER_DATE];
    response
}

#[tokio::test]
async fn watch_prints_each_new_scan_once_and_never_posts() {
    // Bug: Watch starts scans, reprints history, or drops completions across pages.
    let cursor = "2026-11-21T15:59:00.000Z hs_a";
    let first = scan("hs_b", "history_only", Some("2026-11-21T17:00:00.000Z"));
    let last = scan("hs_a", "applied", Some("2026-11-21T18:00:00.000Z"));
    let running = scan("hs_b", "running", None);
    let old = scan("hs_old", "applied", Some(PREVIOUS));
    let (origin, requests) = respond_in_sequence_with_headers(vec![
        dated(site_page()),
        page(json!([running, old]), None),
        page(json!([last]), Some(cursor)),
        page(json!([first, old]), None),
        page(json!([last, first, old]), None),
        reply(json!({"code": "unverified_site"}), "403 Forbidden"),
    ])
    .await;
    let clock = FakeClock::default();
    let mut output = Vec::new();
    let result = super::super::watch::run_with(
        &client(&origin),
        &Url::parse(TARGET).unwrap(),
        Duration::from_secs(7),
        &clock,
        &mut output,
    )
    .await;
    assert_eq!(result, Err(HostedError::UnverifiedSite));
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 2, "{output}");
    assert!(output.lines().next().unwrap().contains("hs_b"), "{output}");
    assert!(output.lines().last().unwrap().contains("hs_a"), "{output}");
    let requests = requests.await.unwrap();
    assert_eq!(requests.len(), 6);
    assert!(
        requests.iter().all(|request| request.starts_with("GET ")),
        "{requests:?}"
    );
    assert!(request_line(&requests[3]).contains("/scans?cursor="));
    assert_eq!(*clock.sleeps.borrow(), [7, 7, 7]);
}

#[tokio::test]
async fn watch_retries_transient_failures_with_retry_after() {
    // Bug: A temporary lookup or poll refusal stops watch or retries too soon.
    let limited = (
        r#"{"code":"rate_limited"}"#.into(),
        "429 Too Many Requests",
        &[SERVER_DATE, "Retry-After: 19"][..],
    );
    let unavailable = (
        r#"{"code":"restore_in_progress"}"#.into(),
        "503 Service Unavailable",
        &["Retry-After: 13"][..],
    );
    let (origin, requests) = respond_in_sequence_with_headers(vec![
        limited,
        site_page(),
        unavailable,
        page(
            json!([scan(
                "hs_during_outage",
                "rejected",
                Some("2026-11-21T16:00:20.000Z")
            )]),
            None,
        ),
        reply(json!({"code":"entitlement_suspended"}), "403 Forbidden"),
    ])
    .await;
    let clock = FakeClock::default();
    let mut output = Vec::new();
    let result = super::super::watch::run_with(
        &client(&origin),
        &Url::parse(TARGET).unwrap(),
        Duration::from_secs(7),
        &clock,
        &mut output,
    )
    .await;
    assert_eq!(result, Err(HostedError::EntitlementSuspended));
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 3, "{output}");
    assert!(
        output.contains("[#1] Scan error:") && output.contains("[#2] Scan error:"),
        "{output}"
    );
    assert!(
        output.lines().last().unwrap().contains("hs_during_outage"),
        "{output}"
    );
    assert_eq!(*clock.sleeps.borrow(), [19, 13, 7]);
    let requests = requests.await.unwrap();
    assert!(
        requests.iter().all(|request| request.starts_with("GET ")),
        "{requests:?}"
    );
}

#[tokio::test]
async fn watch_uses_the_first_refusal_date_with_fast_and_slow_local_clocks() {
    // Bug: Local clock skew hides scans finished during a retry or prints older scans.
    for (wall_offset, headers) in [
        (120, &[SERVER_DATE, "Retry-After: 120"][..]),
        (
            -120,
            &[SERVER_DATE, "Retry-After: Sat, 21 Nov 2026 16:02:00 GMT"][..],
        ),
    ] {
        let old = scan("hs_old", "applied", Some("2026-11-21T15:59:00.000Z"));
        let new = scan("hs_new", "applied", Some("2026-11-21T16:01:00.000Z"));
        let snapshot = page(json!([old, new]), None);
        let mut site = site_page();
        site.2 = &["Date: Sat, 21 Nov 2026 16:02:00 GMT"];
        let (origin, requests) = respond_in_sequence_with_headers(vec![
            (
                r#"{"code":"restore_in_progress"}"#.into(),
                "503 Service Unavailable",
                headers,
            ),
            site,
            snapshot.clone(),
            snapshot,
            reply(json!({"code": "unverified_site"}), "403 Forbidden"),
        ])
        .await;
        let clock = FakeClock {
            wall_offset,
            ..FakeClock::default()
        };
        let mut output = Vec::new();
        assert_eq!(
            super::super::watch::run_with(
                &client(&origin),
                &Url::parse(TARGET).unwrap(),
                Duration::from_secs(7),
                &clock,
                &mut output,
            )
            .await,
            Err(HostedError::UnverifiedSite)
        );
        let output = String::from_utf8(output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2, "{output}");
        assert!(lines[0].starts_with("[#1] Scan error:"), "{output}");
        assert_eq!(
            lines[1],
            "[#2] Hosted scan hs_new finished at 2026-11-21T16:01:00Z."
        );
        assert_eq!(*clock.sleeps.borrow(), [120, 7, 7]);
        let requests = requests.await.unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
    }
}

#[tokio::test]
async fn watch_seeds_history_when_the_first_response_has_no_usable_date() {
    // Bug: Watch prints or later repeats the first snapshot when it has no Connect time reference.
    for headers in [&[][..], &["Date: unknown"][..]] {
        let mut site = site_page();
        site.2 = headers;
        let existing = scan("hs_existing", "applied", Some("2026-11-21T16:01:00.000Z"));
        let new = scan("hs_new", "applied", Some("2026-11-21T16:02:00.000Z"));
        let next = dated(page(json!([existing, new]), None));
        let (origin, requests) = respond_in_sequence_with_headers(vec![
            site,
            dated(page(json!([existing]), None)),
            next.clone(),
            next,
            reply(json!({"code": "unverified_site"}), "403 Forbidden"),
        ])
        .await;
        let clock = FakeClock::default();
        let mut output = Vec::new();
        assert_eq!(
            super::super::watch::run_with(
                &client(&origin),
                &Url::parse(TARGET).unwrap(),
                Duration::from_secs(7),
                &clock,
                &mut output,
            )
            .await,
            Err(HostedError::UnverifiedSite)
        );
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().collect::<Vec<_>>(), [
            "[#1] Connect didn't provide a usable time. Skipping the scans in the first snapshot.",
            "[#2] Hosted scan hs_new finished at 2026-11-21T16:02:00Z.",
        ]);
        assert_eq!(*clock.sleeps.borrow(), [7, 7, 7]);
        let requests = requests.await.unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
    }
}

#[tokio::test]
async fn watch_stops_when_the_site_leaves_the_account() {
    // Bug: A site's disappearance is reported as an unknown refusal instead of site_not_in_account.
    let (origin, requests) = respond_in_sequence_with_headers(vec![
        site_page(),
        reply(json!({"code":"not_found"}), "404 Not Found"),
    ])
    .await;
    let clock = FakeClock::default();
    let mut output = Vec::new();
    assert_eq!(
        super::super::watch::run_with(
            &client(&origin),
            &Url::parse(TARGET).unwrap(),
            Duration::from_secs(7),
            &clock,
            &mut output,
        )
        .await,
        Err(HostedError::SiteNotInAccount)
    );
    assert!(clock.sleeps.borrow().is_empty());
    assert!(output.is_empty());
    assert_eq!(requests.await.unwrap().len(), 2);
}
