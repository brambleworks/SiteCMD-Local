use std::cell::{Cell, RefCell};

use serde_json::{json, Value};
use tokio::net::TcpListener;

use super::*;
use crate::connected_service::test_double::{
    request_line, respond_in_sequence_with_headers, respond_once, respond_once_with_headers,
};
use crate::core::scan_types::Category;
use crate::core::scan_types::Severity;

const FINISHED: &str = "2026-11-21T16:00:00.000Z";
const PREVIOUS: &str = "2026-11-20T16:00:00.000Z";
const TARGET: &str = "https://example.com/path";

struct FakeClock {
    started: Instant,
    elapsed: Cell<Duration>,
    sleeps: RefCell<Vec<u64>>,
    wall_offset: i64,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            elapsed: Cell::default(),
            sleeps: RefCell::default(),
            wall_offset: 0,
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.started + self.elapsed.get()
    }

    fn wall_time(&self) -> Timestamp {
        Timestamp::from_second(
            FINISHED.parse::<Timestamp>().unwrap().as_second()
                + self.wall_offset
                + self.elapsed.get().as_secs() as i64,
        )
        .unwrap()
    }

    async fn sleep(&self, delay: Duration) {
        self.sleeps.borrow_mut().push(delay.as_secs());
        self.elapsed.set(self.elapsed.get() + delay);
    }
}

type Reply = (String, &'static str, &'static [&'static str]);

fn reply(body: Value, status: &'static str) -> Reply {
    (body.to_string(), status, &[])
}

fn ok(body: Value) -> Reply {
    reply(body, "200 OK")
}

fn page(items: impl Into<Value>, cursor: Option<&str>) -> Reply {
    ok(json!({"items": items.into(), "next_cursor": cursor}))
}

fn site_page() -> Reply {
    page(json!([{"id": "site_a", "url": TARGET}]), None)
}

fn scan(id: &str, state: &str, finished_at: Option<&str>) -> Value {
    json!({"id": id, "state": state, "finished_at": finished_at})
}

fn applied() -> Value {
    scan("hs_a", "applied", Some(FINISHED))
}

fn started() -> Reply {
    reply(json!({"scan_id": "hs_a"}), "202 Accepted")
}

fn score(at: &str, overall: u32) -> Reply {
    ok(json!({
        "score": {"overall": overall, "perCategory": {
            "security": 72, "domain_https": 91, "email": 90, "seo": 88, "ai_visibility": 87,
            "performance": 82, "accessibility": 65, "privacy": 76, "polish": 94,
            "reliability": 99, "code_quality": 98, "compliance": 97
        }},
        "last_scan_at": at
    }))
}

fn group(check: &str, category: &str, severity: &str) -> Value {
    json!({
        "check": check, "title": format!("Title for {check}"), "category": category,
        "severity": severity, "occurrences": 4, "sources": ["web"], "state":"active",
        "dormant":false
    })
}

fn report_pages(at: &str, overall: u32, groups: Value) -> [Reply; 3] {
    [score(at, overall), page(groups, None), score(at, overall)]
}

pub(super) fn args() -> ScanArgs {
    ScanArgs {
        url: None,
        fail_under: None,
        fail_on: None,
        json: true,
        timeout: None,
        categories: None,
        diff: false,
        env_name: None,
        latest: false,
        connect_origin: None,
    }
}

fn client(origin: &str) -> ConnectedServiceClient {
    ConnectedServiceClient::for_test_origin(origin, Some("test-bearer")).unwrap()
}

async fn run_test(
    client: &ConnectedServiceClient,
    args: &ScanArgs,
    dir: Option<&Path>,
    clock: &FakeClock,
) -> Result<u8, HostedError> {
    run_with(client, &Url::parse(TARGET).unwrap(), args, dir, clock).await
}

#[tokio::test]
async fn a_revoked_token_reads_as_signed_out() {
    // Bug: An expired or revoked bearer is treated as a service outage.
    let (origin, request) = respond_once(
        r#"{"code":"expired_token","detail":"private"}"#,
        "401 Unauthorized",
    )
    .await;
    let refusal = run_test(&client(&origin), &args(), None, &FakeClock::default()).await;
    assert_eq!(refusal, Err(HostedError::SignedOut));
    assert!(request
        .await
        .unwrap()
        .to_ascii_lowercase()
        .contains("authorization: bearer test-bearer"));
}

#[tokio::test]
async fn matches_the_site_on_the_second_page() {
    // Bug: A matching account site is ignored when it appears after the first cursor.
    let replies = vec![
        page(
            json!([{"id":"site_other","url":"https://other.example"}]),
            Some("site_other"),
        ),
        site_page(),
    ];
    let (origin, requests) = respond_in_sequence_with_headers(replies).await;
    let (site, _) = client::find_site(&client(&origin), &Url::parse(TARGET).unwrap())
        .await
        .unwrap();
    assert_eq!(site.as_str(), "site_a");
    let requests = requests.await.unwrap();
    assert_eq!(
        request_line(&requests[1]),
        "GET /v1/sites?cursor=site_other HTTP/1.1"
    );
}

#[test]
fn origin_match_ignores_case_and_default_port_but_not_www() {
    // Bug: Case or an explicit default port prevents matching, or www matches a different origin.
    let base = Url::parse(TARGET).unwrap();
    for (url, expected) in [
        ("HTTPS://ExAmPlE.CoM:443/other", true),
        ("https://example.com./", true),
        ("https://www.example.com", false),
        ("https://example.com:8443", false),
        ("http://example.com:80", false),
    ] {
        assert_eq!(
            client::same_origin(&base, &Url::parse(url).unwrap()),
            expected,
            "{url}"
        );
    }
}

#[tokio::test]
async fn http_uses_the_default_https_site_and_stops_paging() {
    // Bug: An HTTP target misses its HTTPS site or reads another page after matching.
    let (origin, requests) = respond_in_sequence_with_headers(vec![page(
        json!([{"id":"site_a","url":"https://example.com.:443"}]),
        Some("site_a"),
    )])
    .await;
    let target = Url::parse("http://EXAMPLE.COM:80/path").unwrap();
    let (site, _) = client::find_site(&client(&origin), &target).await.unwrap();
    assert_eq!(site.as_str(), "site_a");
    assert_eq!(requests.await.unwrap().len(), 1);

    let (origin, requests) = respond_in_sequence_with_headers(vec![site_page()]).await;
    let target = Url::parse("http://example.com:8080/path").unwrap();
    assert_eq!(
        client::find_site(&client(&origin), &target).await,
        Err(HostedError::SiteNotInAccount)
    );
    assert_eq!(requests.await.unwrap().len(), 1);
}

#[tokio::test]
async fn site_not_in_account_exits_2() {
    // Bug: A missing account site is classified as an outage or triggers a scan.
    let (origin, requests) = respond_in_sequence_with_headers(vec![page(json!([]), None)]).await;
    let refusal = run_test(&client(&origin), &args(), None, &FakeClock::default())
        .await
        .unwrap_err();
    assert_eq!(refusal, HostedError::SiteNotInAccount);
    assert_eq!(HostedError::EXIT_CODE, 2);
    assert_eq!(
        refusal.json(),
        r#"{"error":{"code":"site_not_in_account"}}"#
    );
    assert_eq!(requests.await.unwrap().len(), 1);
}

#[tokio::test]
async fn repeated_cursors_are_refused() {
    // Bug: Repeated pagination cursors keep the CLI walking the same page.
    let (origin, requests) = respond_in_sequence_with_headers(vec![
        page(json!([]), Some("site_a")),
        page(json!([]), Some("site_b")),
        page(json!([]), Some("site_a")),
    ])
    .await;
    assert_eq!(
        run_test(&client(&origin), &args(), None, &FakeClock::default()).await,
        Err(HostedError::RequestFailed)
    );
    assert_eq!(requests.await.unwrap().len(), 3);
}

#[tokio::test]
async fn each_refusal_maps_to_its_code() {
    // Bug: Service refusals get a generic code or echo private problem details.
    for (status, server_code, expected) in [
        ("401 Unauthorized", "unauthorized", "signed_out"),
        ("403 Forbidden", "unverified_site", "unverified_site"),
        (
            "403 Forbidden",
            "entitlement_suspended",
            "entitlement_suspended",
        ),
        (
            "429 Too Many Requests",
            "scan_budget_exhausted",
            "scan_budget_exhausted",
        ),
        ("429 Too Many Requests", "rate_limited", "rate_limited"),
        ("429 Too Many Requests", "unknown_code", "rate_limited"),
        ("400 Bad Request", "invalid_input", "request_failed"),
        ("200 OK", "invalid_response_shape", "request_failed"),
        (
            "503 Service Unavailable",
            "unavailable",
            "service_unavailable",
        ),
        ("bad", "transport_failed", "service_unavailable"),
    ] {
        let refusal = reply(json!({"code":server_code,"detail":"private"}), status);
        let mut answers = vec![site_page(), refusal.clone()];
        if status == "bad" {
            answers.push(refusal);
        }
        let (origin, requests) = respond_in_sequence_with_headers(answers).await;
        let error = run_test(&client(&origin), &args(), None, &FakeClock::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), expected, "{status}");
        assert_eq!(
            error.json(),
            format!(r#"{{"error":{{"code":"{expected}"}}}}"#)
        );
        assert!(!error.to_string().contains("private"));
        requests.await.unwrap();
    }
}

#[tokio::test]
async fn scan_in_progress_waits_on_the_named_scan() {
    // Bug: An existing scan is refused or polled under the wrong identifier.
    let dir = tempfile::tempdir().unwrap();
    let mut answers = vec![
        site_page(),
        (
            json!({"code":"scan_in_progress","scan_id":"hs_running"}).to_string(),
            "409 Conflict",
            &[][..],
        ),
        ok(scan("hs_running", "applied", Some(FINISHED))),
    ];
    answers.extend(report_pages(FINISHED, 80, json!([])));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let clock = FakeClock::default();
    assert_eq!(
        run_test(&client(&origin), &args(), Some(dir.path()), &clock).await,
        Ok(0)
    );
    assert_eq!(*clock.sleeps.borrow(), [5]);
    let requests = requests.await.unwrap();
    assert_eq!(
        request_line(&requests[1]),
        "POST /v1/sites/site_a/scans HTTP/1.1"
    );
    assert_eq!(
        request_line(&requests[2]),
        "GET /v1/sites/site_a/scans/hs_running HTTP/1.1"
    );
}

#[tokio::test]
async fn poll_honors_retry_after() {
    // Bug: Polling ignores either form of Retry-After or polls sooner than five seconds.
    let dir = tempfile::tempdir().unwrap();
    let mut answers = vec![
        site_page(),
        started(),
        (
            json!({"code": "rate_limited"}).to_string(),
            "429 Too Many Requests",
            &["Retry-After: 20"][..],
        ),
        (
            json!({"code": "restore_in_progress"}).to_string(),
            "503 Service Unavailable",
            &["Retry-After: Sat, 21 Nov 2026 16:00:38 GMT"][..],
        ),
        (
            json!({"code": "restore_in_progress"}).to_string(),
            "503 Service Unavailable",
            &["Retry-After: 1"][..],
        ),
        ok(applied()),
    ];
    answers.extend(report_pages(FINISHED, 80, json!([])));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let clock = FakeClock::default();
    assert_eq!(
        run_test(&client(&origin), &args(), Some(dir.path()), &clock).await,
        Ok(0)
    );
    assert_eq!(*clock.sleeps.borrow(), [5, 20, 13, 5]);
    assert_eq!(requests.await.unwrap().len(), 9);
}

#[tokio::test]
async fn gives_up_after_twenty_minutes_without_an_unknown_dashboard_link() {
    // Bug: Retry-After extends the wait past 20 minutes or loses the scan link.
    let (origin, requests) = respond_in_sequence_with_headers(vec![
        site_page(),
        started(),
        (
            json!({"code": "rate_limited"}).to_string(),
            "429 Too Many Requests",
            &["Retry-After: 7200"][..],
        ),
    ])
    .await;
    let clock = FakeClock::default();
    let error = run_test(&client(&origin), &args(), None, &clock)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "scan_timeout");
    assert_eq!(HostedError::EXIT_CODE, 2);
    assert_eq!(error.to_string(), TIMEOUT);
    assert_eq!(clock.elapsed.get().as_secs(), 1200);
    assert_eq!(requests.await.unwrap().len(), 3);
}

#[test]
fn only_production_connect_has_a_known_dashboard() {
    // Bug: A private Connect deployment is given a production dashboard link.
    let site = Identifier::try_from("site_a").unwrap();
    let scan = Identifier::try_from("hs_a").unwrap();
    let link = dashboard_url("https://connect.sitecmd.com", &site, &scan);
    assert_eq!(
        link.as_deref(),
        Some("https://app.sitecmd.com/sites/site_a/activity?filter=scans&scan=hs_a")
    );
    assert_eq!(HostedError::ScanTimeout { dashboard_url: link }.to_string(),
        format!("{TIMEOUT} {DASHBOARD} https://app.sitecmd.com/sites/site_a/activity?filter=scans&scan=hs_a"));
    assert_eq!(dashboard_url("https://custom.example", &site, &scan), None);
}

#[tokio::test]
async fn latest_without_a_finished_scan_has_its_own_refusal() {
    // Bug: A site with no completed scan appears to be a service outage.
    let (origin, requests) = respond_in_sequence_with_headers(vec![
        site_page(),
        page(json!([scan("hs_a", "running", None)]), None),
    ])
    .await;
    let flags = ScanArgs {
        latest: true,
        ..args()
    };
    let error = run_test(&client(&origin), &flags, None, &FakeClock::default())
        .await
        .unwrap_err();
    assert_eq!(error, HostedError::NoFinishedScan);
    assert_eq!(error.json(), r#"{"error":{"code":"no_finished_scan"}}"#);
    assert_eq!(error.to_string(), NO_FINISHED_SCAN);
    assert_eq!(requests.await.unwrap().len(), 2);
}

#[tokio::test]
async fn latest_never_posts() {
    // Bug: Reading a finished scan spends demand budget or picks a still-running scan.
    let dir = tempfile::tempdir().unwrap();
    let mut answers = vec![
        site_page(),
        page(
            json!([scan("hs_running", "running", None)]),
            Some("2026-11-21T16:00:00.000Z hs_running"),
        ),
        page(json!([applied()]), None),
    ];
    answers.extend(report_pages(FINISHED, 80, json!([])));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let args = ScanArgs {
        latest: true,
        ..args()
    };
    assert_eq!(
        run_test(
            &client(&origin),
            &args,
            Some(dir.path()),
            &FakeClock::default()
        )
        .await,
        Ok(0)
    );
    let requests = requests.await.unwrap();
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests
            .iter()
            .filter(|r| request_line(r).starts_with("GET "))
            .count(),
        6
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| request_line(r).starts_with("POST "))
            .count(),
        0
    );
    assert_eq!(
        request_line(&requests[2]),
        "GET /v1/sites/site_a/scans?cursor=2026-11-21T16%3A00%3A00.000Z+hs_running HTTP/1.1"
    );
}

#[tokio::test]
async fn fail_under_and_fail_on_apply_to_hosted_results() {
    // Bug: The quality gate counts findings a category filter hides.
    use Category::{Accessibility, Security};

    for (picked, under, on, expected) in [
        (&[][..], Some(81), None, 1),
        (&[], Some(80), None, 0),
        (&[], None, Some(Severity::High), 1),
        (&[Accessibility], None, Some(Severity::High), 0),
        (&[Security], Some(80), Some(Severity::High), 1),
        (&[], Some(101), None, 1),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut answers = vec![site_page(), started(), ok(applied())];
        let groups = json!([group("security.headers", "security", "high")]);
        answers.extend(report_pages(FINISHED, 80, groups));
        let (origin, requests) = respond_in_sequence_with_headers(answers).await;
        let args = ScanArgs {
            categories: (!picked.is_empty()).then(|| picked.to_vec()),
            fail_under: under,
            fail_on: on,
            ..args()
        };
        assert_eq!(
            run_test(
                &client(&origin),
                &args,
                Some(dir.path()),
                &FakeClock::default()
            )
            .await,
            Ok(expected)
        );
        requests.await.unwrap();
    }
}

#[tokio::test]
async fn fail_under_requires_every_selected_hosted_category_to_meet_the_bar() {
    // Bug: The overall score or a higher category score can mask a selected category below the bar.
    use Category::{Accessibility, Performance};

    for (picked, threshold, expected) in [
        (&[][..], 81, 1),
        (&[], 80, 0),
        (&[Performance], 81, 0),
        (&[Performance], 83, 1),
        (&[Performance, Accessibility], 66, 1),
        (&[Accessibility, Performance], 66, 1),
        (&[Performance, Accessibility], 65, 0),
    ] {
        let mut answers = vec![site_page(), started(), ok(applied())];
        answers.extend(report_pages(FINISHED, 80, json!([])));
        let (origin, requests) = respond_in_sequence_with_headers(answers).await;
        let args = ScanArgs {
            categories: (!picked.is_empty()).then(|| picked.to_vec()),
            fail_under: Some(threshold),
            ..args()
        };
        assert_eq!(
            run_test(&client(&origin), &args, None, &FakeClock::default()).await,
            Ok(expected),
            "{picked:?} at {threshold}"
        );
        requests.await.unwrap();
    }
}

#[tokio::test]
async fn writes_last_scan_for_fix() {
    // Bug: Unfiltered JSON mode skips the full artifact used by fix.
    let dir = tempfile::tempdir().unwrap();
    let mut answers = vec![site_page(), started(), ok(applied()), score(FINISHED, 80)];
    answers.extend([
        page(
            json!([group("security.headers~hsts", "security", "high")]),
            Some("security.headers~hsts"),
        ),
        page(
            json!([
                group("seo.title", "seo", "medium"),
                group("security.headers.csp", "security", "high")
            ]),
            None,
        ),
        score(FINISHED, 80),
    ]);
    let config_dir = dir.path().join(".sitecmd");
    std::fs::create_dir(&config_dir).unwrap();
    for name in ["issues.md", "issues.json", "rules.md"] {
        std::fs::write(config_dir.join(name), "stale export").unwrap();
    }
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let args = args();
    assert_eq!(
        run_test(
            &client(&origin),
            &args,
            Some(&config_dir),
            &FakeClock::default()
        )
        .await,
        Ok(0)
    );
    let artifact = report::read_artifact(&config_dir).unwrap();
    assert_eq!(artifact.hosted.score(), 80);
    let issues = &artifact.hosted.issues;
    assert_eq!(issues.len(), 3);
    assert_eq!(issues[0].check_id.as_str(), "security.headers~hsts");
    assert_eq!(issues[1].check_id.as_str(), "seo.title");
    let markdown = std::fs::read_to_string(config_dir.join("issues.md")).unwrap();
    assert!(markdown.contains("ID: security.headers~hsts | High"));
    assert!(markdown.contains("Occurrences: 4"));
    let csp_verify = format!("curl -sI {TARGET} | grep -i csp");
    assert!(markdown.contains(&format!("Verify: {csp_verify}")));
    let rules = std::fs::read_to_string(config_dir.join("rules.md")).unwrap();
    assert!(rules.contains("## Security"));
    assert!(rules.contains("- Create and tailor Content-Security-Policy"));
    assert!(rules.contains("- Give each indexable page a descriptive title"));
    let json: Value =
        serde_json::from_slice(&std::fs::read(config_dir.join("issues.json")).unwrap()).unwrap();
    assert_eq!(
        json["issues"][0],
        json!({
            "id": "security.headers~hsts", "title": "Title for security.headers~hsts",
            "category": "security", "severity": "high", "occurrences": 4,
            "verify": "sitecmd scan --diff"
        })
    );
    assert_eq!(json["issues"][1]["id"], "security.headers.csp");
    assert_eq!(json["issues"][1]["verify"], csp_verify);
    assert_eq!(json["issues"][2]["id"], "seo.title");
    assert_eq!(json["score"], 80);
    assert!(json.get("recoverable_points").is_none());
    let requests = requests.await.unwrap();
    assert_eq!(
        request_line(&requests[5]),
        "GET /v1/sites/site_a/groups?cursor=security.headers%7Ehsts HTTP/1.1"
    );
}

#[tokio::test]
async fn fix_prints_connect_fix_text_for_a_hosted_finding() {
    // Bug: Fix drops Connect's fix text and asks the module to write text from the title.
    let dir = tempfile::tempdir().unwrap();
    let mut guided = group("security.headers", "security", "high");
    guided["fix_guide"] = json!({
        "lead": "Your site lets other sites frame its pages.",
        "plain": ["Ask your host to send the header.", "Scan again to confirm it."],
        "steps": [
            "Send `X-Frame-Options: DENY` on every response.",
            "```bash\ncurl -sI https://example.com/ | grep -i x-frame\n```"
        ]
    });
    let mut answers = vec![site_page(), started(), ok(applied())];
    answers.extend(report_pages(FINISHED, 80, json!([guided])));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    assert_eq!(
        run_test(
            &client(&origin),
            &args(),
            Some(dir.path()),
            &FakeClock::default()
        )
        .await,
        Ok(0)
    );
    requests.await.unwrap();
    let contents = std::fs::read_to_string(dir.path().join("last-scan.json")).unwrap();
    let text = crate::cli::fix::FixScanHarness::parse(&contents)
        .unwrap()
        .first_prompt_with(|_| panic!("hosted findings never reach the module"))
        .unwrap();
    assert_eq!(
        text,
        concat!(
            "security.headers - Title for security.headers\n\n",
            "Your site lets other sites frame its pages.\n\n",
            "1. Ask your host to send the header.\n",
            "2. Scan again to confirm it.\n\n",
            "The details\n\n",
            "1. Send `X-Frame-Options: DENY` on every response.\n",
            "2. ```bash\ncurl -sI https://example.com/ | grep -i x-frame\n```",
        )
    );
}

#[test]
fn a_group_without_a_fix_guide_still_parses() {
    // Bug: Requiring fix_guide makes every scan against an older Connect fail.
    let older: client::Group = serde_json::from_value(group("seo.title", "seo", "medium")).unwrap();
    assert!(older.fix_guide.is_none());
    let mut current = group("seo.title", "seo", "medium");
    current["fix_guide"] =
        json!({"plainOnly": true, "plain": ["Give the page a title."], "steps": []});
    let current: client::Group = serde_json::from_value(current).unwrap();
    let guide = current.fix_guide.unwrap();
    assert!(guide.plain_only);
    assert_eq!(guide.plain, ["Give the page a title."]);
}

#[tokio::test]
async fn a_retried_post_reuses_its_idempotency_key() {
    // Bug: After an ambiguous transport failure retrying the POST starts a second scan.
    let dir = tempfile::tempdir().unwrap();
    let mut answers = vec![
        site_page(),
        reply(json!({}), "bad"),
        (
            json!({"code": "request_in_progress"}).to_string(),
            "409 Conflict",
            &["Retry-After: 7"][..],
        ),
        started(),
        ok(applied()),
    ];
    answers.extend(report_pages(FINISHED, 80, json!([])));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let clock = FakeClock::default();
    assert_eq!(
        run_test(&client(&origin), &args(), Some(dir.path()), &clock).await,
        Ok(0)
    );
    assert_eq!(*clock.sleeps.borrow(), [7, 5]);
    let requests = requests.await.unwrap();
    let key = |request: &str| {
        request
            .lines()
            .find_map(|line| line.strip_prefix("idempotency-key: "))
            .unwrap()
            .to_owned()
    };
    assert_eq!(request_line(&requests[1]), request_line(&requests[2]));
    assert_eq!(key(&requests[1]).len(), 64);
    assert_eq!(key(&requests[1]), key(&requests[2]));
    assert_eq!(request_line(&requests[2]), request_line(&requests[3]));
    assert_eq!(key(&requests[2]), key(&requests[3]));
    assert!(!requests[1].contains("content-type: application/json"));
}

#[tokio::test]
async fn the_scanned_host_never_receives_authorization() {
    // Bug: Following a Connect redirect leaks the bearer to the host being scanned.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_url = Url::parse(&format!("http://{}", target.local_addr().unwrap())).unwrap();
    let location = format!("Location: {target_url}");
    let headers: &'static [&'static str] =
        Box::leak(vec![Box::leak(location.into_boxed_str()) as &str].into_boxed_slice());
    let (origin, request) =
        respond_once_with_headers("{}", "307 Temporary Redirect", headers).await;
    let client = client(&origin);
    let args = args();
    let clock = FakeClock::default();
    let flow = run_with(&client, &target_url, &args, None, &clock);
    tokio::pin!(flow);
    let result = tokio::select! {
        result = &mut flow => result,
        _ = target.accept() => panic!("the scanned host received a request"),
    };
    assert_eq!(result, Err(HostedError::RequestFailed));
    assert!(request
        .await
        .unwrap()
        .to_ascii_lowercase()
        .contains("authorization: bearer test-bearer"));
    assert!(futures_util::FutureExt::now_or_never(target.accept()).is_none());
}

#[tokio::test]
async fn fresh_diff_compares_two_distinct_finished_scans() {
    // Bug: Diff uses the live findings for both sides and misses a new critical issue.
    let dir = tempfile::tempdir().unwrap();
    let old = scan("hs_old", "applied", Some(PREVIOUS));
    let mut answers = vec![site_page(), page(json!([old.clone()]), None)];
    answers.extend(report_pages(
        PREVIOUS,
        80,
        json!([group("seo.title", "seo", "low")]),
    ));
    answers.extend([started(), ok(applied())]);
    answers.extend(report_pages(
        FINISHED,
        60,
        json!([
            group("security.headers", "security", "critical"),
            group("operations.example", "operations", "critical")
        ]),
    ));
    answers.push(page(json!([applied(), old]), None));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let args = ScanArgs {
        diff: true,
        ..args()
    };
    assert_eq!(
        run_test(
            &client(&origin),
            &args,
            Some(dir.path()),
            &FakeClock::default()
        )
        .await,
        Ok(1)
    );
    let artifact = report::read_artifact(dir.path()).unwrap();
    let previous = artifact
        .baseline_for(&artifact.hosted, &Identifier::try_from("hs_old").unwrap())
        .unwrap();
    assert_eq!(previous.score(), 80);
    assert_eq!(artifact.hosted.score(), 60);
    requests.await.unwrap();
    if let Some(path) = std::env::var_os("SITECMD_CAPTURE_HOSTED_ARTIFACT") {
        std::fs::copy(dir.path().join("last-scan.json"), path).unwrap();
    }
}

#[test]
fn environment_token_is_used_for_the_selected_connect_origin() {
    // Bug: The public scan reads the repository credential store and ignores a CI token.
    const CHILD: &str = "SITECMD_HOSTED_CREDENTIAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (origin, request) =
                respond_once(r#"{"items":[],"next_cursor":null}"#, "200 OK").await;
            std::env::set_var("SITECMD_CONNECT_ORIGIN", origin);
            assert_eq!(
                run(&Url::parse(TARGET).unwrap(), &args()).await,
                Err(HostedError::SiteNotInAccount)
            );
            let request = request.await.unwrap();
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer ci-test-bearer"));
        });
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::hosted::tests::environment_token_is_used_for_the_selected_connect_origin",
        ])
        .env(CHILD, "1")
        .env("SITECMD_TOKEN", "ci-test-bearer")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
}

#[tokio::test]
async fn latest_diff_uses_only_the_cached_immediate_predecessor() {
    // Bug: A read-only diff silently uses a cached report from the wrong hosted scan.
    let dir = tempfile::tempdir().unwrap();
    let mut answers = vec![
        site_page(),
        page(json!([scan("hs_old", "applied", Some(PREVIOUS))]), None),
    ];
    answers.extend(report_pages(
        PREVIOUS,
        80,
        json!([group("seo.title", "seo", "low")]),
    ));
    answers.extend([site_page(), page(json!([applied()]), None)]);
    answers.extend(report_pages(FINISHED, 85, json!([])));
    answers.push(page(
        json!([applied(), scan("hs_old", "applied", Some(PREVIOUS))]),
        None,
    ));
    answers.extend([site_page(), page(json!([applied()]), None)]);
    answers.extend(report_pages(FINISHED, 85, json!([])));
    answers.push(page(
        json!([applied(), scan("hs_different", "applied", Some(PREVIOUS))]),
        None,
    ));
    let (origin, requests) = respond_in_sequence_with_headers(answers).await;
    let client = client(&origin);
    let mut args = ScanArgs {
        latest: true,
        ..args()
    };
    let clock = FakeClock::default();
    assert_eq!(
        run_test(&client, &args, Some(dir.path()), &clock).await,
        Ok(0)
    );
    args.diff = true;
    assert_eq!(
        run_test(&client, &args, Some(dir.path()), &clock).await,
        Ok(0)
    );
    assert_eq!(
        run_test(&client, &args, Some(dir.path()), &clock).await,
        Ok(0)
    );
    let artifact = report::read_artifact(dir.path()).unwrap();
    assert_eq!(artifact.hosted.scan_id.as_str(), "hs_a");
    assert!(artifact
        .baseline_for(&artifact.hosted, &Identifier::try_from("hs_old").unwrap())
        .is_none());
    assert!(requests
        .await
        .unwrap()
        .iter()
        .all(|request| request_line(request).starts_with("GET ")));
}

#[test]
fn hosted_output_keeps_reports_and_sends_notices_to_stderr() {
    // Bug: Waiting or fallback notices corrupt JSON, or a missing baseline or export loses the fresh result.
    const CHILD: &str = "SITECMD_HOSTED_OUTPUT_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(".sitecmd");
            if mode == "blocked" {
                std::fs::write(&path, "").unwrap();
            }
            let filtered = mode == "filtered";
            let old = scan("hs_old", "applied", Some(PREVIOUS));
            let mut answers = vec![site_page()];
            if mode == "diff" {
                answers.push(page(json!([old]), None));
                answers.extend(report_pages(PREVIOUS, 70, json!([])));
            } else if !filtered {
                answers.push(page(json!([]), None));
            }
            answers.extend([
                started(),
                ok(scan("hs_a", "waiting", None)),
                ok(scan("hs_a", "running", None)),
                ok(scan("hs_a", "running", None)),
                ok(applied()),
            ]);
            let mut code_only = group("code_scan.example", "reliability", "critical");
            code_only["sources"] = json!(["code"]);
            answers.extend(report_pages(FINISHED, 80, json!([code_only])));
            let history = if mode == "diff" {
                json!([applied(), old])
            } else {
                json!([applied()])
            };
            if !filtered {
                answers.push(page(history, None));
            }
            let (origin, requests) = respond_in_sequence_with_headers(answers).await;
            let flags = ScanArgs {
                categories: filtered.then(|| vec![Category::Security]),
                fail_on: Some(Severity::Critical),
                diff: !filtered,
                json: matches!(mode.as_str(), "json" | "blocked"),
                ..args()
            };
            assert_eq!(
                run_test(&client(&origin), &flags, Some(&path), &FakeClock::default()).await,
                Ok(0)
            );
            if matches!(mode.as_str(), "blocked" | "filtered") {
                assert!(!path.join("last-scan.json").exists());
            } else {
                assert_eq!(
                    report::read_artifact(&path)
                        .unwrap()
                        .hosted
                        .scan_id
                        .as_str(),
                    "hs_a"
                );
            }
            requests.await.unwrap();
        });
        return;
    }
    for mode in ["text", "json", "blocked", "filtered", "diff"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::hosted::tests::hosted_output_keeps_reports_and_sends_notices_to_stderr",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stdout.contains("Hosted scan queued."));
        assert_eq!(stderr.lines().filter(|line| *line == QUEUED).count(), 1);
        assert_eq!(stderr.lines().filter(|line| *line == RUNNING).count(), 1);
        assert_eq!(
            stderr
                .lines()
                .filter(|line| *line == FINISHED_NOTICE)
                .count(),
            1
        );
        assert_eq!(
            stderr
                .lines()
                .filter(|line| *line == "There was no earlier finished scan to compare with.")
                .count(),
            usize::from(!matches!(mode, "diff" | "filtered"))
        );
        if mode == "diff" {
            assert!(stdout.contains("Score: 70 \u{2192} 80 (+10)"));
            assert!(stdout.contains("No issues in either scan."));
        } else if mode == "filtered" {
            assert!(stdout.contains("Score: 72/100 (health scan)"));
            assert!(stdout.contains("No issues found."));
            assert!(stdout.contains("Security"));
            assert!(!stdout.contains("Performance"));
        } else if mode == "text" {
            let positions = Category::ALL.map(|category| stdout.find(category.label()).unwrap());
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(stdout.contains("Score: 80/100 (health scan)"));
            assert!(stdout.contains("No issues found."));
            assert!(stdout.contains("Tip: Add to CLAUDE.md:"));
        } else {
            let start = stdout.find('{').unwrap();
            let end = stdout.rfind('}').unwrap();
            let report: Value = serde_json::from_str(&stdout[start..=end]).unwrap();
            assert_eq!(report["overallScore"], json!(80));
            assert_eq!(report["issues"], json!([]));
            assert!(report.get("diff").is_none());
            let categories: Vec<_> = report["categories"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["category"].as_str().unwrap())
                .collect();
            assert_eq!(categories, Category::ALL.map(Category::key));
        }
        assert_eq!(
            stderr.contains("Warning: failed to export scan results:"),
            mode == "blocked"
        );
    }
}

#[path = "check_watch_tests.rs"]
mod check_watch_tests;
