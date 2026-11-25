use std::cell::Cell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use tokio::net::TcpListener;

use super::*;
use crate::cli::lane_test_support::{
    assert_local_fetch_deadline, assert_local_scan_needs_no_sign_in, reply,
};

#[test]
fn choose_lane_accepts_only_resolved_loopback_hosts() {
    // Bug: A loopback target skips the local evaluator, or a hosted address enters it.
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    for (url, addresses) in [
        ("http://localhost:3000", &[v4, v6][..]),
        ("http://127.0.0.1", &[v4][..]),
        ("http://[::1]", &[v6][..]),
        ("http://[::ffff:127.0.0.1]", &[mapped][..]),
        ("http://app.localhost:3000", &[v4, v6][..]),
        ("http://app.localhost:3000", &[mapped][..]),
        ("http://preview.localhost.:3000", &[v4][..]),
    ] {
        assert_eq!(
            choose_lane(&Url::parse(url).unwrap(), addresses),
            Lane::Local,
            "{url}"
        );
    }
    let public = "93.184.216.34".parse().unwrap();
    assert_eq!(
        choose_lane(&Url::parse("https://example.com").unwrap(), &[public]),
        Lane::Hosted
    );
    assert_eq!(
        choose_lane(&Url::parse("http://app.localhost").unwrap(), &[]),
        Lane::Hosted
    );
}

#[test]
fn choose_lane_routes_mixed_dns_answers_to_hosted() {
    // Bug: A localhost name with a loopback answer can hide a second, public address.
    let public = "93.184.216.34".parse().unwrap();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for target in [
        "http://localhost:3000",
        "http://app.localhost:3000",
        "https://example.com",
    ] {
        let url = Url::parse(target).unwrap();
        for addresses in [[loopback, public], [public, loopback]] {
            assert_eq!(choose_lane(&url, &addresses), Lane::Hosted, "{target}");
        }
    }
}

fn deadline() -> Deadline {
    Deadline {
        started: Instant::now(),
        timeout: HTTP_CLIENT_TIMEOUT,
    }
}

#[tokio::test]
async fn a_redirect_off_the_machine_is_not_followed() {
    // Bug: A local site's redirect can send a request to a public host.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://localhost:{}/initial", address.port())).unwrap();
    let server = tokio::spawn(async move {
        reply(
            &listener,
            "302 Found",
            "Location: https://example.com/\r\n",
            "redirect body",
        )
        .await
    });
    let shared_lookups = Rc::new(Cell::new(0));
    let previous = crate::dns_cache::TEST_LOOKUP.replace(Some(Box::new({
        let shared_lookups = shared_lookups.clone();
        move |host, port| {
            assert_eq!(host, "example.com");
            shared_lookups.set(shared_lookups.get() + 1);
            Ok(vec![SocketAddr::new("192.0.2.1".parse().unwrap(), port)])
        }
    })));
    assert!(previous.is_none());
    let off_machine = Url::parse("https://example.com/").unwrap();
    network_policy::validate_url_target(&off_machine, UrlPolicy::ScanTarget)
        .await
        .unwrap();
    assert_eq!(shared_lookups.get(), 1);
    use reqwest::dns::Resolve;
    crate::dns_cache::CachedDnsResolver::for_policy(UrlPolicy::ScanTarget)
        .resolve("example.com".parse().unwrap())
        .await
        .map(|mut addresses| assert!(addresses.next().is_some()))
        .unwrap();
    let shared_before = shared_lookups.get();
    assert_eq!(shared_before, 2);
    let lookups_before = crate::http_client::UNPINNED_LOCAL_DNS_LOOKUPS.with(Cell::get);
    let resolved = Cell::new(0);
    let result = fetch_local(
        target,
        vec![address],
        deadline(),
        ScanPurpose::OneShot,
        async |_| {
            resolved.set(resolved.get() + 1);
            Ok(vec!["192.0.2.1:443".parse().unwrap()])
        },
    )
    .await;
    crate::dns_cache::TEST_LOOKUP.replace(None);
    assert_eq!(server.await.unwrap(), "GET /initial HTTP/1.1\r\n");
    assert!(matches!(result, Err(Error::Refused(message)) if message == OFF_MACHINE));
    assert_eq!(resolved.get(), 0);
    assert_eq!(shared_lookups.get(), shared_before);
    assert_eq!(
        crate::http_client::UNPINNED_LOCAL_DNS_LOOKUPS.with(Cell::get),
        lookups_before
    );
}

#[tokio::test]
async fn a_loopback_redirect_uses_the_checked_addresses_and_final_page() {
    // Bug: A safe redirect is refused, re-resolved at connection time, or evaluated as its first page.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://{address}/initial")).unwrap();
    let final_url = "http://app.localhost/final";
    // A checked endpoint at a non-default port is unreachable via an ordinary DNS lookup.
    let pinned = SocketAddr::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), address.port());
    let system_addrs = tokio::net::lookup_host(("app.localhost", 80)).await;
    assert!(system_addrs
        .into_iter()
        .flatten()
        .all(|addr| addr != pinned));
    let location = format!("Location: {final_url}\r\n");
    let server = tokio::spawn(async move {
        let first = reply(&listener, "302 Found", &location, "redirect body").await;
        let second = reply(
            &listener,
            "200 OK",
            "Set-Cookie: session=xyz\r\n",
            "final body",
        )
        .await;
        (first, second)
    });
    let resolved = Cell::new(0);
    let (request, body) = fetch_local(
        target.clone(),
        vec![address],
        deadline(),
        ScanPurpose::OneShot,
        async |hop| {
            assert_eq!(hop.as_str(), final_url);
            resolved.set(resolved.get() + 1);
            Ok(vec![pinned])
        },
    )
    .await
    .unwrap();
    assert_eq!(resolved.get(), 1);
    assert_eq!(
        server.await.unwrap(),
        (
            "GET /initial HTTP/1.1\r\n".into(),
            "GET /final HTTP/1.1\r\n".into()
        )
    );
    assert_eq!(request.requested_url, target.as_str());
    assert_eq!(request.final_url, final_url);
    assert_eq!(request.status, 200);
    assert!(request.header_lines.is_empty());
    assert_eq!(request.body.slice(&body).unwrap(), b"final body");
}

#[tokio::test]
async fn a_mapped_loopback_redirect_stays_in_the_local_lane() {
    // Bug: The local fetch refuses a redirect to an IPv4-mapped loopback literal.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://{address}/initial")).unwrap();
    let hop = format!("http://[::ffff:127.0.0.1]:{}/final", address.port());
    let location = format!("Location: {hop}\r\n");
    let server = tokio::spawn(async move {
        assert_eq!(
            reply(&listener, "302 Found", &location, "").await,
            "GET /initial HTTP/1.1\r\n"
        );
        reply(&listener, "200 OK", "", "mapped body").await
    });
    let (request, body) = fetch_local(
        target,
        vec![address],
        deadline(),
        ScanPurpose::OneShot,
        resolve,
    )
    .await
    .unwrap();
    assert_eq!(server.await.unwrap(), "GET /final HTTP/1.1\r\n");
    assert_eq!(request.final_url, Url::parse(&hop).unwrap().as_str());
    assert_eq!(request.body.slice(&body).unwrap(), b"mapped body");
}

#[tokio::test]
async fn a_redirect_loop_returns_a_fetch_error() {
    // Bug: The local lane can report a redirect loop as a refusal or a different fetch error.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://{address}/a")).unwrap();
    let server = tokio::spawn(async move {
        assert_eq!(
            reply(&listener, "302 Found", "Location: /b\r\n", "").await,
            "GET /a HTTP/1.1\r\n"
        );
        assert_eq!(
            reply(&listener, "302 Found", "Location: /a\r\n", "").await,
            "GET /b HTTP/1.1\r\n"
        );
    });
    let result = fetch_local(
        target,
        vec![address],
        deadline(),
        ScanPurpose::Watch,
        resolve,
    )
    .await;
    server.await.unwrap();
    assert!(
        matches!(&result, Err(Error::Fetch(message)) if message == REDIRECT_LOOP),
        "{result:?}"
    );
}

#[tokio::test]
async fn ten_local_redirects_return_a_fetch_error_after_ten_requests() {
    // Bug: The local lane can stop at the wrong hop or report the wrong error at the limit.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://{address}/0")).unwrap();
    let server = tokio::spawn(async move {
        for step in 0..10 {
            let location = format!("Location: /{}\r\n", step + 1);
            assert_eq!(
                reply(&listener, "302 Found", &location, "").await,
                format!("GET /{step} HTTP/1.1\r\n")
            );
        }
    });
    let result = fetch_local(
        target,
        vec![address],
        deadline(),
        ScanPurpose::Watch,
        resolve,
    )
    .await;
    assert!(
        matches!(&result, Err(Error::Fetch(message)) if message == TOO_MANY_REDIRECTS),
        "{result:?}"
    );
    tokio::time::timeout(HTTP_CLIENT_TIMEOUT, server)
        .await
        .expect("the local lane must send all ten requests")
        .unwrap();
}

#[tokio::test]
async fn a_redirect_without_a_location_returns_a_fetch_error() {
    // Bug: The local lane can report a redirect without a Location as a different fetch error.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://{address}/a")).unwrap();
    let server = tokio::spawn(async move { reply(&listener, "302 Found", "", "").await });
    let result = fetch_local(
        target,
        vec![address],
        deadline(),
        ScanPurpose::Watch,
        resolve,
    )
    .await;
    assert_eq!(server.await.unwrap(), "GET /a HTTP/1.1\r\n");
    assert!(
        matches!(&result, Err(Error::Fetch(message)) if message == INVALID_REDIRECT),
        "{result:?}"
    );
}

#[tokio::test]
async fn an_off_machine_redirect_at_the_hop_limit_is_refused() {
    // Bug: The hop limit turns an off-machine redirect into a retryable watch error.
    use crate::cli::local_redirects::REDIRECT_HOP_LIMIT;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Url::parse(&format!("http://{address}/0")).unwrap();
    let server = tokio::spawn(async move {
        for step in 0..REDIRECT_HOP_LIMIT {
            let location = if step + 1 == REDIRECT_HOP_LIMIT {
                "Location: https://example.com/\r\n".into()
            } else {
                format!("Location: /{}\r\n", step + 1)
            };
            assert_eq!(
                reply(&listener, "302 Found", &location, "").await,
                format!("GET /{step} HTTP/1.1\r\n")
            );
        }
    });
    let result = fetch_local(
        target,
        vec![address],
        deadline(),
        ScanPurpose::Watch,
        resolve,
    )
    .await;
    assert!(matches!(result, Err(Error::Refused(message)) if message == OFF_MACHINE));
    server.await.unwrap();
}

#[tokio::test]
async fn local_fetch_uses_the_configured_deadline_above_the_client_default() {
    // Bug: A local page that takes over 30 seconds fails even with a longer scan timeout.
    assert_local_fetch_deadline(|result| {
        assert_eq!(result.mode, "predeploy");
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].check_id, "standin.rule");
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn hosted_dns_timeout_uses_hosted_copy() {
    // Bug: DNS resolution of a hosted URL reports the local fetch timeout.
    let target = Url::parse("https://example.com/").unwrap();
    let result = resolve_target(&target, HTTP_CLIENT_TIMEOUT, async |_| {
        std::future::pending().await
    })
    .await;
    assert!(matches!(result, Err(Error::Fetch(message)) if message == HOSTED_DNS_TIMEOUT));
    assert_ne!(HOSTED_DNS_TIMEOUT, FETCH_TIMEOUT);
}

#[tokio::test]
async fn local_scan_needs_no_sign_in() {
    // Bug: Scanning on loopback initializes a connected-service client or checks for a sign-in.
    assert_local_scan_needs_no_sign_in("cli::lane::tests::local_scan_needs_no_sign_in", |result| {
        assert_eq!(result.mode, "predeploy");
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].check_id, "standin.rule");
        assert_eq!(result.overall_score, 100);
    })
    .await;
}

#[test]
fn missing_local_categories_are_an_invalid_score() {
    // A module answer the host prints without checking.
    let request = LocalSiteRequest {
        requested_url: "http://localhost/index.html".into(),
        final_url: "http://localhost/index.html".into(),
        status: 200,
        header_lines: vec![],
        body: BodyRef { at: 0, len: 0 },
        now_ms: 0,
        polish_only: false,
        categories: None,
    };
    let engine = sitecmd_engine_host::load().unwrap();
    let mut answer = engine.local_site_evaluate(&request, &[]).unwrap();
    assert!(answer.categories.take().is_some());
    assert_eq!(
        local_scan_result(request, answer, ScanType::Health, WallClock::now()).unwrap_err(),
        INVALID_ENGINE_SCORE
    );
}

#[test]
fn local_category_above_100_is_an_invalid_score() {
    // An out-of-range category score can reach the local scan display.
    let request = LocalSiteRequest {
        requested_url: "http://localhost/index.html".into(),
        final_url: "http://localhost/index.html".into(),
        status: 200,
        header_lines: vec![],
        body: BodyRef { at: 0, len: 0 },
        now_ms: 0,
        polish_only: false,
        categories: None,
    };
    let engine = sitecmd_engine_host::load().unwrap();
    let mut answer = engine.local_site_evaluate(&request, &[]).unwrap();
    answer.categories.as_mut().unwrap()[0].score = 101;
    assert_eq!(
        local_scan_result(request, answer, ScanType::Health, WallClock::now()).unwrap_err(),
        INVALID_ENGINE_SCORE
    );
}

#[test]
fn local_fix_points_must_match_actionable_findings_and_fit_score_headroom() {
    // Bug: Extra point entries or gains exceeding 100 points can reach scan artifacts.
    let request = LocalSiteRequest {
        requested_url: "http://localhost/index.html".into(),
        final_url: "http://localhost/index.html".into(),
        status: 200,
        header_lines: vec![],
        body: BodyRef { at: 0, len: 0 },
        now_ms: 0,
        polish_only: false,
        categories: None,
    };
    let engine = sitecmd_engine_host::load().unwrap();
    let answer = engine.local_site_evaluate(&request, &[]).unwrap();
    let mut wrong_length = answer.clone();
    wrong_length.fix_points.push(0);
    let mut excessive = answer.clone();
    excessive.score.overall = 100.0;
    excessive.fix_points[0] = 1;
    assert!(local_scan_result(request.clone(), answer, ScanType::Health, WallClock::now()).is_ok());
    for answer in [wrong_length, excessive] {
        assert_eq!(
            local_scan_result(request.clone(), answer, ScanType::Health, WallClock::now())
                .unwrap_err(),
            INVALID_ENGINE_SCORE
        );
    }
}
