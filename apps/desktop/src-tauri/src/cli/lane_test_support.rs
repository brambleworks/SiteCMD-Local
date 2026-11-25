//! Loopback-only fixtures for the local lane.

use super::lane::{Error, Lane, ScanPurpose, Target, FETCH_TIMEOUT};
use crate::constants::HTTP_CLIENT_TIMEOUT;
use crate::core::scan_types::{ScanResult, ScanType};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub(super) async fn accept_request(listener: &TcpListener) -> (tokio::net::TcpStream, String) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut reader = BufReader::new(&mut stream);
    let mut request = String::new();
    reader.read_line(&mut request).await.unwrap();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
            break;
        }
    }
    (stream, request)
}

pub(super) async fn reply(
    listener: &TcpListener,
    status: &str,
    headers: &str,
    body: &str,
) -> String {
    let (mut stream, request) = accept_request(listener).await;
    let response = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    request
}

pub(super) async fn assert_local_fetch_deadline(verify: impl Fn(ScanResult)) {
    let response_delay = HTTP_CLIENT_TIMEOUT + Duration::from_secs(1);
    for (timeout, succeeds) in [(2, false), (60, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (_, result) = tokio::join!(
            async {
                let (mut stream, request) = accept_request(&listener).await;
                assert_eq!(request, "GET / HTTP/1.1\r\n");
                tokio::time::pause();
                tokio::time::sleep(response_delay).await;
                tokio::time::resume();
                let sent = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                if succeeds {
                    sent.unwrap();
                }
            },
            async {
                let target = Target::resolve(&url, Some(timeout)).await?;
                let lane = target.lane();
                let result = target
                    .scan_local(ScanType::Health, ScanPurpose::OneShot, None)
                    .await?;
                Ok((lane, result))
            },
        );
        if succeeds {
            let (lane, result) = result.unwrap();
            assert_eq!(lane, Lane::Local);
            verify(result);
        } else {
            assert!(matches!(result, Err(Error::Fetch(message)) if message == FETCH_TIMEOUT));
        }
    }
}

pub(super) async fn assert_local_scan_needs_no_sign_in(
    test_name: &str,
    verify: impl FnOnce(ScanResult),
) {
    use crate::connected_service::{ConnectedServiceClient, CLIENT_CONSTRUCTION_ATTEMPTS};
    use std::sync::atomic::Ordering::Relaxed;

    // Run alone so concurrent connected-service tests cannot affect the process-wide count.
    const ISOLATED: &str = "SITECMD_TEST_ISOLATED_LOCAL_SCAN";
    if std::env::var_os(ISOLATED).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name])
            .env(ISOLATED, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let before = CLIENT_CONSTRUCTION_ATTEMPTS.load(Relaxed);
    tokio::spawn(async {
        ConnectedServiceClient::for_origin("https://127.0.0.1", None).unwrap();
    })
    .await
    .unwrap();
    let after_control = CLIENT_CONSTRUCTION_ATTEMPTS.load(Relaxed);
    assert_eq!(after_control, before + 1);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server =
        tokio::spawn(
            async move { reply(&listener, "200 OK", "", "<html>A local page</html>").await },
        );
    let target = Target::resolve(&url, None).await.unwrap();
    let lane = target.lane();
    let result = target
        .scan_local(ScanType::Health, ScanPurpose::OneShot, None)
        .await
        .unwrap();
    assert_eq!(lane, Lane::Local);
    verify(result);
    assert_eq!(server.await.unwrap(), "GET / HTTP/1.1\r\n");
    assert_eq!(CLIENT_CONSTRUCTION_ATTEMPTS.load(Relaxed), after_control);
}
