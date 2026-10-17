//! Loopback HTTP doubles for the connected-service wire tests: a listener that
//! answers a fixed response and hands back the exact bytes the client sent.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What every machine door answers a read-only account.
pub(crate) const ACCOUNT_INACTIVE_PROBLEM: &str = r#"{"type":"about:blank","title":"Forbidden","status":403,"detail":"This account is inactive.","code":"account_inactive","request_id":"req_0123456789abcdef"}"#;

/// What a CI door answers a subscription that cannot watch its sites.
pub(crate) const ENTITLEMENT_SUSPENDED_PROBLEM: &str = r#"{"type":"about:blank","title":"Forbidden","status":403,"detail":"This subscription cannot watch its sites.","code":"entitlement_suspended","request_id":"req_0123456789abcdef"}"#;

/// Answer one connection with `body` under `status`, returning the origin to
/// point a client at and the request that arrived.
pub(crate) async fn respond_once(
    body: &'static str,
    status: &'static str,
) -> (String, JoinHandle<String>) {
    respond_once_with_headers(body, status, &[]).await
}

/// `respond_once`, with `headers` (whole `Name: value` lines) added to the
/// response.
pub(crate) async fn respond_once_with_headers(
    body: &'static str,
    status: &'static str,
    headers: &'static [&'static str],
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let captured = tokio::spawn(async move {
        let (mut stream, _) = accept(&listener).await;
        read_and_answer(&mut stream, body, status, headers).await
    });
    (format!("http://{address}"), captured)
}

/// Answer one connection per response, in order, and return every request, for
/// the flows that make more than one call against the same origin. The body is
/// owned so a flow whose answer depends on the test's own fixtures, such as a
/// claim naming the checkout's head, can build one.
pub(crate) async fn respond_in_sequence(
    responses: Vec<(String, &'static str)>,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let captured = tokio::spawn(async move {
        let mut requests = Vec::with_capacity(responses.len());
        for (body, status) in responses {
            let (mut stream, _) = accept(&listener).await;
            requests.push(read_and_answer(&mut stream, &body, status, &[]).await);
        }
        requests
    });
    (format!("http://{address}"), captured)
}

/// The method, path and version a captured request opened with.
pub(crate) fn request_line(request: &str) -> &str {
    request.lines().next().unwrap_or_default()
}

/// A flow that short-circuits must fail the test rather than hang it, so a
/// connection that never arrives is bounded.
async fn accept(listener: &TcpListener) -> (TcpStream, std::net::SocketAddr) {
    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
        .await
        .expect("a request within five seconds")
        .expect("accept")
}

async fn read_and_answer(
    stream: &mut TcpStream,
    body: &str,
    status: &str,
    headers: &[&str],
) -> String {
    let mut bytes = vec![0_u8; 64 * 1024];
    let read = stream.read(&mut bytes).await.expect("read");
    let request = String::from_utf8_lossy(&bytes[..read]).to_string();
    let extra: String = headers.iter().map(|line| format!("{line}\r\n")).collect();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("respond");
    request
}
