//! Loopback HTTP doubles for the connected-service wire tests: a listener that
//! answers a fixed response and hands back the exact bytes the client sent.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Answer one connection with `body` under `status`, returning the origin to
/// point a client at and the request that arrived.
pub(crate) async fn respond_once(
    body: &'static str,
    status: &'static str,
) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let captured = tokio::spawn(async move {
        let (mut stream, _) = accept(&listener).await;
        read_and_answer(&mut stream, body, status).await
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
            requests.push(read_and_answer(&mut stream, &body, status).await);
        }
        requests
    });
    (format!("http://{address}"), captured)
}

/// A flow that short-circuits must fail the test rather than hang it, so a
/// connection that never arrives is bounded.
async fn accept(listener: &TcpListener) -> (TcpStream, std::net::SocketAddr) {
    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
        .await
        .expect("a request within five seconds")
        .expect("accept")
}

async fn read_and_answer(stream: &mut TcpStream, body: &str, status: &str) -> String {
    let mut bytes = vec![0_u8; 64 * 1024];
    let read = stream.read(&mut bytes).await.expect("read");
    let request = String::from_utf8_lossy(&bytes[..read]).to_string();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("respond");
    request
}
