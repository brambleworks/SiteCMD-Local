use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::configure;

#[test]
fn self_signed_exception_is_limited_to_strict_loopback_names() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};

    let verifier = super::LoopbackVerifier(
        rustls_platform_verifier::Verifier::new(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap(),
    );
    let certificate = CertificateDer::from(include_bytes!("testdata/cert.der").as_slice());
    for (name, allowed) in [
        ("localhost", true),
        ("LOCALHOST.", true),
        ("127.0.0.2", true),
        ("::1", true),
        ("public.example", false),
        ("api.localhost", false),
        ("localhost.example", false),
        ("192.168.1.1", false),
        ("::ffff:127.0.0.1", false),
    ] {
        let result = verifier.verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from(name).unwrap(),
            &[],
            UnixTime::now(),
        );
        assert_eq!(result.is_ok(), allowed, "certificate policy for {name}");
    }
}

async fn tls_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<bool>) {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(
            include_bytes!("testdata/cert.der").to_vec(),
        )],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("testdata/key.der").to_vec(),
        )),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
        else {
            return false;
        };
        let mut request = [0; 4096];
        if tls.read(&mut request).await.is_err() {
            return false;
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        true
    });
    (address, task)
}

fn local_scan_client(address: std::net::SocketAddr) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    configure(reqwest::Client::builder())
        .resolve("public.example", address)
        .timeout(crate::constants::API_TIMEOUT_SHORT)
        .build()
        .unwrap()
}

#[tokio::test]
async fn local_scan_client_offers_http2_and_http1_over_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let observed = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let handshake =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await
                .unwrap();
        handshake
            .client_hello()
            .alpn()
            .into_iter()
            .flatten()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    });
    let _ = local_scan_client(address)
        .get(format!("https://{address}/"))
        .send()
        .await;
    assert_eq!(
        observed.await.unwrap(),
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[tokio::test]
async fn accepts_self_signed_loopback_server() {
    let (address, served) = tls_server().await;
    let response = local_scan_client(address)
        .get(format!("https://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(served.await.unwrap());
}

#[tokio::test]
async fn loopback_certificate_exceptions_ignore_proxy_routing() {
    let (address, served) = tls_server().await;
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let client =
        configure(reqwest::Client::builder().proxy(reqwest::Proxy::all(proxy_url).unwrap()))
            .timeout(crate::constants::API_TIMEOUT_SHORT)
            .build()
            .unwrap();
    let response = client.get(format!("https://{address}/")).send().await;
    proxy_task.abort();
    assert_eq!(response.unwrap().status(), reqwest::StatusCode::OK);
    assert!(served.await.unwrap());
}

#[tokio::test]
async fn rejects_self_signed_public_asset_during_local_scan() {
    let (address, served) = tls_server().await;
    let result = local_scan_client(address)
        .get(format!("https://public.example:{}/asset", address.port()))
        .send()
        .await;
    assert!(
        result.is_err(),
        "public assets must have a trusted certificate"
    );
    assert!(!served.await.unwrap());
}

#[tokio::test]
async fn rejects_self_signed_public_redirect_during_local_scan() {
    let (address, served) = tls_server().await;
    let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_address = redirect.local_addr().unwrap();
    let redirected = tokio::spawn(async move {
        let (mut stream, _) = redirect.accept().await.unwrap();
        let mut request = [0; 4096];
        let received = stream.read(&mut request).await.unwrap();
        assert!(received > 0, "redirect server must receive a request");
        stream.write_all(format!(
            "HTTP/1.1 302 Found\r\nLocation: https://public.example:{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            address.port()
        ).as_bytes()).await.unwrap();
    });
    let result = local_scan_client(address)
        .get(format!("http://{redirect_address}/"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "redirects must verify the destination certificate"
    );
    redirected.await.unwrap();
    assert!(!served.await.unwrap());
}
