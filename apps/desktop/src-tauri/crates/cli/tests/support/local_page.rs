use std::{
    io::{BufRead, BufReader},
    net::{TcpListener, TcpStream},
    path::Path,
    time::Duration,
};

pub fn with_local_page<T: std::fmt::Debug>(
    respond: impl FnOnce(&mut TcpStream) + Send + 'static,
    run: impl FnOnce(&str, &Path) -> T,
) -> T {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(&stream);
        let mut request = String::new();
        loop {
            request.clear();
            if reader.read_line(&mut request).unwrap() == 0 || request == "\r\n" {
                break;
            }
        }
        respond(&mut stream);
        sent.send(()).unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let output = run(&format!("http://{address}/"), directory.path());
    received
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| {
            panic!("site did not respond: {error}: {output:?}");
        });
    server.join().unwrap();
    output
}

pub fn write_hosted_artifact(config: &Path, check: &str) -> String {
    std::fs::create_dir(config).unwrap();
    let artifact = format!(
        r#"{{
        "hosted": {{"connectOrigin":"https://connect.sitecmd.com","siteId":"site_a",
        "scanId":"hs_a","url":"https://example.com","overallScore":80,
        "timestamp":"2026-11-21T16:00:00.000Z","categoryScores":{{}},
        "issues":[{{"checkId":"{check}","title":"Fixture issue","category":"config",
        "severity":"medium","occurrences":1}}]}}
    }}"#
    );
    std::fs::write(config.join("last-scan.json"), &artifact).unwrap();
    artifact
}
