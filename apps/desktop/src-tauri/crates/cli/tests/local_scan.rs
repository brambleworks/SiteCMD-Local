use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};

#[path = "support/cli_binary.rs"]
mod cli_binary;
use cli_binary::cli_binary;
use std::time::{Duration, Instant};

#[path = "support/local_page.rs"]
mod local_page;
use local_page::{with_local_page, write_hosted_artifact};

use serde_json::Value;
use sitecmd_runtime::cli::lane::LOCAL_CHECKS_NOTICE as PENDING;

fn scan_page(args: &[&str], respond: impl FnOnce(&mut TcpStream) + Send + 'static) -> Output {
    with_local_page(respond, |url, directory| {
        cli(directory)
            .args(["scan", "--url", url])
            .args(args)
            .output()
            .unwrap()
    })
}

fn cli(directory: &Path) -> Command {
    let mut command = Command::new(cli_binary());
    command.current_dir(directory).env_remove("RUST_LOG");
    command
}

#[test]
fn mapped_loopback_target_is_scanned_locally() {
    // Bug: An IPv4-mapped loopback target goes through the hosted scan.
    let output = with_local_page(serve_fixture, |url, directory| {
        let url = url.replace("127.0.0.1", "[::ffff:127.0.0.1]");
        cli(directory)
            .args(["scan", "--url", &url, "--json"])
            .output()
            .unwrap()
    });
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let scan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(scan["mode"], "predeploy");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("{PENDING}\n")
    );
}

#[test]
fn local_category_filter_limits_results_and_scores() {
    let output = scan_page(&["--categories", "accessibility", "--json"], serve_fixture);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let scan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(scan["issues"], serde_json::json!([]));
    assert_eq!(scan["categories"], serde_json::json!([]));
    assert_eq!(scan["overallScore"], 0);
}

#[test]
fn local_json_output_keeps_the_pending_line_on_stderr() {
    // Bug: A human-readable notice corrupts machine-readable scan output.
    let output = scan_page(&["--json"], serve_finding_fixture);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let scan: Value = serde_json::from_str(&stdout).unwrap();
    assert!(scan["issues"].as_array().unwrap().iter().any(is_actionable));
    assert!(!stdout.contains(PENDING), "{stdout}");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("{PENDING}\n")
    );
}

#[test]
fn local_output_adds_the_pending_line() {
    // Bug: The local scan leaves readers guessing when the other checks run.
    let output = scan_page(&[], serve_finding_fixture);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\nIssues ("), "{stdout}");
    assert_eq!(
        stdout.lines().filter(|line| *line == PENDING).count(),
        1,
        "{stdout}"
    );
}

#[test]
fn strict_check_uses_and_preserves_a_hosted_artifact() {
    // Bug: Strict check treats hosted findings as no baseline and replaces the hosted artifact.
    let scan = scan_page(&["--json"], serve_finding_fixture);
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let scan: Value = serde_json::from_slice(&scan.stdout).unwrap();
    let finding = scan["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|issue| is_actionable(issue))
        .unwrap();
    let check_id = finding["checkId"].as_str().unwrap();

    for (check, expected) in [("fixture.other", 1), (check_id, 0)] {
        let output = with_local_page(serve_finding_fixture, |url, directory| {
            let config = directory.join(".sitecmd");
            let artifact = write_hosted_artifact(&config, check);
            std::fs::write(
                config.join("config.json"),
                format!(r#"{{"version":1,"url":"{url}","name":"Local site"}}"#),
            )
            .unwrap();
            let output = cli(directory).args(["check", "--strict"]).output().unwrap();
            assert_eq!(
                std::fs::read_to_string(config.join("last-scan.json")).unwrap(),
                artifact
            );
            assert!(!config.join("issues.json").exists());
            output
        });
        assert_eq!(output.status.code(), Some(expected), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.contains("1 new issue"), expected == 1, "{stderr}");
        assert!(!stderr.contains("No previous scan"), "{stderr}");
    }
}

fn is_actionable(issue: &Value) -> bool {
    matches!(issue["status"].as_str(), Some("fail" | "warn"))
}

#[test]
fn local_check_scans_locally() {
    // Bug: A loopback check enters the hosted lane and requires Connect configuration.
    let output = with_local_page(serve_fixture, |url, directory| {
        let config = directory.join(".sitecmd");
        std::fs::create_dir(&config).unwrap();
        std::fs::write(
            config.join("config.json"),
            format!(r#"{{"version":1,"url":"{url}","name":"Local site"}}"#),
        )
        .unwrap();
        let output = cli(directory)
            .env("SITECMD_CONNECT_ORIGIN", "http://connect.invalid")
            .env_remove("SITECMD_TOKEN")
            .args(["check", "--strict"])
            .output()
            .unwrap();
        let artifact = std::fs::read_to_string(config.join("last-scan.json")).unwrap();
        assert!(
            artifact.contains(&format!("\"url\": \"{url}\"")),
            "{artifact}"
        );
        assert!(!artifact.contains("\"hosted\":"), "{artifact}");
        output
    });
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .any(|line| line == PENDING));
}

#[test]
fn local_check_outputs_the_pending_line_as_plain_text() {
    // Bug: Terminal progress controls can prefix the notice in captured check output.
    let output = with_local_page(serve_fixture, |url, directory| {
        let config = directory.join(".sitecmd");
        std::fs::create_dir(&config).unwrap();
        std::fs::write(
            config.join("config.json"),
            format!(r#"{{"version":1,"url":"{url}","name":"Local site"}}"#),
        )
        .unwrap();
        cli(directory).args(["check", "--strict"]).output().unwrap()
    });
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.lines().filter(|line| *line == PENDING).count(),
        1,
        "{stderr}"
    );
}

#[test]
fn a_redirect_off_the_machine_exits_with_two() {
    // Bug: A refused redirect produces results or appears to be a failed check.
    let output = scan_page(&["--json"], |stream| {
        stream
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Scan failed: The local site redirected to a URL outside this computer.\n"
    );
}

#[test]
fn local_fetch_timeout_covers_the_response_body() {
    // Bug: The fetch timeout ends at the response headers and leaves a stalled body reading.
    let output = scan_page(&["--timeout", "1"], |stream| {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n<html>")
            .unwrap();
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    });
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Scan failed: The site fetch timed out.\n"
    );
}

#[test]
fn unspecified_addresses_are_refused_as_both_targets_and_redirects() {
    // Bug: An unspecified address is fetched or reported as being outside this computer.
    let directory = tempfile::tempdir().unwrap();
    for address in ["0.0.0.0", "[::]"] {
        let target = format!("http://{address}/");
        let initial = cli(directory.path())
            .args(["scan", "--url", &target, "--timeout", "1"])
            .output()
            .unwrap();
        let redirect = scan_page(&["--timeout", "1"], move |stream| {
            let port = stream.local_addr().unwrap().port();
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{address}:{port}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        for output in [initial, redirect] {
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "Scan failed: Use a specific address instead of an unspecified address such as 0.0.0.0 or [::].\n"
            );
        }
    }
}

struct RunningWatch(Child);

impl Drop for RunningWatch {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn watch_until(
    url: &str,
    directory: &Path,
    stop: impl Fn(&str) -> bool,
) -> (String, Option<ExitStatus>) {
    let stderr = directory.join("watch.stderr");
    let mut child = RunningWatch(
        cli(directory)
            .args(["watch", "--url", url, "--interval", "1"])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = child.0.try_wait().unwrap();
        let output = std::fs::read_to_string(&stderr).unwrap();
        if status.is_some() || stop(&output) {
            return (output, status);
        }
        assert!(
            Instant::now() < deadline,
            "watch did not reach the expected outcome: {output}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn watch_preserves_a_hosted_artifact() {
    // Bug: Watch replaces the hosted baseline with native results.
    with_local_page(serve_fixture, |url, directory| {
        let config = directory.join(".sitecmd");
        let artifact = write_hosted_artifact(&config, "seo.title");
        let (stderr, status) = watch_until(url, directory, |stderr| stderr.contains(PENDING));
        assert!(status.is_none(), "{status:?}: {stderr}");
        assert!(stderr.contains("[#1] Baseline - Score:"), "{stderr}");
        assert_eq!(
            std::fs::read_to_string(config.join("last-scan.json")).unwrap(),
            artifact
        );
        assert!(!config.join("issues.json").exists());
    });
}

#[test]
fn watch_retries_after_the_local_connection_is_refused() {
    // Bug: Watch exits after the first failed connection to a stopped local server.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    drop(listener);
    let directory = tempfile::tempdir().unwrap();
    let (stderr, status) = watch_until(&url, directory.path(), |stderr| {
        stderr.contains("[#3] Scan error:")
    });
    assert!(status.is_none(), "{status:?}: {stderr}");
    for iteration in 1..=3 {
        assert!(
            stderr.contains(&format!("[#{iteration}] Scan error: Failed to fetch ")),
            "{stderr}"
        );
    }
}

#[test]
fn watch_retries_http_errors_but_exits_on_an_off_machine_redirect() {
    // Bug: Watch stops on a transient HTTP error or keeps retrying a refused redirect.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for response in [
            "HTTP/1.1 503 Service Unavailable\r\n",
            "HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\n",
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            loop {
                line.clear();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
            }
            write!(
                stream,
                "{response}Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let (stderr, status) = watch_until(&url, directory.path(), |_| false);
    assert_eq!(status.and_then(|status| status.code()), Some(2), "{stderr}");
    assert!(
        stderr.contains("[#1] Scan error: The local site returned HTTP 503."),
        "{stderr}"
    );
    assert!(
        stderr.contains("Error: The local site redirected to a URL outside this computer."),
        "{stderr}"
    );
    assert!(!stderr.contains("[#2] Scan error:"), "{stderr}");
    server.join().unwrap();
}

#[test]
fn watch_exits_on_a_local_url_with_credentials() {
    // Bug: Watch repeats a URL refusal instead of exiting with code 2.
    let directory = tempfile::tempdir().unwrap();
    let url = "http://user:password@127.0.0.1/";
    let (stderr, status) = watch_until(url, directory.path(), |_| false);
    assert_eq!(status.and_then(|status| status.code()), Some(2), "{stderr}");
    assert!(
        stderr.contains("Error: Remove the username and password from the local site URL."),
        "{stderr}"
    );
    assert!(!stderr.contains("Scan error:"), "{stderr}");
}

fn serve_fixture(stream: &mut TcpStream) {
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
}

fn serve_finding_fixture(stream: &mut TcpStream) {
    let body = "<html><body><script>console.log('Fixture');</script></body></html>";
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
    .unwrap();
}
