//! Local wire doubles and disposable checkout for connection regressions.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use super::{connect_with, ConnectArgs};
use crate::cli::autofix::github_api::GitHubApi;
use crate::connected_service::ConnectedServiceClient;

pub(super) const REPOSITORY: &str = "example-org/example-site";
pub(super) const SITE_URL: &str = "https://site-repo.example.com/entry";

pub(super) fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/connect/code-flow")
        .join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

pub(super) struct Reply {
    pub status: u16,
    pub body: Zeroizing<String>,
    pub retry_after: Option<u64>,
}

impl Reply {
    pub fn fixture(name: &str) -> Self {
        let wire = fixture(name);
        Self {
            status: wire["status"].as_u64().unwrap() as u16,
            body: Zeroizing::new(wire["body"].to_string()),
            retry_after: None,
        }
    }
    pub fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body: Zeroizing::new(body.to_string()),
            retry_after: None,
        }
    }
}

pub(super) struct Request {
    pub route: String,
    pub body: Zeroizing<String>,
    pub connection_bearer: bool,
    pub github_bearer: bool,
}

pub(super) struct Harness {
    pub args: ConnectArgs,
    pub head: String,
    pub requests: Arc<Mutex<Vec<Request>>>,
    pub waits: Arc<Mutex<Vec<std::time::Duration>>>,
    pub key: crypto_box::SecretKey,
    pub client: ConnectedServiceClient,
    pub github: GitHubApi,
    task: tokio::task::JoinHandle<()>,
    _checkout: tempfile::TempDir,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    pub async fn new(mut replies: Vec<Reply>) -> Self {
        let checkout = tempfile::tempdir().unwrap();
        let path = checkout.path();
        std::fs::write(path.join("package.json"), "{\"name\":\"connect-test\"}\n").unwrap();
        std::fs::write(path.join("app.js"), "export const run = x => eval(x);\n").unwrap();
        for args in [
            vec!["init", "-q", "-b", "main"],
            vec!["config", "user.name", "Test User"],
            vec!["config", "user.email", "test@example.com"],
            vec!["config", "commit.gpgsign", "false"],
            vec![
                "remote",
                "add",
                "origin",
                "git@github.com:example-org/example-site.git",
            ],
            vec!["add", "."],
            vec!["commit", "-qm", "Fixture checkout"],
        ] {
            let output = crate::core::git::run_git_command(
                path,
                &args,
                crate::constants::AUTOFIX_GIT_TIMEOUT,
                None,
            )
            .unwrap();
            assert!(output.ok());
        }
        let head = crate::core::git::checkout_head_and_clean(&path.to_string_lossy())
            .unwrap()
            .0;
        let key = crypto_box::SecretKey::from_bytes([42; 32]);
        for reply in &mut replies {
            if reply.body.as_str() == "PUBLIC_KEY" {
                reply.body = Zeroizing::new(
                    json!({"key_id":"key-id", "key":STANDARD.encode(key.public_key().as_bytes())})
                        .to_string(),
                );
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            let mut replies: VecDeque<_> = replies.into();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Zeroizing::new(Vec::new());
                let (header_end, length) = loop {
                    let mut chunk = Zeroizing::new([0; 4096]);
                    let read = stream.read(&mut *chunk).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while bytes.len() < header_end + length {
                    let mut chunk = Zeroizing::new([0; 4096]);
                    let read = stream.read(&mut *chunk).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                }
                let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let first = headers.lines().next().unwrap();
                let route = first.strip_suffix(" HTTP/1.1").unwrap().to_string();
                captured.lock().unwrap().push(Request {
                    route,
                    body: Zeroizing::new(
                        std::str::from_utf8(&bytes[header_end..header_end + length])
                            .unwrap()
                            .to_string(),
                    ),
                    connection_bearer: headers.lines().any(|line| {
                        line.eq_ignore_ascii_case("authorization: Bearer sitecmd_cnx_FIXTURE")
                    }),
                    github_bearer: headers
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case("authorization: Bearer ghs_FIXTURE")),
                });
                let reply = replies
                    .pop_front()
                    .unwrap_or_else(|| Reply::json(500, json!({})));
                if reply.status == 0 {
                    continue;
                }
                let retry_after = reply
                    .retry_after
                    .map(|seconds| format!("Retry-After: {seconds}\r\n"))
                    .unwrap_or_default();
                let response = Zeroizing::new(format!("HTTP/1.1 {} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{retry_after}\r\n{}", reply.status, reply.body.len(), reply.body.as_str()));
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            args: ConnectArgs {
                url: "https://Example.com/path".into(),
                repository: None,
                rotate: false,
                connect_origin: Some(origin.clone()),
                path: Some(PathBuf::from(path)),
            },
            head,
            requests,
            waits: Arc::new(Mutex::new(Vec::new())),
            key,
            client: ConnectedServiceClient::for_endpoint(&origin, None, true).unwrap(),
            github: GitHubApi::for_test(&origin).unwrap(),
            task,
            _checkout: checkout,
        }
    }

    pub async fn run(&self) -> (Result<String, String>, String) {
        let mut stderr = Vec::new();
        let waits = self.waits.clone();
        let result = connect_with(
            &self.args,
            &self.client,
            &self.github,
            &mut stderr,
            move |delay| {
                waits.lock().unwrap().push(delay);
                Box::pin(async {})
            },
        )
        .await;
        (result, String::from_utf8(stderr).unwrap())
    }

    pub fn routes(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.route.clone())
            .collect()
    }

    pub fn opened_secret(&self, name: &str) -> Zeroizing<Vec<u8>> {
        let requests = self.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|request| request.route.ends_with(name))
            .unwrap();
        let body: Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["key_id"], "key-id");
        let sealed = STANDARD
            .decode(body["encrypted_value"].as_str().unwrap())
            .unwrap();
        Zeroizing::new(self.key.unseal(&sealed).unwrap())
    }
}

pub(super) fn success(version: i64) -> Vec<Reply> {
    let mut approved = fixture("connect");
    approved["body"]["key_version"] = json!(version);
    approved["body"]["site_url"] = json!(SITE_URL);
    vec![
        Reply::fixture("issued"),
        Reply::json(200, approved["body"].clone()),
        Reply::json(
            200,
            json!({"status": if version == 1 { "bootstrapped" } else { "applied" }, "key_version":version}),
        ),
        Reply::fixture("secrets-token"),
        Reply {
            status: 200,
            body: Zeroizing::new("PUBLIC_KEY".into()),
            retry_after: None,
        },
        Reply::json(201, json!({})),
        Reply::json(204, json!({})),
        Reply {
            status: 204,
            body: Zeroizing::new(String::new()),
            retry_after: None,
        },
        Reply::fixture("secrets-provisioned"),
    ]
}
