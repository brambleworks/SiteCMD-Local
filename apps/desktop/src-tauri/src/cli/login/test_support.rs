use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type DeleteHook = Arc<dyn Fn(&str) + Send + Sync>;

pub(super) struct ConnectDouble {
    pub origin: String,
    pub live: Arc<Mutex<HashSet<String>>>,
    pub replacement_saved: Arc<AtomicBool>,
    pub captured: tokio::task::JoinHandle<Vec<String>>,
}

impl ConnectDouble {
    pub async fn serve(
        responses: Vec<(String, &'static str)>,
        saved_path: Option<PathBuf>,
        initial_tokens: &[&str],
    ) -> Self {
        Self::serve_inner(responses, saved_path, initial_tokens, None, None, None).await
    }

    pub async fn serve_with_delete_hook(
        responses: Vec<(String, &'static str)>,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::serve_with_delete_observer(responses, Arc::new(move |_| hook())).await
    }

    pub async fn serve_with_delete_observer(
        responses: Vec<(String, &'static str)>,
        hook: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Self {
        Self::serve_inner(responses, None, &["old-bearer"], Some(hook), None, None).await
    }

    pub async fn serve_with_after_delete_hook(
        responses: Vec<(String, &'static str)>,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::serve_inner(responses, None, &["old-bearer"], None, None, Some(hook)).await
    }

    pub async fn serve_with_poll_hook(
        responses: Vec<(String, &'static str)>,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::serve_inner(
            responses,
            None,
            &["old-bearer", "file-bearer"],
            None,
            Some(hook),
            None,
        )
        .await
    }

    async fn serve_inner(
        responses: Vec<(String, &'static str)>,
        saved_path: Option<PathBuf>,
        initial_tokens: &[&str],
        on_delete: Option<DeleteHook>,
        on_poll: Option<Arc<dyn Fn() + Send + Sync>>,
        after_delete: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let live = Arc::new(Mutex::new(
            initial_tokens
                .iter()
                .map(|token| token.to_string())
                .collect::<HashSet<_>>(),
        ));
        let replacement_saved = Arc::new(AtomicBool::new(false));
        let observed_live = live.clone();
        let observed_saved = replacement_saved.clone();
        let captured = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (body, status) in responses {
                let accepted =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await;
                let Ok(Ok((mut stream, _))) = accepted else {
                    break;
                };
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0; 8192];
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(n, 0, "incomplete local request");
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|slice| slice == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(str::trim)
                                    .and_then(|length| length.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                if request.starts_with("POST /v1/cli/token ") {
                    if let Some(hook) = &on_poll {
                        hook();
                    }
                }
                if request.starts_with("POST /v1/cli/token ") && status == "200 OK" {
                    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
                    if let Some(token) = value["token"].as_str() {
                        observed_live.lock().unwrap().insert(token.into());
                    }
                }
                if request.starts_with("DELETE /v1/account/tokens/current ") {
                    if let Some(hook) = &on_delete {
                        hook(&request);
                    }
                    if let Some(path) = &saved_path {
                        let saved = std::fs::read_to_string(path).unwrap_or_default();
                        observed_saved
                            .store(saved.contains("sitecmd_pat_FIXTURE"), Ordering::SeqCst);
                    }
                    if status == "204 No Content" {
                        let bearer = request
                            .lines()
                            .find_map(|line| {
                                line.split_once(':')
                                    .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                                    .and_then(|(_, value)| value.trim().strip_prefix("Bearer "))
                            })
                            .unwrap();
                        observed_live.lock().unwrap().remove(bearer);
                    }
                }
                let is_delete = request.starts_with("DELETE /v1/account/tokens/current ");
                requests.push(request);
                let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
                if is_delete {
                    if let Some(hook) = &after_delete {
                        hook();
                    }
                }
            }
            requests
        });
        Self {
            origin,
            live,
            replacement_saved,
            captured,
        }
    }
}
