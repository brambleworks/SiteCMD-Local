use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

pub struct LocalSite {
    pub url: String,
    address: SocketAddr,
    degraded: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LocalSite {
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let degraded = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker = {
            let degraded = Arc::clone(&degraded);
            let stopped = Arc::clone(&stopped);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopped.load(Ordering::SeqCst) {
                        break;
                    }
                    let mut stream = stream.unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                        .unwrap();
                    let mut request = [0; 8192];
                    let _ = stream.read(&mut request);
                    let body = if degraded.load(Ordering::SeqCst) {
                        "<html><body>Fixture</body></html>"
                    } else {
                        concat!(
                            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
                            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                            "<title>SiteCMD CLI fixture</title>",
                            "<meta name=\"description\" content=\"Local fixture for CLI scans.\">",
                            "</head><body><main><h1>Fixture</h1></main></body></html>"
                        )
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            })
        };
        Self {
            url: format!("http://{address}"),
            address,
            degraded,
            stopped,
            worker: Some(worker),
        }
    }

    pub fn degrade(&self) {
        self.degraded.store(true, Ordering::SeqCst);
    }
}

impl Drop for LocalSite {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}
