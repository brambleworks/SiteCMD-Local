//! Desktop transfer-size measurement for sampled assets.
//!
//! Prefer `Content-Range`, then `Content-Length`, then a bounded body count.

use crate::http_client::{read_body_limited, BodyReadError};
use sitecmd_engine::checks::performance::assets::{
    parse_content_range_total, CollectedAsset, MeasuredAsset,
};

/// Fetch one asset and measure its transfer size. Never panics; failures come
/// back as `status_code: 0` / `bytes: None` so the caller can report honestly.
pub async fn fetch_asset(client: reqwest::Client, asset: CollectedAsset) -> MeasuredAsset {
    let mut measured = MeasuredAsset::unfetched(&asset);
    let response = match client
        .get(asset.url.clone())
        .header(reqwest::header::RANGE, "bytes=0-0")
        .timeout(crate::constants::CHECK_PROBE_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return measured,
    };

    measured.status_code = response.status().as_u16();
    measured.content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase()
        });
    measured.cache_control =
        sitecmd_engine::header_lines::field_value(response.headers(), "cache-control");

    if measured.status_code >= 400 {
        return measured;
    }

    // 206 Partial Content: Content-Range names the full size for one byte
    // of transfer.
    if measured.status_code == 206 {
        measured.bytes = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_content_range_total);
        return measured;
    }

    // The server ignored the Range request; Content-Length is the next best
    // signal.
    if let Some(length) = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        measured.bytes = Some(length);
        return measured;
    }

    // No size headers at all: count the bytes ourselves, bounded so a huge or
    // dishonest response cannot blow the probe budget.
    match read_body_limited(
        response,
        crate::constants::MAX_PROBE_BODY_SIZE,
        crate::constants::CHECK_PROBE_TIMEOUT,
    )
    .await
    {
        Ok(body) => measured.bytes = Some(body.len() as u64),
        Err(BodyReadError::TooLarge { received_bytes, .. }) => {
            measured.bytes = Some(received_bytes);
            measured.measured_floor = true;
        }
        Err(_) => {}
    }
    measured
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serve an asset with supplied response fields that ignores the Range request.
    async fn asset_server(body: Vec<u8>, extra_headers: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind asset server");
        let addr = listener.local_addr().expect("asset server address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept asset request");
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("read request head");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(head.as_bytes())
                .await
                .expect("write response head");
            stream.write_all(&body).await.expect("write gzip body");
            stream.shutdown().await.expect("close asset response");
        });
        format!("http://{addr}/app.css")
    }

    #[tokio::test]
    async fn a_compressed_asset_is_measured_at_its_wire_size() {
        use std::io::Write;
        let payload = "body { color: rebeccapurple; }\n".repeat(400);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload.as_bytes()).expect("gzip payload");
        let compressed = encoder.finish().expect("finish gzip stream");
        assert!(
            compressed.len() < payload.len() / 4,
            "fixture must compress enough for the two sizes to be distinguishable"
        );

        let url = asset_server(compressed.clone(), "Content-Encoding: gzip\r\n").await;
        let asset = CollectedAsset {
            url: url::Url::parse(&url).expect("asset url"),
            kind: sitecmd_engine::checks::performance::assets::AssetKind::Style,
            has_srcset: false,
            group: 0,
        };
        let measured = fetch_asset(
            crate::http_client::no_decompress_client(true).clone(),
            asset,
        )
        .await;

        assert_eq!(measured.status_code, 200);
        assert_eq!(
            measured.bytes,
            Some(compressed.len() as u64),
            "the sampler must report the bytes the server sent, not the {} decoded bytes",
            payload.len()
        );
    }

    #[tokio::test]
    async fn an_asset_keeps_every_cache_control_line() {
        // Reading only the first cache line misses the no-store directive on the second.
        let url = asset_server(
            Vec::new(),
            "Cache-Control: max-age=60\r\nCache-Control: no-store\r\n",
        )
        .await;
        let asset = CollectedAsset {
            url: url::Url::parse(&url).expect("asset url"),
            kind: sitecmd_engine::checks::performance::assets::AssetKind::Style,
            has_srcset: false,
            group: 0,
        };
        let measured = fetch_asset(
            crate::http_client::no_decompress_client(true).clone(),
            asset,
        )
        .await;
        assert_eq!(
            measured.cache_control.as_deref(),
            Some("max-age=60, no-store")
        );
    }
}
