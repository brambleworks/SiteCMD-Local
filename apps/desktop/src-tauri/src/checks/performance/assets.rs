//! Asset-sampler shell: the desktop's page-subresource policy and fetch
//! concurrency over the engine's requests, sent through the raw probe seam.

use std::future::Future;

use crate::checks::{probe_raw, AsyncCheck, CheckContext, CheckResult, ScanCategory};
use futures_util::{stream, StreamExt};
use sitecmd_engine::checks::performance::assets;
use sitecmd_engine::checks::performance::assets::MeasuredAsset;

pub struct AssetSamplerCheck;

#[async_trait::async_trait]
impl AsyncCheck for AssetSamplerCheck {
    fn id(&self) -> &str {
        "performance.asset_weight"
    }
    fn emitted_ids(&self) -> Vec<String> {
        vec![
            "performance.asset_weight".to_string(),
            "performance.asset_caching".to_string(),
            "performance.broken_images".to_string(),
            "performance.images.heavy".to_string(),
        ]
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Performance
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let policy = ctx.subordinate_policy();
        let collection = assets::collect_assets(
            &ctx.body,
            ctx.body_lower(),
            &ctx.url,
            |target| {
                crate::network_policy::validate_page_subresource_target(target, policy).is_ok()
            },
            assets::ASSET_SAMPLE_LIMIT,
        );
        let strict_local = ctx.is_strict_localhost;
        let measured = collect_measurements(
            collection
                .sampled
                .clone()
                .into_iter()
                .map(move |asset| measure_asset(strict_local, asset)),
        )
        .await;
        assets::evaluate_asset_sample(ctx.body.len() as u64, &collection, &measured)
    }
}

async fn measure_asset(is_strict_local: bool, asset: assets::CollectedAsset) -> MeasuredAsset {
    let (outcome, measure) = probe_raw(is_strict_local, assets::asset_request(&asset.url)).await;
    assets::measured_asset(&asset, &outcome, measure)
}

async fn collect_measurements<F>(fetches: impl IntoIterator<Item = F>) -> Vec<MeasuredAsset>
where
    F: Future<Output = MeasuredAsset>,
{
    // Owning each future ties running and queued requests to the check lifetime.
    let mut measured: Vec<_> = stream::iter(fetches.into_iter().enumerate())
        .map(|(index, fetch)| async move { (index, fetch.await) })
        .buffer_unordered(crate::constants::ASSET_FETCH_CONCURRENCY)
        .collect()
        .await;
    measured.sort_unstable_by_key(|(index, _)| *index);
    measured.into_iter().map(|(_, asset)| asset).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CheckStatus;

    #[test]
    fn dropping_the_sampler_cancels_running_fetches_without_starting_queued_assets() {
        use std::cell::Cell;
        use std::task::{Context, Poll};

        struct RunningFetch<'a>(&'a Cell<usize>);

        impl Drop for RunningFetch<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }

        let started = Cell::new(0);
        let running = Cell::new(0);
        let fetches = (0..assets::ASSET_SAMPLE_LIMIT).map(|_| async {
            started.set(started.get() + 1);
            running.set(running.get() + 1);
            let _running = RunningFetch(&running);
            std::future::pending::<MeasuredAsset>().await
        });
        let mut sampler = Box::pin(collect_measurements(fetches));
        let mut context = Context::from_waker(futures_util::task::noop_waker_ref());

        assert!(matches!(sampler.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(started.get(), crate::constants::ASSET_FETCH_CONCURRENCY);
        assert_eq!(running.get(), crate::constants::ASSET_FETCH_CONCURRENCY);

        drop(sampler);

        assert_eq!(running.get(), 0, "in-flight fetch futures must be dropped");
        assert_eq!(
            started.get(),
            crate::constants::ASSET_FETCH_CONCURRENCY,
            "queued assets must never start after the parent is dropped"
        );
    }

    #[test]
    fn sampler_refills_when_later_fetches_finish_and_preserves_sample_order() {
        use std::cell::Cell;
        use std::task::{Context, Poll};

        let measured_asset = |index| {
            MeasuredAsset::unfetched(&assets::CollectedAsset {
                url: url::Url::parse(&format!("https://example.com/{index}.png"))
                    .expect("asset URL"),
                kind: assets::AssetKind::Image,
                has_srcset: false,
                group: 0,
            })
        };
        let (mut senders, receivers): (Vec<_>, Vec<_>) = (0..assets::ASSET_SAMPLE_LIMIT)
            .map(|_| {
                let (sender, receiver) = tokio::sync::oneshot::channel();
                (Some(sender), receiver)
            })
            .unzip();
        let started = Cell::new(0);
        let fetches = receivers.into_iter().map(|receiver| async {
            started.set(started.get() + 1);
            receiver.await.expect("measurement")
        });
        let mut sampler = Box::pin(collect_measurements(fetches));
        let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(matches!(sampler.as_mut().poll(&mut context), Poll::Pending));

        for (index, sender) in senders
            .iter_mut()
            .enumerate()
            .take(crate::constants::ASSET_FETCH_CONCURRENCY)
            .skip(1)
        {
            sender
                .take()
                .expect("sender")
                .send(measured_asset(index))
                .expect("finish later request");
        }
        assert!(matches!(sampler.as_mut().poll(&mut context), Poll::Pending));
        assert!(
            started.get() > crate::constants::ASSET_FETCH_CONCURRENCY,
            "a slow first asset must not stall the queue"
        );

        for (index, sender) in senders.into_iter().enumerate() {
            if let Some(sender) = sender {
                sender
                    .send(measured_asset(index))
                    .expect("finish remaining request");
            }
        }
        let Poll::Ready(measured) = sampler.as_mut().poll(&mut context) else {
            panic!("all asset requests completed");
        };
        let expected: Vec<_> = (0..assets::ASSET_SAMPLE_LIMIT)
            .map(|index| measured_asset(index).url)
            .collect();
        assert_eq!(
            measured
                .into_iter()
                .map(|asset| asset.url)
                .collect::<Vec<_>>(),
            expected
        );
    }

    /// The one adapter path with no network: a page that references no
    /// fetchable assets. Pins the wiring of AssetSamplerCheck end to end -
    /// the engine's four rows come back under their registered ids.
    #[tokio::test]
    async fn a_page_without_assets_emits_the_four_clean_rows() {
        let ctx = crate::checks::CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse("https://example.com/").expect("static test url"),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: "<html><body><p>No assets here.</p></body></html>".into(),
                is_localhost: false,
                is_strict_localhost: false,
                http_version: Some("HTTP/2.0".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(false).clone(),
            probe_cache: Default::default(),
        };
        let results = AssetSamplerCheck.run(&ctx).await;
        let ids: Vec<&str> = results.iter().map(|row| row.check_id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "performance.asset_weight",
                "performance.broken_images",
                "performance.images.heavy",
                "performance.asset_caching",
            ]
        );
        assert!(results.iter().all(|row| row.status == CheckStatus::Pass));
    }

    #[test]
    fn the_policy_gate_refuses_internal_targets_from_untrusted_markup() {
        let html = r#"
            <img src="http://169.254.169.254/latest/meta-data/x.png" alt="a">
            <img src="http://10.0.0.5/internal.png" alt="b">
            <script src="http://127.0.0.1:11434/api.js"></script>
            <link rel="stylesheet" href="http://localhost:5173/app.css">
            <img src="https://cdn.example.com/ok.png" alt="c">
        "#;
        let lower = html.to_ascii_lowercase();
        let page_url = url::Url::parse("https://example.com/").expect("page url");
        let collection = assets::collect_assets(
            html,
            &lower,
            &page_url,
            |target| {
                crate::network_policy::validate_page_subresource_target(
                    target,
                    crate::network_policy::UrlPolicy::Redirect {
                        allow_local_dev: false,
                    },
                )
                .is_ok()
            },
            30,
        );
        assert_eq!(collection.sampled.len(), 1);
        assert_eq!(
            collection.sampled[0].url.as_str(),
            "https://cdn.example.com/ok.png"
        );
        assert_eq!(collection.skipped_unsupported, 4);
    }

    #[test]
    fn loopback_assets_are_allowed_only_for_strict_localhost_scans() {
        let html = r#"<img src="http://127.0.0.1:5173/hero.png" alt="a">"#;
        let lower = html.to_ascii_lowercase();
        let collect = |page: &str, allow_local_dev: bool| {
            let policy = crate::network_policy::UrlPolicy::Redirect { allow_local_dev };
            let page_url = url::Url::parse(page).expect("page url");
            assets::collect_assets(
                html,
                &lower,
                &page_url,
                |target| {
                    crate::network_policy::validate_page_subresource_target(target, policy).is_ok()
                },
                30,
            )
        };
        let local = collect("http://127.0.0.1:5173/", true);
        assert_eq!(
            local.sampled.len(),
            1,
            "local dev scans fetch their own assets"
        );
        let public = collect("https://example.com/", false);
        assert!(public.sampled.is_empty());
        assert_eq!(public.skipped_unsupported, 1);
    }

    /// Serve one asset answer and hand back the request head it read, so a
    /// case can check what the sampler asked for as well as what it graded.
    async fn asset_origin(answer: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind asset origin");
        let addr = listener.local_addr().expect("asset origin address");
        let served = tokio::spawn(async move {
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
            stream
                .write_all(answer.as_bytes())
                .await
                .expect("write asset answer");
            stream.shutdown().await.expect("close asset answer");
            String::from_utf8_lossy(&request).to_ascii_lowercase()
        });
        (format!("http://{addr}"), served)
    }

    fn asset_context(origin: &str, body: String) -> CheckContext {
        CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse(&format!("{origin}/")).expect("origin url"),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body,
                is_localhost: true,
                is_strict_localhost: true,
                http_version: Some("HTTP/1.1".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(true).clone(),
            probe_cache: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_sampled_asset_is_requested_and_measured_through_the_raw_seam() {
        // The request must carry the one-byte range and the identity coding,
        // and a read through the decoding seam would be refused unsent,
        // leaving the image unsized.
        let (origin, served) = asset_origin(
            "HTTP/1.1 206 Partial Content\r\nContent-Type: image/jpeg\r\nContent-Range: bytes 0-0/900000\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
        )
        .await;
        let ctx = asset_context(
            &origin,
            format!("<html><body><img src=\"{origin}/hero.jpg\" alt=\"h\"></body></html>"),
        );
        let results = AssetSamplerCheck.run(&ctx).await;
        let heavy = results
            .iter()
            .find(|row| row.check_id == "performance.images.heavy")
            .expect("heavy row");
        // Checked before the head is awaited: a request refused unsent would
        // leave the origin waiting for a connection that never comes.
        assert_eq!(heavy.status, CheckStatus::Warn);
        let head = served.await.expect("asset origin");
        assert!(head.contains("\r\nrange: bytes=0-0\r\n"), "{head}");
        assert!(head.contains("\r\naccept-encoding: identity\r\n"), "{head}");
    }

    #[tokio::test]
    async fn a_sampled_unsized_stylesheet_keeps_its_counted_bytes() {
        // Dropping the raw seam's measure leaves the stylesheet's bytes unmeasured.
        let (origin, served) = asset_origin(
            "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await;
        let ctx = asset_context(
            &origin,
            format!("<link rel=\"stylesheet\" href=\"{origin}/app.css\">"),
        );
        let results = AssetSamplerCheck.run(&ctx).await;
        let weight = results
            .iter()
            .find(|row| row.check_id == "performance.asset_weight")
            .expect("weight row");
        assert_eq!(
            weight.raw_data.as_ref().expect("weight data")["measured_asset_bytes"],
            5
        );
        served.await.expect("asset origin");
    }

    #[tokio::test]
    async fn an_asset_keeps_every_cache_control_line() {
        // Reading only the first cache line misses the no-store directive on the second.
        let (origin, served) = asset_origin(
            "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nCache-Control: max-age=60\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let asset = assets::CollectedAsset {
            url: url::Url::parse(&format!("{origin}/app.css")).expect("asset url"),
            kind: assets::AssetKind::Style,
            has_srcset: false,
            group: 0,
        };
        let (outcome, measure) = probe_raw(true, assets::asset_request(&asset.url)).await;
        served.await.expect("asset origin");
        assert_eq!(
            assets::measured_asset(&asset, &outcome, measure)
                .cache_control
                .as_deref(),
            Some("max-age=60, no-store")
        );
    }
}
