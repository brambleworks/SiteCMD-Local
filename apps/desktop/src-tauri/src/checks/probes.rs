//! Origin-scoped, per-scan probe transport. Classification, the sitemap candidate
//! walk and sitemap grammar remain in the portable engine.

use sitecmd_engine::checks::seo::robots::{robots_fetch_from_probe, robots_txt_url};
use sitecmd_engine::checks::seo::sitemap_walk::{sitemap_candidates, walk_sitemap_candidates};
use sitecmd_engine::evaluation::probe_key;
use sitecmd_engine::probe::{ProbeOutcome, ProbeRequest};

use super::{performance, probe, CheckContext, RedirectWalk, RobotsTxtFetch, SitemapProbe};

/// Per-scan memo for origin-scoped probe fetches and the page's link resolution,
/// shared across async checks.
/// Checks racing on the same entry await one in-flight request instead of each
/// re-fetching the same origin resource.
#[derive(Default)]
pub struct ProbeCache {
    pub(in crate::checks) requested_url: std::sync::OnceLock<url::Url>,
    /// How far outside the public internet the scan target sits, resolved once
    /// per scan. Unset in a context built without one, where the target's own
    /// address answers instead.
    pub(in crate::checks) origin: std::sync::OnceLock<crate::network_policy::LocalOrigin>,
    pub(in crate::checks) robots_txt: tokio::sync::OnceCell<RobotsTxtFetch>,
    pub(in crate::checks) sitemap: tokio::sync::OnceCell<SitemapProbe>,
    pub(in crate::checks) redirect_chain: tokio::sync::OnceCell<RedirectWalk>,
    /// The page's anchor destinations under the desktop's subresource policy,
    /// resolved once for both broken-link checks.
    pub(in crate::checks) link_targets:
        std::sync::OnceLock<sitecmd_engine::checks::seo::links::LinkTargets>,
    /// The certificate facts the TLS handshake produced. Memoized like the
    /// other origin probes, and for the same reason: it is one connection per
    /// scan, and what it learned outlives the verdicts it was opened for.
    pub(in crate::checks) tls_facts:
        std::sync::Mutex<Option<sitecmd_engine::checks::security::tls::TlsFacts>>,
}

impl CheckContext {
    /// Follow the scanned URL's redirect chain once per scan and share the
    /// observed hops across checks (`performance.redirect_chain` counts
    /// them, `seo.temporary_redirect` grades their status codes).
    pub async fn redirect_chain(&self) -> &RedirectWalk {
        self.probe_cache
            .redirect_chain
            .get_or_init(|| performance::redirects::walk_redirect_chain(self))
            .await
    }

    /// Fetch `/robots.txt` once per scan through the probe seam and share the
    /// engine-classified outcome across checks.
    pub async fn robots_txt(&self) -> &RobotsTxtFetch {
        self.probe_cache
            .robots_txt
            .get_or_init(|| async {
                let request = ProbeRequest::get(robots_txt_url(&self.url));
                robots_fetch_from_probe(probe(&self.client, request).await)
            })
            .await
    }

    /// Probe the sitemap candidate URLs once per scan. The memo preserves a
    /// conclusive missing result separately from access/network failures.
    /// The desktop sends each request the walk names through the probe seam in order.
    pub async fn sitemap(&self) -> &SitemapProbe {
        self.probe_cache
            .sitemap
            .get_or_init(|| async {
                let origin = super::origin_with_port(&self.url);
                let candidates = sitemap_candidates(&origin, self.robots_txt().await);
                let mut answered: Vec<(String, ProbeOutcome)> = Vec::new();
                loop {
                    let next = match walk_sitemap_candidates(&candidates, |request| {
                        let key = probe_key(request);
                        answered
                            .iter()
                            .find(|(asked, _)| *asked == key)
                            .map(|(_, outcome)| outcome)
                    }) {
                        Ok(found) => return found,
                        Err(next) => next,
                    };
                    let key = probe_key(&next);
                    answered.push((key, probe(&self.client, next).await));
                }
            })
            .await
    }
}

#[cfg(test)]
#[path = "probes_tests.rs"]
mod tests;
