//! Desktop scan-check traits and shared types.
//! `Check` reads fetched data; `AsyncCheck` performs network probes.

pub mod accessibility;
pub mod compliance;
pub mod config;
pub use sitecmd_engine::checks::html_attrs;
pub mod inventory;
pub mod performance;
pub mod polish;
pub use sitecmd_engine::checks::predeploy;
mod probe_adapter;
mod probe_slots;
pub mod security;
pub(crate) use probe_adapter::{probe, probe_get, probe_raw, probe_with_timeout};
mod probes;
pub use probes::ProbeCache;

// Portable probe vocabulary re-exported for desktop checks.
pub use sitecmd_engine::checks::origin_with_port;
pub use sitecmd_engine::checks::performance::redirects::{
    RedirectHop, RedirectWalk, RedirectWalkTermination,
};
pub use sitecmd_engine::checks::seo::robots::RobotsTxtFetch;
pub use sitecmd_engine::checks::seo::sitemap::{
    SitemapFetch, SitemapProbe, SitemapProbeObservation,
};

pub mod seo;

// Shared scan vocabulary.
pub use sitecmd_engine::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};
// Synchronous check surface.
pub use sitecmd_engine::{Check, PageContext};

/// Portable page data plus desktop runtime services needed by async checks.
/// `Deref` exposes the shared [`PageContext`] interface.
pub struct CheckContext {
    pub page: PageContext,
    pub client: reqwest::Client,
    /// Per-scan memo for origin-scoped probe fetches (robots.txt, sitemap)
    /// shared across async checks. See `ProbeCache`.
    #[doc(hidden)]
    pub probe_cache: ProbeCache,
}

impl CheckContext {
    pub fn new(page: PageContext, client: reqwest::Client) -> Self {
        Self {
            page,
            client,
            probe_cache: Default::default(),
        }
    }

    /// Preserve the caller URL for explicit redirect-chain replay.
    pub(crate) fn with_requested_url(self, requested_url: url::Url) -> Self {
        self.probe_cache
            .requested_url
            .set(requested_url)
            .expect("requested URL is assigned once while building a scan context");
        self
    }

    /// Record the scan target's reach so subordinate fetches inherit it.
    pub(crate) fn with_origin(self, origin: crate::network_policy::LocalOrigin) -> Self {
        self.probe_cache
            .origin
            .set(origin)
            .expect("origin is assigned once while building a scan context");
        self
    }

    /// The policy for a URL this page steers the scan to. A page may name any
    /// URL; it never earns more reach than the target the person asked for.
    /// Without a recorded origin the target's own address answers, which loses
    /// only the case of a hostname that resolves into a private network.
    pub(crate) fn subordinate_policy(&self) -> crate::network_policy::UrlPolicy {
        self.probe_cache
            .origin
            .get()
            .copied()
            .unwrap_or_else(|| crate::network_policy::LocalOrigin::classify(&self.url))
            .subordinate_policy()
    }

    pub(crate) fn requested_url(&self) -> &url::Url {
        self.probe_cache.requested_url.get().unwrap_or(&self.url)
    }

    /// Cache observed TLS facts for verdicts and baseline projection.
    pub(crate) fn record_tls_facts(&self, facts: &sitecmd_engine::checks::security::tls::TlsFacts) {
        if let Ok(mut slot) = self.probe_cache.tls_facts.lock() {
            *slot = Some(facts.clone());
        }
    }

    /// Return any certificate facts observed by this scan.
    pub(crate) fn observed_tls_facts(
        &self,
    ) -> Option<sitecmd_engine::checks::security::tls::TlsFacts> {
        self.probe_cache
            .tls_facts
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }
}

impl std::ops::Deref for CheckContext {
    type Target = PageContext;
    fn deref(&self) -> &PageContext {
        &self.page
    }
}

impl std::ops::DerefMut for CheckContext {
    fn deref_mut(&mut self) -> &mut PageContext {
        &mut self.page
    }
}

/// Trait for checks that need to make additional HTTP requests or async operations
#[async_trait::async_trait]
pub trait AsyncCheck: Send + Sync {
    fn id(&self) -> &str;
    fn category(&self) -> ScanCategory;
    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult>;
    fn skip_in_predeploy(&self) -> bool {
        false
    }
    /// Whether multi-page scans may run this check once per origin.
    fn origin_scoped(&self) -> bool {
        false
    }
    /// Every check id this check can emit. Most checks emit exactly `id()`;
    /// a runner shell that fans out into sub-ids overrides this so the
    /// inventory sees the sub-ids too.
    fn emitted_ids(&self) -> Vec<String> {
        vec![self.id().to_string()]
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
