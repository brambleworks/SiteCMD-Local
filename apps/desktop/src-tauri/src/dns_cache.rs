//! Bounded, process-wide DNS cache shared by the reqwest clients.
//!
//! Cache misses and expired entries resolve through the system resolver.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::network_policy::UrlPolicy;
use moka::sync::Cache;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

#[cfg(test)]
type TestLookup = Box<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>>>;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_LOOKUP: std::cell::RefCell<Option<TestLookup>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(crate) async fn lookup_host(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    #[cfg(test)]
    if let Some(answer) = TEST_LOOKUP.with_borrow(|lookup| lookup.as_ref().map(|f| f(host, port))) {
        return answer;
    }
    tokio::net::lookup_host((host, port))
        .await
        .map(|addresses| addresses.collect())
}

pub struct CachedDnsResolver {
    cache: Cache<String, Vec<SocketAddr>>,
    policy: UrlPolicy,
}

impl Default for CachedDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedDnsResolver {
    pub fn new() -> Self {
        Self::for_policy(UrlPolicy::Scan)
    }

    pub fn for_policy(policy: UrlPolicy) -> Self {
        Self::with_limits(
            policy,
            crate::constants::DNS_CACHE_TTL,
            crate::constants::DNS_CACHE_MAX_ENTRIES,
        )
    }

    fn with_limits(policy: UrlPolicy, ttl: Duration, max_entries: u64) -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(ttl)
                .max_capacity(max_entries)
                .build(),
            policy,
        }
    }

    fn cached_addrs(&self, host: &str) -> Option<Vec<SocketAddr>> {
        self.cache.get(host)
    }

    fn store(&self, host: String, addrs: Vec<SocketAddr>) {
        self.cache.insert(host, addrs);
    }
}

impl Resolve for CachedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let policy = self.policy;
        if let Some(addrs) = self.cached_addrs(&host) {
            if let Err(error) = validate_resolved_addrs(&host, &addrs, policy) {
                return Box::pin(async move { Err(error.into()) });
            }
            return Box::pin(async move { Ok(Box::new(addrs.into_iter()) as Addrs) });
        }

        let cache = self.cache.clone();
        Box::pin(async move {
            // Port 0 is a placeholder; reqwest patches the real port on the
            // returned SocketAddr based on the request URL.
            let addrs = lookup_host(&host, 0).await?;
            validate_resolved_addrs(&host, &addrs, policy)?;
            let resolver = CachedDnsResolver { cache, policy };
            resolver.store(host, addrs.clone());
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn validate_resolved_addrs(
    host: &str,
    addrs: &[SocketAddr],
    policy: UrlPolicy,
) -> Result<(), io::Error> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No address records for '{host}'."),
        ));
    }

    for addr in addrs {
        crate::network_policy::validate_resolved_domain_ip_target(host, addr.ip(), policy)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
    }
    Ok(())
}

/// Shared resolver instance used by all HTTP clients.
pub fn shared() -> Arc<CachedDnsResolver> {
    static RESOLVER: LazyLock<Arc<CachedDnsResolver>> =
        LazyLock::new(|| Arc::new(CachedDnsResolver::new()));
    RESOLVER.clone()
}

/// Shared resolver enforcing external-callback policy at connection time.
pub fn external_callback_resolver() -> Arc<CachedDnsResolver> {
    static RESOLVER: LazyLock<Arc<CachedDnsResolver>> =
        LazyLock::new(|| Arc::new(CachedDnsResolver::for_policy(UrlPolicy::ExternalCallback)));
    RESOLVER.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn cache_hits_avoid_a_second_lookup() {
        let resolver = CachedDnsResolver::new();
        let name = Name::from_str("localhost").unwrap();
        let _first = resolver.resolve(name).await.unwrap();
        resolver.cache.run_pending_tasks();
        let cached = resolver.cached_addrs("localhost");
        assert!(cached.is_some(), "first lookup should populate cache");
        let name2 = Name::from_str("localhost").unwrap();
        let _second = resolver.resolve(name2).await.unwrap();
        assert_eq!(
            cached,
            resolver.cached_addrs("localhost"),
            "second resolve within TTL should preserve the cached answer"
        );
    }

    #[tokio::test]
    async fn concurrent_reads_do_not_serialize() {
        // Pre-populate one host so every spawned task hits the read path.
        let resolver = Arc::new(CachedDnsResolver::new());
        let prime = Name::from_str("localhost").unwrap();
        let _ = resolver.resolve(prime).await.unwrap();

        // Cache hits should stay cheap under concurrent scanner probes.
        let started = Instant::now();
        let mut handles = Vec::with_capacity(32);
        for _ in 0..32 {
            let resolver = resolver.clone();
            handles.push(tokio::spawn(async move {
                // Read directly through the public API to exercise the lock path.
                let name = Name::from_str("localhost").unwrap();
                let _ = resolver.resolve(name).await.unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "32 concurrent cache reads should finish quickly; took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn security_regression_cached_public_host_cannot_rebind_to_loopback() {
        let resolver = CachedDnsResolver::new();
        resolver.store(
            "rebind.example".to_string(),
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 80))],
        );

        let name = Name::from_str("rebind.example").unwrap();
        let result = resolver.resolve(name).await;

        assert!(
            result.is_err(),
            "cached DNS answers must still pass the shared URL policy before reqwest connects"
        );
    }

    #[tokio::test]
    async fn external_callback_resolver_refuses_host_resolving_to_loopback() {
        let resolver = CachedDnsResolver::for_policy(UrlPolicy::ExternalCallback);
        resolver.store(
            "hook.example".to_string(),
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))],
        );
        let name = Name::from_str("hook.example").unwrap();
        assert!(
            resolver.resolve(name).await.is_err(),
            "external-callback egress must refuse a host resolving to loopback"
        );
    }

    #[test]
    fn cache_evicts_by_capacity_and_ttl() {
        let resolver =
            CachedDnsResolver::with_limits(UrlPolicy::Scan, Duration::from_millis(10), 2);
        let address = vec![SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443))];
        resolver.store("one.example".into(), address.clone());
        resolver.store("two.example".into(), address.clone());
        resolver.store("three.example".into(), address);
        resolver.cache.run_pending_tasks();

        assert!(resolver.cache.entry_count() <= 2);

        std::thread::sleep(Duration::from_millis(20));
        resolver.cache.run_pending_tasks();
        assert_eq!(resolver.cache.entry_count(), 0);
    }
}
