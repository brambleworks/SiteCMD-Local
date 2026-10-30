//! Where a site is served from, and whose nameservers answer for its domain.
//!
//! Only an answer that names the platform counts: the site's own subdomain of
//! a platform, a header only that platform sends, markup only it writes, or a
//! DNS answer that points at it. A site behind Cloudflare's proxy answers with
//! Cloudflare's headers whatever runs behind it, so those name the CDN and
//! never the host. An address is never read: platforms move their ranges, and
//! one address fronts many products.

use super::{labels, DetectedStack};
use crate::dns::{DnsOutcome, ResolverFacts};

/// A platform's own domain, under which it serves the sites it hosts. A host
/// at one of these names, rather than under it, is the platform's own site.
const PLATFORM_SUBDOMAINS: &[(&str, &str)] = &[
    ("pages.dev", labels::CLOUDFLARE_PAGES),
    ("workers.dev", labels::CLOUDFLARE_WORKERS),
    ("vercel.app", labels::VERCEL),
    ("netlify.app", labels::NETLIFY),
    ("github.io", labels::GITHUB_PAGES),
    ("myshopify.com", labels::SHOPIFY),
    ("webflow.io", labels::WEBFLOW),
    ("wixsite.com", labels::WIX),
    ("squarespace.com", labels::SQUARESPACE),
    ("framer.website", labels::FRAMER),
    ("wordpress.com", labels::WORDPRESS_COM),
];

/// A DNS name as the comparisons below read it: lowercase, without the root's
/// trailing dot.
fn dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `name` is a name under `domain`, compared at a label boundary, so
/// `evilpages.dev` is not under `pages.dev`.
fn under(name: &str, domain: &str) -> bool {
    name.strip_suffix(domain)
        .is_some_and(|rest| rest.ends_with('.'))
}

fn platform_subdomain(host: &str) -> Option<&'static str> {
    let host = dns_name(host);
    PLATFORM_SUBDOMAINS
        .iter()
        .find(|(domain, _)| under(&host, domain))
        .map(|(_, label)| *label)
}

/// Where a custom domain's CNAME points when one of these platforms serves it,
/// each the target that platform's own custom-domain guide documents.
const CNAME_TARGETS: &[(&str, &str)] = &[
    ("pages.dev", labels::CLOUDFLARE_PAGES),
    ("netlify.app", labels::NETLIFY),
    ("github.io", labels::GITHUB_PAGES),
    ("vercel-dns.com", labels::VERCEL),
    ("myshopify.com", labels::SHOPIFY),
    ("squarespace.com", labels::SQUARESPACE),
    ("webflow.com", labels::WEBFLOW),
    ("wixdns.net", labels::WIX),
    ("framer.app", labels::FRAMER),
    ("wordpress.com", labels::WORDPRESS_COM),
];

/// Vercel's per-project targets, `<id>.vercel-dns-<n>.com`, beside its shared
/// `cname.vercel-dns.com`.
static VERCEL_PROJECT_TARGET: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?:\A|\.)vercel-dns-[0-9]{1,4}\.com\z").expect("static vercel target regex")
    // allow-expect: compile-time literal regex
});

/// The nameservers' own domains, which name their DNS providers.
const NAMESERVER_DOMAINS: &[(&str, &str)] = &[
    ("ns.cloudflare.com", labels::CLOUDFLARE),
    ("vercel-dns.com", labels::VERCEL),
];

/// The names an answer that held records gave; none for one that failed or
/// held nothing.
fn answered(outcome: Option<&DnsOutcome<Vec<String>>>) -> impl Iterator<Item = String> + '_ {
    let names: &[String] = match outcome {
        Some(DnsOutcome::Records(names)) => names,
        _ => &[],
    };
    names.iter().map(|name| dns_name(name))
}

fn cname_platform(outcome: Option<&DnsOutcome<Vec<String>>>) -> Option<&'static str> {
    // Later hops can name shared infrastructure rather than the site's host.
    let target = answered(outcome).next()?;
    if VERCEL_PROJECT_TARGET.is_match(&target) {
        return Some(labels::VERCEL);
    }
    CNAME_TARGETS
        .iter()
        .find(|(domain, _)| under(&target, domain))
        .map(|(_, label)| *label)
}

fn nameserver_provider(outcome: Option<&DnsOutcome<Vec<String>>>) -> Option<&'static str> {
    let provider = |server: &str| {
        NAMESERVER_DOMAINS
            .iter()
            .find(|(domain, _)| under(server, domain))
            .map(|(_, label)| *label)
    };
    let mut servers = answered(outcome);
    let first = provider(&servers.next()?)?;
    servers
        .all(|server| provider(&server) == Some(first))
        .then_some(first)
}

/// The CNAME that names the platform serving `host`: its own, or for a site at
/// its apex the `www` name's.
fn dns_platform(host: &str, facts: &ResolverFacts) -> Option<&'static str> {
    cname_platform(facts.host_cname.as_ref()).or_else(|| {
        if dns_name(host) == dns_name(&facts.domain) {
            cname_platform(Some(&facts.www_cname))
        } else {
            None
        }
    })
}

/// A header the platform sends on every response it serves and no proxy in
/// front of it adds. GitHub's `Server` and request id are sent by github.com
/// itself too, so the pair counts only beside the Fastly request id Pages
/// answers through.
fn platform_headers(headers: &http::HeaderMap) -> Option<&'static str> {
    if headers.contains_key("x-vercel-id") {
        return Some(labels::VERCEL);
    }
    if headers.contains_key("x-nf-request-id") || headers.contains_key("x-netlify-request-id") {
        return Some(labels::NETLIFY);
    }
    let github_server = headers
        .get("server")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|server| server.eq_ignore_ascii_case("github.com"));
    if github_server
        && headers.contains_key("x-github-request-id")
        && headers.contains_key("x-fastly-request-id")
    {
        return Some(labels::GITHUB_PAGES);
    }
    None
}

/// Framer's own markup: the generator tag it writes on every published page,
/// or the host it serves a page's own bundle from. A link to framer.com is not
/// either.
fn platform_markup(body: &str, lower: &str) -> Option<&'static str> {
    let generator = super::generator_value(body).is_some_and(|value| {
        value
            .get(.."framer".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("framer"))
    });
    (generator || lower.contains("framerusercontent.com/sites/")).then_some(labels::FRAMER)
}

/// Name where the site is served from onto the stack `detect_stack` read from
/// the same page. `host` is the page's own host, and `resolver` the answers
/// the hosted runner gathered for the site's domain, absent where none were.
/// `body` is the page's markup and `lower` its ASCII-lowercased copy.
/// The strongest answer wins: the site's own subdomain, then a CNAME, then a
/// header, then markup. The domain's nameservers name its DNS provider.
pub fn detect_hosting(
    stack: &mut DetectedStack,
    host: &str,
    headers: &http::HeaderMap,
    body: &str,
    lower: &str,
    resolver: Option<&ResolverFacts>,
) {
    if let Some(label) = platform_subdomain(host)
        .or_else(|| resolver.and_then(|facts| dns_platform(host, facts)))
        .or_else(|| platform_headers(headers))
        .or_else(|| platform_markup(body, lower))
    {
        stack.hosting = Some(label.into());
    }
    if let Some(label) = resolver.and_then(|facts| nameserver_provider(facts.ns.as_ref())) {
        stack.dns_provider = Some(label.into());
    }
}

#[cfg(test)]
#[path = "stack_hosting_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stack_hosting_dns_tests.rs"]
mod dns_tests;
