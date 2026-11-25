//! Tests for the network policy: which addresses each policy may reach,
//! and which spellings of a private address must never slip past it.

use super::{
    validate_ip_target, validate_redirect_target_nonblocking, validate_resolved_domain_ip_target,
    validate_url, LocalOrigin, UrlPolicy,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn local_origin_matches_the_predicates_it_replaces() {
    use sitecmd_protocol::network_class::{is_localhost, is_strict_localhost};
    for url in [
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "http://0.0.0.0:5173",
        "http://myapp.local",
        "http://myapp.localhost:3000",
        "http://[::1]:5173",
        "https://localhost.run",
        "https://example.com",
        "https://127.0.0.1.example.com",
    ] {
        let parsed = url::Url::parse(url).expect(url);
        let origin = LocalOrigin::classify(&parsed);
        assert_eq!(
            origin != LocalOrigin::Public,
            is_localhost(&parsed),
            "{url}"
        );
        assert_eq!(
            origin == LocalOrigin::Loopback,
            is_strict_localhost(&parsed),
            "{url}"
        );
        assert_eq!(
            origin.allows_local_dev(),
            LocalOrigin::classify(&parsed).allows_local_dev(),
            "{url}"
        );
    }
    // The one deliberate widening: every 127/8 literal is loopback.
    let wide = url::Url::parse("http://127.0.0.2:5173").unwrap();
    assert!(LocalOrigin::classify(&wide) == LocalOrigin::Loopback);
    assert!(!is_strict_localhost(&wide));

    // A second deliberate widening: a trailing-dot FQDN form of
    // localhost normalizes the same way `is_local_dev_domain` (and
    // therefore `LocalOrigin::classify`) already normalizes it
    // elsewhere in this file, so `LocalOrigin` treats "localhost." as
    // loopback even though the two protocol predicates compare
    // `host_str()` without trimming the trailing dot.
    let trailing_dot = url::Url::parse("http://localhost./").unwrap();
    let trailing_dot_origin = LocalOrigin::classify(&trailing_dot);
    assert!(trailing_dot_origin == LocalOrigin::Loopback);
    assert!(!is_strict_localhost(&trailing_dot));
    assert!(trailing_dot_origin != LocalOrigin::Public);
    assert!(!is_localhost(&trailing_dot));
    assert!(trailing_dot_origin.allows_local_dev());
    assert!(LocalOrigin::classify(&trailing_dot).allows_local_dev());
}

#[tokio::test]
async fn scan_validation_allows_explicit_local_dev_loopback() {
    assert!(validate_url("http://localhost:5173", UrlPolicy::Scan)
        .await
        .is_ok());
    assert!(validate_url("http://127.0.0.1:5173", UrlPolicy::Scan)
        .await
        .is_ok());
    assert!(validate_url("http://[::1]:5173", UrlPolicy::Scan)
        .await
        .is_ok());
}

#[test]
fn only_explicit_local_scan_origins_inherit_the_loopback_exception() {
    for url in [
        "http://localhost:5173",
        "http://app.localhost:5173",
        "http://127.0.0.2:5173",
        "http://[::1]:5173",
    ] {
        let parsed = url::Url::parse(url).expect("parse explicit local URL");
        assert!(
            LocalOrigin::classify(&parsed).allows_local_dev(),
            "{url} should inherit the local-dev exception"
        );
    }

    for url in [
        "https://example.com",
        "https://localhost.run",
        "https://127.0.0.1.example.com",
    ] {
        let parsed = url::Url::parse(url).expect("parse public URL");
        assert!(
            !LocalOrigin::classify(&parsed).allows_local_dev(),
            "{url} must not inherit the local-dev exception"
        );
    }
}

#[tokio::test]
async fn scan_validation_rejects_private_non_loopback_targets() {
    assert!(validate_url("http://192.168.1.10", UrlPolicy::Scan)
        .await
        .is_err());
    assert!(validate_url("http://10.0.0.5", UrlPolicy::Scan)
        .await
        .is_err());
    assert!(validate_url("http://169.254.169.254", UrlPolicy::Scan)
        .await
        .is_err());
}

#[tokio::test]
async fn external_callback_validation_rejects_local_targets() {
    assert!(
        validate_url("http://localhost:5173", UrlPolicy::ExternalCallback)
            .await
            .is_err()
    );
    assert!(
        validate_url("http://127.0.0.1:5173", UrlPolicy::ExternalCallback)
            .await
            .is_err()
    );
    assert!(
        validate_url("http://[::1]:5173", UrlPolicy::ExternalCallback)
            .await
            .is_err()
    );
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn ip_target_rejects_rfc1918_under_external_callback_policy() {
    assert!(validate_ip_target(ipv4(10, 0, 0, 1), UrlPolicy::ExternalCallback).is_err());
    assert!(validate_ip_target(ipv4(172, 16, 0, 1), UrlPolicy::ExternalCallback).is_err());
    assert!(validate_ip_target(ipv4(192, 168, 1, 1), UrlPolicy::ExternalCallback).is_err());
}

#[tokio::test]
async fn a_named_scan_target_may_reach_the_networks_this_machine_is_on() {
    // SiteCMD runs as the person who typed the address, on their machine,
    // with their network. Naming a box they can already reach grants no
    // access they did not have.
    for target in [
        "http://192.168.1.40:8080/",
        "http://10.0.0.5:3000/",
        "http://172.16.4.2/",
        "http://100.100.4.7/",
        "http://[fd00::1]:8080/",
    ] {
        assert!(
            validate_url(target, UrlPolicy::Scan).await.is_err(),
            "{target} is not a subordinate fetch's to reach"
        );
        assert!(
            validate_url(target, UrlPolicy::ExternalCallback)
                .await
                .is_err(),
            "{target} must never be a callback"
        );
        assert!(
            validate_url(target, UrlPolicy::ScanTarget).await.is_ok(),
            "{target} is a target a person can name"
        );
    }
}

#[tokio::test]
async fn no_policy_reaches_link_local_or_the_addresses_that_are_not_hosts() {
    // Cloud metadata answers on link-local, and a scan body is persisted,
    // exported, and can be sent to an AI provider. The rest are not hosts.
    for target in [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.10.9/",
        "http://[fe80::1]/",
        "http://224.0.0.1/",
        "http://255.255.255.255/",
        "http://198.18.0.1/",
        "http://0.1.2.3/",
    ] {
        for policy in [
            UrlPolicy::ScanTarget,
            UrlPolicy::Scan,
            UrlPolicy::ExternalCallback,
        ] {
            assert!(
                validate_url(target, policy).await.is_err(),
                "{target} under {policy:?}"
            );
        }
    }
}

#[test]
fn redirect_policy_preserves_the_target_reach() {
    let public_origin =
        LocalOrigin::classify(&url::Url::parse("https://example.com/").expect("url"));
    assert_eq!(public_origin, LocalOrigin::Public);
    let public = UrlPolicy::Redirect {
        allow_local_dev: false,
    };
    for stolen in [
        "http://192.168.1.40/",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
    ] {
        assert!(
            redirect_nonblocking(stolen, public).is_err(),
            "{stolen} from a public page"
        );
    }

    // A target the person named on their own network keeps its own reach.
    let lan = LocalOrigin::classify(&url::Url::parse("http://192.168.1.40:8080/").expect("url"));
    assert_eq!(lan, LocalOrigin::PrivateNetwork);
    assert!(redirect_nonblocking("http://192.168.1.41/app.css", UrlPolicy::ScanTarget).is_ok());
    assert!(redirect_nonblocking("http://169.254.169.254/", UrlPolicy::ScanTarget).is_err());
}

#[test]
fn a_name_earns_private_reach_only_when_every_answer_is_private() {
    let resolved = |answers: &[&str]| {
        LocalOrigin::from_resolved_addresses(
            LocalOrigin::Public,
            answers.iter().map(|ip| ip.parse::<IpAddr>().expect("ip")),
        )
    };
    assert_eq!(resolved(&["192.168.1.40"]), LocalOrigin::PrivateNetwork);
    assert_eq!(
        resolved(&["10.0.0.5", "fd00::5"]),
        LocalOrigin::PrivateNetwork
    );
    assert_eq!(resolved(&["100.64.0.9"]), LocalOrigin::PrivateNetwork);

    // A public answer beside a private one is a public site whose owner chose
    // the private record; its pages must not gain the LAN.
    assert_eq!(
        resolved(&["93.184.216.34", "10.0.0.5"]),
        LocalOrigin::Public
    );
    assert_eq!(
        resolved(&["10.0.0.5", "93.184.216.34"]),
        LocalOrigin::Public
    );
    assert_eq!(resolved(&["10.0.0.5", "127.0.0.1"]), LocalOrigin::Public);
    assert_eq!(resolved(&["169.254.169.254"]), LocalOrigin::Public);
    assert_eq!(resolved(&[]), LocalOrigin::Public);
}

#[test]
fn ip_target_rejects_link_local_and_metadata_addresses() {
    // 169.254.169.254 is the cloud metadata service that DNS rebinding
    // attacks classically target.
    assert!(validate_ip_target(ipv4(169, 254, 169, 254), UrlPolicy::Scan).is_err());
    assert!(validate_ip_target(ipv4(169, 254, 0, 1), UrlPolicy::ExternalCallback).is_err());
}

#[test]
fn ip_target_rejects_cgnat_and_this_network_ranges() {
    // RFC 6598 carrier-grade NAT (100.64/10) and RFC 791 "this network"
    // (0.0.0.0/8) are internal/non-routable and must be refused as targets.
    assert!(validate_ip_target(ipv4(100, 64, 0, 1), UrlPolicy::Scan).is_err());
    assert!(validate_ip_target(ipv4(100, 127, 255, 255), UrlPolicy::ExternalCallback).is_err());
    assert!(validate_ip_target(ipv4(0, 1, 2, 3), UrlPolicy::Scan).is_err());
    // Public addresses adjacent to the CGNAT block stay allowed.
    assert!(validate_ip_target(ipv4(100, 63, 0, 1), UrlPolicy::ExternalCallback).is_ok());
    assert!(validate_ip_target(ipv4(100, 128, 0, 1), UrlPolicy::ExternalCallback).is_ok());
}

#[test]
fn ip_target_rejects_private_addresses_even_under_scan_policy() {
    assert!(validate_ip_target(ipv4(10, 0, 0, 5), UrlPolicy::Scan).is_err());
    assert!(validate_ip_target(ipv4(192, 168, 1, 10), UrlPolicy::Scan).is_err());
}

#[test]
fn ip_target_rejects_ipv6_unique_local_and_link_local() {
    // fc00::/7 (unique local) and fe80::/10 (link local) plus loopback::1.
    assert!(validate_ip_target(
        IpAddr::V6("fc00::1".parse::<Ipv6Addr>().unwrap()),
        UrlPolicy::ExternalCallback
    )
    .is_err());
    assert!(validate_ip_target(
        IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        UrlPolicy::ExternalCallback
    )
    .is_err());
    assert!(
        validate_ip_target(IpAddr::V6(Ipv6Addr::LOCALHOST), UrlPolicy::ExternalCallback).is_err()
    );
}

// fec0::/10 sits outside the fe80::/10 link-local mask, so it needed its
// own branch; fe00::/9 and the public 2000::/3 space must stay allowed.
#[test]
fn ip_target_rejects_ipv6_site_local_addresses() {
    for site_local in ["fec0::1", "feff:ffff::1", "fed0::8888"] {
        assert!(
            validate_ip_target(
                IpAddr::V6(site_local.parse::<Ipv6Addr>().unwrap()),
                UrlPolicy::ExternalCallback
            )
            .is_err(),
            "{site_local} is site-local and must be refused"
        );
    }
    for public in ["2606:4700::1111", "2001:4860:4860::8888"] {
        assert!(
            validate_ip_target(
                IpAddr::V6(public.parse::<Ipv6Addr>().unwrap()),
                UrlPolicy::ExternalCallback
            )
            .is_ok(),
            "{public} is public and must stay allowed"
        );
    }
}

#[test]
fn ip_target_rejects_ipv4_mapped_ipv6_private_addresses() {
    let mapped: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(
        validate_ip_target(IpAddr::V6(mapped), UrlPolicy::ExternalCallback).is_err(),
        "v4-mapped private address must be refused so an IPv6 query path cannot bypass the v4 private-range check"
    );
}

#[test]
fn reserved_and_embedded_private_ranges_are_refused_with_public_neighbors_allowed() {
    let policy = UrlPolicy::ExternalCallback;
    let cases: &[(&str, bool)] = &[
        // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved.
        ("224.0.0.1", false),
        ("239.255.255.255", false),
        ("223.255.255.255", true),
        ("240.0.0.1", false),
        ("255.255.255.254", false),
        // 198.18.0.0/15 benchmarking (RFC 2544).
        ("198.18.0.1", false),
        ("198.19.255.255", false),
        ("198.17.255.255", true),
        ("198.20.0.1", true),
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890).
        ("192.0.0.1", false),
        ("192.0.0.255", false),
        ("192.0.1.1", true),
        // NAT64 64:ff9b::/96 carries an IPv4 address in the low 32 bits;
        // 64:ff9b:1::/48 is local-use NAT64 and always internal.
        ("64:ff9b::10.0.0.1", false),
        ("64:ff9b::a9fe:a9fe", false),
        ("64:ff9b::8.8.8.8", true),
        ("64:ff9b:1::1", false),
        // 6to4 2002::/16 carries the IPv4 address in bits 16-47.
        ("2002:0a00:0001::1", false),
        ("2002:c0a8:0101::1", false),
        ("2002:0808:0808::1", true),
        // Teredo 2001:0000::/32: server address in bits 32-63, client
        // address inverted in the low 32 bits.
        ("2001:0:0a00:1:0:0:f7f7:f7f7", false),
        ("2001:0:0808:0808:0:0:f5ff:fffe", false),
        ("2001:0:0808:0808:0:0:f7f7:f7f7", true),
        // IPv6 multicast and the deprecated IPv4-compatible form.
        ("ff02::1", false),
        ("::10.0.0.1", false),
        ("2606:4700::1111", true),
        ("1.1.1.1", true),
    ];
    for (address, allowed) in cases {
        let ip: IpAddr = address.parse().expect(address);
        assert_eq!(
            validate_ip_target(ip, policy).is_ok(),
            *allowed,
            "{address} should be {}",
            if *allowed { "allowed" } else { "refused" }
        );
    }
}

#[test]
fn ip_target_accepts_loopback_under_scan_but_rejects_under_external_callback() {
    let lo = ipv4(127, 0, 0, 1);
    assert!(validate_ip_target(lo, UrlPolicy::Scan).is_ok());
    assert!(validate_ip_target(lo, UrlPolicy::ExternalCallback).is_err());
}

#[test]
fn security_regression_domain_resolution_rejects_loopback_under_scan_policy() {
    let lo = ipv4(127, 0, 0, 1);
    assert!(validate_resolved_domain_ip_target("rebind.example", lo, UrlPolicy::Scan).is_err());
}

#[test]
fn a_mapped_loopback_answer_requires_a_localhost_name() {
    // Bug: A public hostname can resolve to an IPv4-mapped loopback address under ScanTarget.
    let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    assert!(
        validate_resolved_domain_ip_target("rebind.example", mapped, UrlPolicy::ScanTarget)
            .is_err()
    );
    assert!(
        validate_resolved_domain_ip_target("app.localhost", mapped, UrlPolicy::ScanTarget).is_ok()
    );
}

#[test]
fn local_dev_domain_resolution_must_stay_loopback() {
    let lo = ipv4(127, 0, 0, 1);
    let private = ipv4(192, 168, 1, 10);
    assert!(validate_resolved_domain_ip_target("localhost", lo, UrlPolicy::Scan).is_ok());
    assert!(validate_resolved_domain_ip_target("localhost", private, UrlPolicy::Scan).is_err());
}

fn redirect_nonblocking(url: &str, policy: UrlPolicy) -> Result<(), String> {
    validate_redirect_target_nonblocking(&url::Url::parse(url).expect("parse url"), policy)
}

#[test]
fn redirect_policy_rejects_ip_literal_internal_targets_inline() {
    // reqwest dials IP-literal redirect targets directly, bypassing the DNS
    // resolver, so the redirect policy must reject them inline.
    let policy = UrlPolicy::Redirect {
        allow_local_dev: false,
    };
    assert!(redirect_nonblocking("http://169.254.169.254/latest/meta-data/", policy).is_err());
    assert!(redirect_nonblocking("http://10.0.0.5/admin", policy).is_err());
    assert!(redirect_nonblocking("http://[::1]/", policy).is_err());
    assert!(redirect_nonblocking("http://[::ffff:127.0.0.1]/", policy).is_err());
}

fn redirect_with_local_dev(url: &str, allow_local_dev: bool) -> Result<(), String> {
    redirect_nonblocking(url, UrlPolicy::Redirect { allow_local_dev })
}

#[test]
fn redirect_target_rejects_ip_literal_internal_targets() {
    assert!(redirect_with_local_dev("http://169.254.169.254/latest/meta-data/", false).is_err());
    assert!(redirect_with_local_dev("http://10.0.0.5/admin", false).is_err());
    assert!(redirect_with_local_dev("http://192.168.1.1/reboot", false).is_err());
    assert!(redirect_with_local_dev("http://127.0.0.1:11434/api", false).is_err());
    assert!(redirect_with_local_dev("http://[::1]/", false).is_err());
    assert!(redirect_with_local_dev("http://[::ffff:127.0.0.1]/", false).is_err());
}

#[test]
fn redirect_target_allows_public_targets() {
    assert!(redirect_with_local_dev("https://cdn.example.com/style.css", false).is_ok());
    assert!(redirect_with_local_dev("https://fonts.example.org/f.css", false).is_ok());
}

#[test]
fn redirect_target_allows_loopback_only_when_scanning_local_dev() {
    // Scanning a localhost dev server must still fetch its own same-origin
    // assets (allow_local_dev=true), but a public scan (false) must not.
    assert!(redirect_with_local_dev("http://127.0.0.1:5173/app.css", true).is_ok());
    assert!(redirect_with_local_dev("http://127.0.0.1:5173/app.css", false).is_err());
    // Even under local-dev, a private (non-loopback) LAN target stays blocked.
    assert!(redirect_with_local_dev("http://192.168.1.10/x.css", true).is_err());
}

#[test]
fn redirect_target_rejects_non_http_schemes() {
    assert!(redirect_with_local_dev("file:///etc/passwd", false).is_err());
    assert!(redirect_with_local_dev("ftp://internal/x", false).is_err());
}

#[test]
fn redirect_policy_defers_domain_targets_without_blocking_dns() {
    let policy = UrlPolicy::Redirect {
        allow_local_dev: false,
    };
    assert!(redirect_nonblocking("https://this-host-does-not-resolve.invalid/", policy).is_ok());
    assert!(redirect_nonblocking("https://example.com/", policy).is_ok());
    assert!(redirect_nonblocking("http://metadata.google.internal/", policy).is_err());
    assert!(redirect_nonblocking("http://localhost/", policy).is_err());
}
