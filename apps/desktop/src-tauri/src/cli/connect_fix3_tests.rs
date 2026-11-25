//! Parsed URL-component regressions for connection setup.

use serde_json::{json, Value};

use super::normalized_origin;
use super::test_support::{success, Harness, Reply};

#[test]
fn connect_normalizes_default_ports_from_the_parsed_host() {
    // Bug: raw authority splitting can reject the HTTPS default port that the shared parser canonicalizes away.
    for (address, expected) in [
        ("https://Example.com:443/path", "https://example.com"),
        ("https://[::1]:443/", "https://[::1]"),
        ("https:example.com:443/#://", "https://example.com"),
        (
            "https:/example.com:443/?next=https://a",
            "https://example.com",
        ),
    ] {
        assert_eq!(normalized_origin(address).unwrap(), expected);
    }
}

#[tokio::test]
async fn connect_rejects_nondefault_ports_in_approved_site_urls() {
    // Bug: a later :// can make raw authority splitting miss a port in Connect's returned site_url.
    for address in [
        "https:/example.com:8443/?next=https://a",
        "https:example.com:8443/#://x",
        r"https:\\example.com:8443/a://b",
        "https:\\example.com:8443/a://b",
        "https:example.com:8443",
    ] {
        let mut replies = success(1);
        let mut approved: Value = serde_json::from_str(&replies[1].body).unwrap();
        approved["site_url"] = json!(address);
        replies[1] = Reply::json(200, approved);
        let harness = Harness::new(replies).await;
        assert_eq!(
            harness.run().await.0.unwrap_err(),
            "SiteCMD returned an invalid site address"
        );
        assert_eq!(harness.routes().len(), 2);
    }
}
