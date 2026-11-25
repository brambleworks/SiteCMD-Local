use super::*;

fn route_of(url: &str) -> CanonicalRoute {
    canonical_route(&url::Url::parse(url).expect("fixture url"))
}

#[test]
fn a_route_is_a_path_not_a_url() {
    // The environment pins scheme and host, so carrying them in the route
    // would key identity on facts that belong to the site record.
    assert_eq!(route_of("https://example.com/pricing").route, "/pricing");
    assert_eq!(route_of("https://example.com").route, "/");
}

#[test]
fn trailing_slashes_are_distinct_routes() {
    assert_eq!(route_of("https://example.com/checkout").route, "/checkout");
    assert_eq!(
        route_of("https://example.com/checkout/").route,
        "/checkout/"
    );
}

#[test]
fn a_query_string_is_stripped_and_flagged() {
    let observed = route_of("https://example.com/product?id=1");
    assert_eq!(observed.route, "/product");
    // The stripped route cannot tell ?id=1 from ?id=2, so the merge is
    // recorded rather than hidden; verification refuses to compare these.
    assert!(observed.query_dependent);
    assert!(!route_of("https://example.com/product").query_dependent);
    // An empty query is not a variant of anything.
    assert!(!route_of("https://example.com/product?").query_dependent);
}

#[test]
fn a_fragment_never_reaches_the_route() {
    let observed = route_of("https://example.com/docs#install");
    assert_eq!(observed.route, "/docs");
    assert!(!observed.query_dependent);
}

#[test]
fn dot_segments_resolve_and_repeated_slashes_stay() {
    assert_eq!(canonical_path("/a/b/../c"), "/a/c");
    assert_eq!(canonical_path("/a/./b"), "/a/b");
    assert_eq!(canonical_path("/a/.."), "/");
    // Preserved: `//a` and `/a` can serve different content, and the rules
    // say what is assumed rather than what looks tidy.
    assert_eq!(canonical_path("//a"), "//a");
    assert_eq!(canonical_path("/a//b"), "/a//b");
}

#[test]
fn an_encoded_slash_is_never_decoded() {
    // Decoding it would turn one segment into two and merge two resources
    // whose paths only look alike after the rewrite.
    assert_eq!(canonical_path("/files/a%2Fb"), "/files/a%2Fb");
    assert_eq!(canonical_path("/files/a%2fb"), "/files/a%2Fb");
}

#[test]
fn percent_encoding_is_normalized_without_changing_what_it_means() {
    // Unreserved characters decode: %7E is a tilde in every reading.
    assert_eq!(canonical_path("/%7Euser"), "/~user");
    assert_eq!(canonical_path("/%61bc"), "/abc");
    // Everything else keeps its escape, with uppercase hex.
    assert_eq!(canonical_path("/a%20b"), "/a%20b");
    assert_eq!(canonical_path("/a%2bb"), "/a%2Bb");
    // Non-ASCII bytes stay as sent: no Unicode normalization, because two
    // byte sequences a human reads alike can still be two resources.
    assert_eq!(canonical_path("/caf%C3%A9"), "/caf%C3%A9");
    assert_eq!(canonical_path("/caf%c3%a9"), "/caf%C3%A9");
}

#[test]
fn a_malformed_escape_is_left_exactly_as_sent() {
    // Rewriting it would invent a route the server never served.
    assert_eq!(canonical_path("/100%"), "/100%");
    assert_eq!(canonical_path("/a%zz"), "/a%zz");
}

#[test]
fn path_case_is_preserved() {
    // Servers differ on whether case matters; assuming it does not would
    // merge two pages on the ones where it does.
    assert_eq!(canonical_path("/Docs/Install"), "/Docs/Install");
}

#[test]
fn an_authored_route_gains_its_leading_slash() {
    // literal authored path delimiters must encode instead of being stripped as URL metadata.
    assert_eq!(canonical_path("pricing"), "/pricing");
    assert_eq!(canonical_path(""), "/");
    assert_eq!(canonical_path("/search?q=x#top"), "/search%3Fq=x%23top");
}

#[test]
fn canonicalizing_twice_changes_nothing() {
    // Storage round-trips routes, so a second pass has to be a no-op or
    // stored identity would drift from freshly observed identity.
    for path in [
        "/a/b/../c",
        "/files/a%2Fb",
        "/%7Euser",
        "//a",
        "/checkout/",
        "/caf%C3%A9",
        "/100%",
    ] {
        let once = canonical_path(path);
        assert_eq!(canonical_path(&once), once, "{path}");
    }
}

#[test]
fn the_canonicalizer_version_is_pinned() {
    assert_eq!(CANONICALIZER_VERSION, 3);
}

#[test]
fn authored_unicode_route_is_idempotent() {
    // UTF-8 bytes were cast to Latin-1 characters during percent normalization.
    for (path, expected) in [
        ("/café", "/caf%C3%A9"),
        ("/日本語/%2F", "/%E6%97%A5%E6%9C%AC%E8%AA%9E/%2F"),
    ] {
        assert_eq!(canonical_path(path), expected);
        assert_eq!(canonical_path(&canonical_path(path)), expected);
    }
}

#[test]
fn authored_ascii_paths_match_rust_url_paths() {
    // controls and backslashes split authored routes from rust-url's observed paths.
    let mut failures = Vec::new();
    for byte in 0..=127u8 {
        let ch = char::from(byte);
        for authored in [format!("/a{ch}b"), format!("/a{ch}")] {
            let mut observed = url::Url::parse("https://example.com/").unwrap();
            observed.set_path(authored.trim_matches(|ch| ch <= '\u{20}'));
            let expected = observed.path().replace('^', "%5E");
            let actual = canonical_path(&authored);
            if actual != expected {
                failures.push(format!("ASCII {byte:#04x}: {actual:?} != {expected:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn http_path_cleanup_precedes_escape_and_dot_normalization() {
    // removing ignored controls after escape parsing left authored paths noncanonical.
    for authored in ["/%4\t1", "/%\n41", "/a/.\r./b", "/a\\../b"] {
        let mut observed = url::Url::parse("https://example.com/").unwrap();
        observed.set_path(authored);
        let expected = canonical_route(&observed).route;
        assert_eq!(canonical_path(authored), expected, "{authored:?}");
        assert_eq!(canonical_path(&canonical_path(authored)), expected);
    }
}

#[test]
fn shared_route_spellings_match_authored_and_observed_paths() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/sync/route-cases.json"
    ))
    .unwrap();
    for case in fixture["canonicalization"].as_array().unwrap() {
        let input = case["route"].as_str().unwrap();
        let expected = case["canonical_route"].as_str().unwrap();
        assert_eq!(canonical_path(input), expected, "{input}");
        let observed = url::Url::parse(&format!("https://example.com{input}")).unwrap();
        assert_eq!(canonical_route(&observed).route, expected, "{input}");
        assert_eq!(canonical_path(expected), expected, "{input}");
        let wire: crate::sync::wire::RoutePath = expected.try_into().unwrap();
        assert_eq!(serde_json::to_value(wire).unwrap(), expected);
        let route = CanonicalRoute::new(canonical_path(input), false);
        assert_eq!(serde_json::to_value(route).unwrap()["route"], expected);
    }
}

#[test]
fn authored_edge_paths_have_stable_observed_spellings() {
    for (input, expected) in [
        ("/a ", "/a"),
        ("//.", "//"),
        ("/\\.", "//"),
        ("/9%d%321", "/9%D21"),
        ("/%4%31", "/A"),
    ] {
        assert_eq!(canonical_path(input), expected, "{input}");
        assert_eq!(canonical_path(expected), expected);
        let wire: crate::sync::wire::RoutePath = expected.try_into().unwrap();
        assert_eq!(serde_json::to_value(wire).unwrap(), expected);
    }
}
