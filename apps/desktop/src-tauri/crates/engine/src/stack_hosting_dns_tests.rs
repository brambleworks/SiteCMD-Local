use super::tests::headers;
use super::*;
use http::HeaderMap;

#[test]
fn hosting_changes_no_other_field() {
    let original = DetectedStack {
        server: Some("nginx".into()),
        cdn: Some("Cloudflare".into()),
        framework: Some("Astro".into()),
        cms: Some("WordPress".into()),
        js_framework: Some("React".into()),
        css_framework: Some("Tailwind CSS".into()),
        other: vec!["jQuery".into()],
        hosting: None,
        dns_provider: None,
    };
    for (host, map, body, label) in [
        ("shop.pages.dev", HeaderMap::new(), "", "Cloudflare Pages"),
        (
            "www.example.com",
            headers(&[("x-vercel-id", "iad1::abc123")]),
            "",
            "Vercel",
        ),
        (
            "www.example.com",
            HeaderMap::new(),
            r#"<html><head><meta name="generator" content="Framer"></head></html>"#,
            "Framer",
        ),
    ] {
        let mut stack = original.clone();
        detect_hosting(
            &mut stack,
            host,
            &map,
            body,
            &body.to_ascii_lowercase(),
            None,
        );
        assert_eq!(
            stack,
            DetectedStack {
                hosting: Some(label.into()),
                ..original.clone()
            },
            "{label}"
        );
    }
    let resolver = facts(serde_json::json!({
        "host_cname": records(&["example.netlify.app."]),
        "ns": records(&["ada.ns.cloudflare.com."])
    }));
    let mut stack = original.clone();
    detect_hosting(
        &mut stack,
        "www.example.com",
        &HeaderMap::new(),
        "",
        "",
        Some(&resolver),
    );
    assert_eq!(
        stack,
        DetectedStack {
            hosting: Some("Netlify".into()),
            dns_provider: Some("Cloudflare".into()),
            ..original
        }
    );
}

/// Resolver facts for example.com, every answer empty but the ones given.
fn facts(given: serde_json::Value) -> ResolverFacts {
    let mut wire = serde_json::json!({
        "domain": "example.com",
        "apex_txt": { "answer": "no_records" },
        "apex_mx": { "answer": "no_records" },
        "dmarc_txt": { "answer": "no_records" },
        "dnskey": { "answer": "no_records" },
        "caa": { "answer": "no_records" },
        "www_cname": { "answer": "no_records" }
    });
    for (name, value) in given.as_object().expect("an object of answers") {
        wire[name] = value.clone();
    }
    serde_json::from_value(wire).expect("resolver facts parse")
}

fn records(names: &[&str]) -> serde_json::Value {
    serde_json::json!({ "answer": "records", "value": names })
}

fn from_dns(host: &str, resolver: &ResolverFacts) -> DetectedStack {
    let mut stack = DetectedStack::default();
    detect_hosting(&mut stack, host, &HeaderMap::new(), "", "", Some(resolver));
    stack
}

#[test]
fn a_cname_to_a_platform_s_target_names_it() {
    for (target, label) in [
        ("shop.pages.dev.", "Cloudflare Pages"),
        ("example.netlify.app.", "Netlify"),
        ("example.github.io.", "GitHub Pages"),
        ("cname.vercel-dns.com.", "Vercel"),
        ("cname.vercel-dns-0.com.", "Vercel"),
        ("d1e2f3a4b5.vercel-dns-017.com.", "Vercel"),
        ("shops.myshopify.com.", "Shopify"),
        ("ext-cust.squarespace.com.", "Squarespace"),
        ("cdn.webflow.com.", "Webflow"),
        ("proxy-ssl.webflow.com.", "Webflow"),
        ("pointing.wixdns.net.", "Wix"),
        ("sites.framer.app.", "Framer"),
    ] {
        let resolver = facts(serde_json::json!({ "host_cname": records(&[target]) }));
        assert_eq!(
            from_dns("www.example.com", &resolver).hosting.as_deref(),
            Some(label),
            "{target}"
        );
    }
}

#[test]
fn a_cname_to_a_lookalike_or_an_unknown_target_names_nothing() {
    for target in [
        "pages.dev.example.net.",
        "example.vercel-dns.com.example.net.",
        "vercel-dns-x.com.",
        "edge.example.net.",
        "evilpages.dev.",
        "vercel-dns-12345.com.",
        "example.vercel-dns-17.com.example.com.",
    ] {
        let resolver = facts(serde_json::json!({ "host_cname": records(&[target]) }));
        assert_eq!(
            from_dns("www.example.com", &resolver).hosting,
            None,
            "{target}"
        );
    }
}

#[test]
fn an_apex_site_reads_its_www_cname_and_a_www_site_does_not() {
    let resolver = facts(serde_json::json!({ "www_cname": records(&["example.netlify.app."]) }));
    assert_eq!(
        from_dns("example.com", &resolver).hosting.as_deref(),
        Some("Netlify")
    );
    assert_eq!(from_dns("shop.example.com", &resolver).hosting, None);
    assert_eq!(from_dns("www.example.com", &resolver).hosting, None);
}

#[test]
fn an_answer_that_failed_or_held_nothing_names_nothing() {
    let resolver = facts(serde_json::json!({
        "host_cname": { "answer": "failed", "value": "timed out" },
        "ns": { "answer": "no_records" }
    }));
    assert_eq!(
        from_dns("www.example.com", &resolver),
        DetectedStack::default()
    );
}

#[test]
fn the_nameservers_name_the_dns_provider() {
    for (servers, provider) in [
        (
            vec!["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."],
            Some("Cloudflare"),
        ),
        (
            vec!["ns1.vercel-dns.com.", "ns2.vercel-dns.com."],
            Some("Vercel"),
        ),
        (vec!["ns1.example.net."], None),
        (vec!["ada.ns.cloudflare.com.example.com."], None),
        (vec!["evilns.cloudflare.com."], None),
        (vec!["ns1.vercel-dns.com.example.com."], None),
    ] {
        let resolver = facts(serde_json::json!({ "ns": records(&servers) }));
        assert_eq!(
            from_dns("www.example.com", &resolver)
                .dns_provider
                .as_deref(),
            provider,
            "{servers:?}"
        );
    }
}

#[test]
fn the_site_s_subdomain_outranks_its_cname_and_its_cname_outranks_a_header() {
    let pages = facts(serde_json::json!({ "host_cname": records(&["example.netlify.app."]) }));
    assert_eq!(
        from_dns("shop.pages.dev", &pages).hosting.as_deref(),
        Some("Cloudflare Pages")
    );
    let mut stack = DetectedStack::default();
    detect_hosting(
        &mut stack,
        "www.example.com",
        &headers(&[("x-vercel-id", "iad1::abc123")]),
        "",
        "",
        Some(&pages),
    );
    assert_eq!(stack.hosting.as_deref(), Some("Netlify"));
}

#[test]
fn dns_names_ignore_case_and_the_root_dot() {
    let resolver = facts(serde_json::json!({
        "www_cname": records(&["EXAMPLE.NETLIFY.APP."]),
        "ns": records(&["ADA.NS.CLOUDFLARE.COM."])
    }));
    let stack = from_dns("EXAMPLE.COM.", &resolver);
    assert_eq!(stack.hosting.as_deref(), Some("Netlify"));
    assert_eq!(stack.dns_provider.as_deref(), Some("Cloudflare"));
}

#[test]
fn the_host_s_cname_outranks_the_apex_s_www_cname() {
    let resolver = facts(serde_json::json!({
        "host_cname": records(&["example.github.io."]),
        "www_cname": records(&["example.netlify.app."])
    }));
    assert_eq!(
        from_dns("example.com", &resolver).hosting.as_deref(),
        Some("GitHub Pages")
    );
}

#[test]
fn an_unanswered_dns_question_keeps_the_existing_labels() {
    for answer in [
        serde_json::json!({"answer": "no_records"}),
        serde_json::json!({"answer": "failed", "value": "timed out"}),
        records(&[]),
    ] {
        let resolver = facts(serde_json::json!({"host_cname": answer, "ns": answer}));
        let original = DetectedStack {
            hosting: Some("Vercel".into()),
            dns_provider: Some("Cloudflare".into()),
            ..DetectedStack::default()
        };
        let mut stack = original.clone();
        detect_hosting(
            &mut stack,
            "www.example.com",
            &HeaderMap::new(),
            "",
            "",
            Some(&resolver),
        );
        assert_eq!(stack, original);
    }
}

#[test]
fn omitted_dns_questions_deserialize_as_absent() {
    let resolver = facts(serde_json::json!({}));
    assert!(resolver.host_cname.is_none());
    assert!(resolver.ns.is_none());
    assert_eq!(
        from_dns("www.example.com", &resolver),
        DetectedStack::default()
    );
}

#[test]
fn a_vercel_lookalike_label_cannot_name_vercel() {
    for target in ["evilvercel-dns-17.com", "evilvercel-dns-17.com."] {
        let resolver = facts(serde_json::json!({"host_cname": records(&[target])}));
        assert_eq!(
            from_dns("www.example.com", &resolver).hosting,
            None,
            "{target}"
        );
    }
}

#[test]
fn a_cname_root_dot_does_not_change_its_hosting_match() {
    for target in [
        "shop.pages.dev",
        "shop.pages.dev.",
        "project.vercel-dns-17.com",
        "project.vercel-dns-17.com.",
    ] {
        let resolver = facts(serde_json::json!({"host_cname": records(&[target])}));
        let expected = if target.starts_with("shop.") {
            "Cloudflare Pages"
        } else {
            "Vercel"
        };
        assert_eq!(
            from_dns("www.example.com", &resolver).hosting.as_deref(),
            Some(expected),
            "{target}"
        );
    }
}

#[test]
fn a_cname_chain_cannot_name_a_host_from_a_later_hop() {
    for (targets, expected) in [
        (vec!["edge.example.net.", "shop.pages.dev."], None),
        (
            vec!["example.netlify.app.", "shop.pages.dev."],
            Some("Netlify"),
        ),
    ] {
        let resolver = facts(serde_json::json!({"host_cname": records(&targets)}));
        assert_eq!(
            from_dns("www.example.com", &resolver).hosting.as_deref(),
            expected,
            "{targets:?}"
        );
    }
}

#[test]
fn a_split_nameserver_set_cannot_name_one_dns_provider() {
    for servers in [
        vec!["ada.ns.cloudflare.com.", "ns1.vercel-dns.com."],
        vec!["ns1.vercel-dns.com.", "ada.ns.cloudflare.com."],
        vec!["ada.ns.cloudflare.com.", "ns1.example.net."],
        vec!["ns1.example.net.", "ada.ns.cloudflare.com."],
    ] {
        let resolver = facts(serde_json::json!({"ns": records(&servers)}));
        assert_eq!(
            from_dns("www.example.com", &resolver).dns_provider,
            None,
            "{servers:?}"
        );
    }
}

#[test]
fn a_wordpress_com_cname_must_name_wordpress_com_hosting() {
    for target in ["shop.wordpress.com", "shop.wordpress.com."] {
        let resolver = facts(serde_json::json!({"host_cname": records(&[target])}));
        assert_eq!(
            from_dns("www.example.com", &resolver).hosting.as_deref(),
            Some("WordPress.com"),
            "{target}"
        );
    }
}
