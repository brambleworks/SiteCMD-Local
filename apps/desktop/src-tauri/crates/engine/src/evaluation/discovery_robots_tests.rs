use super::RobotsRules;

#[test]
fn rfc_9309_groups_and_longest_paths() {
    let body = concat!(
        "User-Agent: *\nDisallow: *.gif$\nDisallow: /example/\nAllow: /publications/\n",
        "User-Agent: foobot\nDisallow:/\nAllow:/example/page.html\nAllow:/example/allowed.gif\n",
        "User-Agent: barbot\nUser-Agent: bazbot\nDisallow: /example/page.html\n",
        "User-Agent: quxbot\n",
    );
    for (agent, path, allowed) in [
        ("SiteCMD", "/publications/paper", true),
        ("SiteCMD", "/example/page.html", false),
        ("SiteCMD", "/image.gif", false),
        ("SiteCMD", "/image.gif/more", true),
        ("foobot", "/example/page.html", true),
        ("foobot", "/example/allowed.gif", true),
        ("foobot", "/elsewhere", false),
        ("barbot", "/example/page.html", false),
        ("bazbot", "/elsewhere", true),
        ("quxbot", "/example/page.html", true),
    ] {
        assert_eq!(
            RobotsRules::parse(body, agent).allowed(path),
            allowed,
            "{agent} {path}"
        );
    }
    let rules = RobotsRules::parse(
        "User-agent: foobot\nAllow: /example/page/\nDisallow: /example/page/disallowed.gif",
        "foobot",
    );
    assert!(rules.allowed("/example/page/allowed.gif"));
    assert!(!rules.allowed("/example/page/disallowed.gif"));
}

#[test]
fn rfc_9309_percent_encoding_and_special_characters() {
    for (pattern, path) in [
        ("/foo/bar?baz=quz", "/foo/bar?baz=quz"),
        (
            "/foo/bar?baz=https%3A%2F%2Ffoo.bar",
            "/foo/bar?baz=https%3a%2f%2ffoo.bar",
        ),
        ("/foo/bar/ツ", "/foo/bar/%E3%83%84"),
        ("/foo/bar/%E3%83%84", "/foo/bar/ツ"),
        ("/foo/bar/%62%61%7A", "/foo/bar/baz"),
        ("/foo/bar/baz", "/foo/bar/%62%61%7a"),
        ("/path/file-with-a-%2A.html", "/path/file-with-a-%2a.html"),
        ("/path/foo-%24", "/path/foo-%24"),
        ("/path/file-with-a-%2A.html", "/path/file-with-a-*.html"),
        ("/path/foo-%24", "/path/foo-$"),
        (
            "/foo/bar?baz=https://foo.bar",
            "/foo/bar?baz=https%3A%2F%2Ffoo.bar",
        ),
    ] {
        let rules = RobotsRules::parse(&format!("User-agent: *\nDisallow: {pattern}"), "SiteCMD");
        assert!(!rules.allowed(path), "{pattern} {path}");
    }
    let rules = RobotsRules::parse("User-agent: *\nDisallow: /foo%2Fbar", "SiteCMD");
    assert!(rules.allowed("/foo/bar"));
    assert!(!rules.allowed("/foo%2fbar"));
}

#[test]
fn groups_ignore_other_records_and_rules_outside_groups() {
    let rules = RobotsRules::parse(concat!(
        "Disallow: /public\nUser-agent: Other\nDisallow: /public\n",
        "User-agent: SiteCMD\nDisallow: /one\nSitemap: https://example.com/map.xml\nDisallow: /two\n",
        "User-agent: SiteCMD\nDisallow: /three\n",
    ), "SiteCMD");
    assert!(rules.allowed("/public"));
    for path in ["/one", "/two", "/three"] {
        assert!(!rules.allowed(path));
    }
    assert!(
        RobotsRules::parse("User-agent: SiteCMD\nDisallow: /", "SiteCMD").allowed("/robots.txt")
    );
}

#[test]
fn robots_txt_exemption_normalizes_unreserved_escapes() {
    let rules = RobotsRules::parse("User-agent: *\nDisallow: /", "SiteCMD");
    for path in [
        "/robot%73.txt",
        "/robots%2Etxt",
        "/robots%2etxt",
        "/robots.txt",
    ] {
        assert!(rules.allowed(path), "{path}");
    }
}

#[test]
fn wildcard_end_anchor_does_not_allow_a_trailing_suffix() {
    let rules = RobotsRules::parse("User-agent: *\nDisallow: /private/*/end$", "SiteCMD");
    assert!(!rules.allowed("/private/a/end"));
    assert!(rules.allowed("/private/a/end/more"));
    assert!(!rules.allowed("/private/a/end/more/end"));
}

#[test]
fn selected_groups_filter_at_capacity_and_become_unknown_above_it() {
    let rules = "Disallow: /private\n".repeat(super::ROBOTS_PIECE_LIMIT / 2);
    let mut body = format!(
        "User-agent: SiteCMD\n{rules}User-agent: SiteCMD\n{rules}User-agent: Other\n{}",
        "Disallow: /public\n".repeat(super::ROBOTS_PIECE_LIMIT + 1)
    );
    let at_capacity = RobotsRules::parse(&body, "SiteCMD");
    assert!(at_capacity.known);
    assert!(!at_capacity.allowed("/private"));
    body.push_str("User-agent: SiteCMD\nDisallow: /private\n");
    COMPILED_RULES.set(0);
    let above_capacity = RobotsRules::parse(&body, "SiteCMD");
    assert!(!above_capacity.known);
    assert!(!above_capacity.allowed("/private"));
    assert_eq!(COMPILED_RULES.get(), 0);
}

#[test]
fn generated_matches_agree_with_the_backtracking_oracle() {
    let mut seed = 0x9309_5eed_u64;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (seed >> 32) as usize
    };
    for _ in 0..20_000 {
        let path: Vec<_> = (0..next() % 48).map(|_| b"/ab?"[next() % 4]).collect();
        let mut pattern: Vec<_> = (0..next() % 32).map(|_| b"/ab?*"[next() % 5]).collect();
        if next() % 2 == 0 {
            pattern.push(b'$');
        }
        assert_eq!(
            compiled_matches(&pattern, &path),
            old_matches(&pattern, &path),
            "pattern {pattern:?}, path {path:?}"
        );
    }
    for (pattern, path) in [
        ("/a*a$", "/aaaa"),
        ("/*a*b*c$", "/abcabc"),
        ("/a**$", "/abc"),
        ("/a*b$", "/ab/ab"),
        ("/*longer*than*path", "/short"),
    ] {
        assert_eq!(
            compiled_matches(pattern.as_bytes(), path.as_bytes()),
            old_matches(pattern.as_bytes(), path.as_bytes())
        );
    }
}

pub(super) fn old_matches(pattern: &[u8], path: &[u8]) -> bool {
    let anchored = pattern.last() == Some(&b'$');
    let pattern = if anchored {
        &pattern[..pattern.len() - 1]
    } else {
        pattern
    };
    let (mut rule, mut at, mut star) = (0, 0, None);
    while at < path.len() {
        if rule == pattern.len() && !anchored {
            return true;
        }
        if pattern.get(rule) == Some(&b'*') {
            rule += 1;
            star = Some((rule, at));
        } else if pattern.get(rule) == Some(&path[at]) {
            rule += 1;
            at += 1;
        } else if let Some((after, consumed)) = star {
            at = consumed + 1;
            star = Some((after, at));
            rule = after;
        } else {
            return false;
        }
    }
    while pattern.get(rule) == Some(&b'*') {
        rule += 1;
    }
    rule == pattern.len()
}

#[test]
fn selected_groups_are_bounded_by_their_merged_pieces() {
    let pattern = format!("/private{}", "*".repeat(super::ROBOTS_PIECE_LIMIT / 2 - 1));
    let body = format!(
        "User-agent: SiteCMD\nDisallow: {pattern}\nUser-agent: Other\nDisallow: /public{}\nUser-agent: SiteCMD\nDisallow: {pattern}",
        "*".repeat(super::ROBOTS_PIECE_LIMIT)
    );
    let at_capacity = RobotsRules::parse(&body, "SiteCMD");
    assert!(at_capacity.known);
    assert!(!at_capacity.allowed("/private"));
    let above = body.replacen("Disallow: /private", "Disallow: /private*", 1);
    COMPILED_RULES.set(0);
    let above_capacity = RobotsRules::parse(&above, "SiteCMD");
    assert!(!above_capacity.known);
    assert!(!above_capacity.allowed("/private"));
    assert_eq!(COMPILED_RULES.get(), 0);
}

#[test]
fn plain_rules_keep_their_full_piece_capacity() {
    for count in [
        1000.min(super::ROBOTS_PIECE_LIMIT),
        super::ROBOTS_PIECE_LIMIT,
    ] {
        let body = format!(
            "User-agent: SiteCMD\n{}",
            "Disallow: /private\n".repeat(count)
        );
        assert!(
            !RobotsRules::parse(&body, "SiteCMD").allowed("/private"),
            "{count}"
        );
    }
}

#[test]
fn selected_groups_filter_at_the_star_limit_and_become_unknown_above_it() {
    let limit = super::ROBOTS_STAR_RULE_LIMIT;
    let first = "Disallow: /private*\n".repeat(limit / 2);
    let second = "Disallow: /private*\n".repeat(limit - limit / 2);
    let plain = "Disallow: /private\n".repeat(super::ROBOTS_PIECE_LIMIT - 2 * limit - 2);
    let mut body = format!(
        "User-agent: SiteCMD\n{first}{plain}User-agent: Other\n{}User-agent: SiteCMD\n{second}",
        "Disallow: /public*\n".repeat(limit + 1)
    );
    let at_capacity = RobotsRules::parse(&body, "SiteCMD");
    assert!(at_capacity.known);
    assert!(!at_capacity.allowed("/private"));
    body.push_str("Disallow: /private*\n");
    COMPILED_RULES.set(0);
    let above_capacity = RobotsRules::parse(&body, "SiteCMD");
    assert!(!above_capacity.known);
    assert!(!above_capacity.allowed("/private"));
    assert_eq!(COMPILED_RULES.get(), 0);
}

#[test]
fn plain_rules_do_not_consume_the_star_rule_capacity() {
    for stars in [0, super::ROBOTS_STAR_RULE_LIMIT] {
        let plain = super::ROBOTS_PIECE_LIMIT - 2 * stars - 1;
        let body = format!(
            "User-agent: SiteCMD\n{}{}",
            "Disallow: /private*\n".repeat(stars),
            "Disallow: /private\n".repeat(plain)
        );
        assert!(!RobotsRules::parse(&body, "SiteCMD").allowed("/private"));
    }
}

fn compiled_matches(pattern: &[u8], path: &[u8]) -> bool {
    super::Rule::compile(
        String::from_utf8(pattern.to_vec()).expect("ASCII pattern"),
        false,
    )
    .matches(std::str::from_utf8(path).expect("ASCII path"))
}

#[test]
fn matching_uses_prebuilt_piece_searchers() {
    let source = include_str!("discovery_robots.rs");
    let matcher = source
        .split("fn matches(")
        .nth(1)
        .expect("matcher")
        .split("#[derive(Default)]")
        .next()
        .expect("matcher body");
    assert!(matcher.contains("piece.find(remaining_path)"));
    assert!(!matcher.contains("Finder::new"));
}

thread_local! {
    pub(super) static COMPILED_RULES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[test]
fn unselected_rules_are_never_compiled() {
    let body = format!(
        "User-agent: SiteCMD\nDisallow: /private\nUser-agent: Other\nDisallow: /{}",
        "*".repeat(500_000)
    );
    COMPILED_RULES.set(0);
    assert!(!RobotsRules::parse(&body, "SiteCMD").allowed("/private"));
    assert_eq!(COMPILED_RULES.get(), 1);
}

#[test]
fn over_limit_groups_are_never_compiled() {
    for pattern in [
        format!("/{}", "*".repeat(super::ROBOTS_PIECE_LIMIT)),
        "/private*\nDisallow: ".repeat(super::ROBOTS_STAR_RULE_LIMIT) + "/private*",
    ] {
        COMPILED_RULES.set(0);
        let body = format!("User-agent: SiteCMD\nDisallow: {pattern}");
        assert!(!RobotsRules::parse(&body, "SiteCMD").allowed("/private"));
        assert_eq!(COMPILED_RULES.get(), 0);
    }
}

#[test]
fn stars_count_toward_specificity() {
    let rules = RobotsRules::parse("User-agent: *\nDisallow: /ab\nAllow: /*b", "SiteCMD");
    assert!(rules.allowed("/ab"));
}

#[test]
fn end_anchors_count_toward_specificity() {
    let rules = RobotsRules::parse("User-agent: *\nDisallow: /a*\nAllow: /a$", "SiteCMD");
    assert!(rules.allowed("/a"));
}
