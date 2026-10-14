//! A response whose repeated field lines a runtime handed over joined reads
//! as the lines it was combined from: the same rows and the same stack as the
//! separate lines give, field by field, for the page and for a probe.

use sitecmd_engine::evaluation::{ExecutedProbe, PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::header_lines::HeaderLines;
use sitecmd_engine::probe::{ProbeBody, ProbeOutcome, ProbeResponse};

const BODY: &str =
    "<html><head><title>Example</title></head><body><main>Example</main></body></html>";

/// Combine repeated values as Fetch does, retaining the fixture's name order.
/// Set-Cookie keeps its separate lines; other names join values with ", ".
fn joined(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut combined: Vec<(String, String)> = Vec::new();
    for (name, value) in pairs {
        let name = name.to_ascii_lowercase();
        match combined
            .iter_mut()
            .find(|(seen, _)| *seen == name && name != "set-cookie")
        {
            Some((_, lines)) => {
                lines.push_str(", ");
                lines.push_str(value);
            }
            None => combined.push((name, value.to_string())),
        }
    }
    combined
}

fn separate(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn artifact(headers: Vec<(String, String)>) -> PageArtifact {
    PageArtifact {
        url: "https://example.com/".into(),
        requested_url: Some("https://example.com/".into()),
        status_code: 200,
        http_version: Some("HTTP/2.0".into()),
        is_localhost: false,
        is_strict_localhost: false,
        headers,
        body: BODY.into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    }
}

/// The rows and the stack one evaluation answers, with nothing recorded.
fn answer(pairs: &[(&str, &str)], lines: HeaderLines) -> serde_json::Value {
    let headers = match lines {
        HeaderLines::Separate => separate(pairs),
        HeaderLines::Joined => joined(pairs),
    };
    let route = RouteSession::open_with(artifact(headers), lines).expect("opens");
    let evaluation = route.evaluate(&RouteFacts::default());
    serde_json::json!({ "results": evaluation.results, "stack": evaluation.stack })
}

fn row<'a>(answer: &'a serde_json::Value, check: &str) -> &'a serde_json::Value {
    answer["results"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["checkId"] == check)
        .expect("check row")
}

const CASES: &[(&str, &[(&str, &str)])] = &[
    (
        "X-Frame-Options twice",
        &[
            ("x-frame-options", "DENY"),
            ("x-frame-options", "SAMEORIGIN"),
        ],
    ),
    (
        "X-Content-Type-Options twice",
        &[
            ("x-content-type-options", "nosniff"),
            ("x-content-type-options", "nosniff"),
        ],
    ),
    (
        "Strict-Transport-Security twice, the first with a quoted comma",
        &[
            ("strict-transport-security", "max-age=31536000; ext=\"a,b\""),
            ("strict-transport-security", "max-age=0"),
        ],
    ),
    (
        "Content-Security-Policy twice",
        &[
            ("content-security-policy", "script-src *; frame-ancestors *"),
            (
                "content-security-policy",
                "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            ),
        ],
    ),
    (
        "a charset on the second Content-Type line",
        &[
            ("content-type", "text/html"),
            ("content-type", "text/html; charset=utf-8"),
        ],
    ),
    (
        "cross-origin isolation headers twice",
        &[
            ("cross-origin-opener-policy", "same-origin"),
            ("cross-origin-opener-policy", "unsafe-none"),
            ("cross-origin-embedder-policy", "require-corp"),
            ("cross-origin-embedder-policy", "unsafe-none"),
            ("cross-origin-resource-policy", "same-site"),
            ("cross-origin-resource-policy", "cross-origin"),
        ],
    ),
    (
        "Access-Control-Allow-Origin and -Credentials twice",
        &[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-origin", "https://example.com"),
            ("access-control-allow-credentials", "true"),
            ("access-control-allow-credentials", "false"),
        ],
    ),
    (
        "a Server comment holding a comma, then a second Server line",
        &[
            ("server", "Apache/2.4.41 (Ubuntu, x64)"),
            ("server", "nginx"),
        ],
    ),
    (
        "Cache-Control over two lines",
        &[
            ("cache-control", "max-age=60"),
            ("cache-control", "no-store"),
        ],
    ),
    (
        "Alt-Svc over two lines",
        &[("alt-svc", "h2=\":443\""), ("alt-svc", "h3=\":443\"")],
    ),
    (
        "X-Powered-By over two lines",
        &[("x-powered-by", "PHP/8.1"), ("x-powered-by", "Express")],
    ),
    (
        "Via over two lines",
        &[
            ("via", "1.1 varnish"),
            ("via", "1.1 abc.cloudfront.net (CloudFront)"),
        ],
    ),
    (
        "X-Generator over two lines",
        &[
            ("x-generator", "Hugo 0.120"),
            ("x-generator", "WordPress 6.4"),
        ],
    ),
    (
        "Referrer-Policy and Permissions-Policy over two lines",
        &[
            ("referrer-policy", "no-referrer"),
            ("referrer-policy", "unsafe-url"),
            ("permissions-policy", "camera=()"),
            ("permissions-policy", "geolocation=()"),
        ],
    ),
    (
        "a report-only policy over two lines",
        &[
            ("content-security-policy-report-only", "script-src 'self'"),
            ("content-security-policy-report-only", "object-src 'none'"),
        ],
    ),
    (
        "Set-Cookie lines whose Expires holds a comma",
        &[
            (
                "set-cookie",
                "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure",
            ),
            ("set-cookie", "b=2; HttpOnly"),
        ],
    ),
];

#[test]
fn every_joined_field_reads_as_its_lines() {
    for (name, pairs) in CASES {
        assert_eq!(
            answer(pairs, HeaderLines::Joined),
            answer(pairs, HeaderLines::Separate),
            "{name}"
        );
    }
}

#[test]
fn a_doubled_strict_transport_security_still_counts_two_fields_when_joined() {
    let pairs = CASES[2].1;
    let rows = answer(pairs, HeaderLines::Joined);
    let hsts = row(&rows, "security.headers.hsts");
    assert_eq!(hsts["rawData"]["header_count"], 2);
}

#[test]
fn a_repeated_list_field_reads_as_its_lines_joined_on_the_desktop_lane() {
    // RFC 9110 section 5.3: a field's lines and their comma-joined value mean the same.
    let two_lines = [
        ("cache-control", "max-age=60"),
        ("cache-control", "no-store"),
    ];
    let one_line = [("cache-control", "max-age=60, no-store")];
    assert_eq!(
        answer(&two_lines, HeaderLines::Separate),
        answer(&one_line, HeaderLines::Separate)
    );
}

#[test]
fn a_csp_line_holding_two_policies_counts_two_on_the_desktop_lane() {
    let one_line = [(
        "content-security-policy",
        "script-src *; frame-ancestors *, script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    )];
    // Equal lane answers can both miss the comma's second policy.
    let rows = answer(&one_line, HeaderLines::Separate);
    assert_eq!(
        row(&rows, "security.headers.csp")["rawData"]["policy_count"],
        2
    );
    assert_eq!(rows, answer(CASES[3].1, HeaderLines::Separate));
}

#[test]
fn a_csp_list_with_only_wildcard_framing_does_not_protect_frames() {
    // Treating a policy separator as a source falsely recognizes wildcard framing as restrictive.
    let pairs = [(
        "content-security-policy",
        "frame-ancestors *, script-src 'self'",
    )];
    let rows = answer(&pairs, HeaderLines::Separate);
    assert_eq!(
        row(&rows, "security.headers.x_frame_options")["status"],
        "warn"
    );
}

#[test]
fn a_non_ascii_line_preserves_the_fields_readable_items_on_both_lanes() {
    // An unreadable line must not erase another line's policy or technology evidence.
    let pairs: Vec<_> = [
        ("cache-control", "no-store"),
        ("content-security-policy", "default-src 'self'"),
        ("referrer-policy", "no-referrer"),
        ("x-powered-by", "PHP/8.1"),
    ]
    .into_iter()
    .flat_map(|(name, value)| [(name, value), (name, "\u{e9}")])
    .collect();
    for lines in [HeaderLines::Separate, HeaderLines::Joined] {
        let rows = answer(&pairs, lines);
        for (check, status, severity) in [
            ("security.headers.csp", "warn", "low"),
            ("security.headers.referrer_policy", "pass", "low"),
            ("security.server_info.x_powered_by", "warn", "low"),
        ] {
            let found = row(&rows, check);
            assert_eq!(
                (found["status"].as_str(), found["severity"].as_str()),
                (Some(status), Some(severity)),
                "{lines:?} {check}"
            );
        }
        let csp = row(&rows, "security.headers.csp");
        assert_ne!(csp["title"], "No enforced Content-Security-Policy");
        assert_eq!(csp["rawData"]["policy_count"], 2);
        assert_eq!(
            row(&rows, "performance.cache")["title"],
            "Cache-Control set to no-store"
        );
        assert_eq!(rows["stack"]["framework"], "PHP");
    }
    assert_eq!(
        answer(&pairs, HeaderLines::Separate),
        answer(&pairs, HeaderLines::Joined)
    );
}

#[test]
fn a_csp_list_ignores_a_policy_without_directives() {
    // A semicolon-only policy has no directives and must not increase the enforced policy count.
    let pairs = [("content-security-policy", "default-src 'self', ;")];
    let rows = answer(&pairs, HeaderLines::Separate);
    assert_eq!(
        row(&rows, "security.headers.csp")["rawData"]["policy_count"],
        1
    );
}

/// A probe response recorded in a session, by the planned probe its check asked for.
fn probe_answer(
    lines: HeaderLines,
    check: &str,
    respond: impl Fn(&str) -> ProbeResponse,
) -> serde_json::Value {
    let mut route = RouteSession::open_with(artifact(Vec::new()), lines).expect("opens");
    route.record(Some(Vec::new()));
    let plan = route.plan();
    let probe = plan
        .probes
        .iter()
        .find(|probe| probe.checks.iter().any(|id| id == check))
        .expect("the check plans a probe");
    let origin = probe
        .request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("origin"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    route.record(Some(vec![ExecutedProbe {
        key: probe.key.clone(),
        outcome: ProbeOutcome::Response(respond(&origin)),
    }]));
    let rows = serde_json::to_value(route.evaluate(&RouteFacts::default()).results).expect("rows");
    rows.as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["checkId"] == check)
        .cloned()
        .collect()
}

#[test]
fn a_probe_response_reads_its_joined_lines_as_the_page_does() {
    let reflection = |lines: HeaderLines| {
        probe_answer(lines, "security.cors_reflection", move |origin| {
            ProbeResponse {
                status: 200,
                final_url: "https://example.com/".into(),
                content_type: Some("text/html".into()),
                content_length: None,
                headers: match lines {
                    HeaderLines::Separate => vec![
                        ("access-control-allow-origin".into(), origin.into()),
                        ("access-control-allow-origin".into(), "*".into()),
                    ],
                    HeaderLines::Joined => {
                        vec![("access-control-allow-origin".into(), format!("{origin}, *"))]
                    }
                },
                body: None,
            }
        })
    };
    assert_eq!(
        reflection(HeaderLines::Joined),
        reflection(HeaderLines::Separate)
    );
    let robots = |lines: HeaderLines| {
        probe_answer(lines, "seo.robots_txt", move |_| ProbeResponse {
            status: 200,
            final_url: "https://example.com/robots.txt".into(),
            content_type: Some(match lines {
                HeaderLines::Separate => "text/plain".into(),
                HeaderLines::Joined => "text/plain, text/html".into(),
            }),
            content_length: None,
            headers: Vec::new(),
            body: Some(ProbeBody {
                text: "User-agent: *\nDisallow:\n".into(),
                bytes: 24,
                utf8_valid: true,
            }),
        })
    };
    assert_eq!(robots(HeaderLines::Joined), robots(HeaderLines::Separate));
}
