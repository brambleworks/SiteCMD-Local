//! Generic inputs and assertions shared by redaction consumers.

use base64::Engine;
use std::cell::Cell;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

thread_local! {
    static REDACTION_WORK: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn count_redaction_work(work: usize) {
    REDACTION_WORK.with(|counter| {
        if let Some(total) = counter.get() {
            counter.set(Some(total + work));
        }
    });
}

pub fn measure_redaction_work(redact: fn(&str) -> String, input: &str) -> usize {
    const HANG_BACKSTOP: Duration = Duration::from_secs(120);
    let (sender, receiver) = mpsc::channel();
    let input = input.to_owned();
    let worker = std::thread::spawn(move || {
        let work = REDACTION_WORK.with(|counter| {
            assert!(counter.replace(Some(0)).is_none());
            std::hint::black_box(redact(&input));
            counter.take().unwrap()
        });
        let _ = sender.send(work);
    });
    match receiver.recv_timeout(HANG_BACKSTOP) {
        Ok(work) => {
            worker.join().unwrap();
            work
        }
        Err(RecvTimeoutError::Timeout) => {
            panic!("redaction did not finish within {HANG_BACKSTOP:?}")
        }
        Err(RecvTimeoutError::Disconnected) => {
            worker.join().unwrap();
            unreachable!("redaction worker exited without reporting work");
        }
    }
}

pub fn assert_redaction_work_linear(
    redact: fn(&str) -> String,
    name: &str,
    field: &str,
    sources: &[String; 2],
) {
    let [small, large] = sources
        .each_ref()
        .map(|input| measure_redaction_work(redact, input));
    assert!(
        small > 0 && large > small,
        "{field} {name} measured {small} and {large}"
    );
    assert!(
        large < small * 8,
        "{field} {name} work grew from {small} to {large} with four times the input"
    );
}

pub fn basic_credential_routes() -> Vec<String> {
    let routes: Vec<String> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/sync/basic-credential-cases.json"
    ))
    .unwrap();
    assert_eq!(routes.len(), 525);
    routes
}

pub fn visit_basic_separator_cases(mut visit: impl FnMut(&str, &str, &str)) {
    for separator in [
        "\t", "\n", "\u{b}", "\u{c}", "\r", " ", "\r\n ", "\u{85}", "\u{a0}", "\u{1680}",
        "\u{2000}", "\u{2001}", "\u{2002}", "\u{2003}", "\u{2004}", "\u{2005}", "\u{2006}",
        "\u{2007}", "\u{2008}", "\u{2009}", "\u{200a}", "\u{2028}", "\u{2029}", "\u{202f}",
        "\u{205f}", "\u{3000}", "\u{feff}", "%09", "%0A", "%0a", "%0B", "%0C", "%0D", "%20", "+",
        "++",
    ] {
        for neighbor in ["", "é", "密钥"] {
            let source = format!("{neighbor}Basic{separator}dXNlcjpwYXNz");
            let encoded: String = url::form_urlencoded::byte_serialize(source.as_bytes()).collect();
            visit(
                &source,
                &format!("{neighbor}Basic{separator}***"),
                &format!("/share/{encoded}"),
            );
        }
    }
}

pub fn visit_short_basic_cases(mut visit: impl FnMut(&str, &str)) {
    for (source, expected) in [
        ("Basic +Basic dXNlcjpwYXNz", "Basic +Basic ***"),
        ("Basic a=Basic dXNlcjpwYXNz", "Basic a=Basic ***"),
        (
            "Authorization: Basic /Basic dXNlcjpwYXNzMQ==",
            "Authorization: Basic /Basic ***",
        ),
        ("Basic ab=Basic dXNlcjpwYXNz", "Basic ab=Basic ***"),
    ] {
        for neighbor in ["", "é", "密钥"] {
            let source = format!("{neighbor}{source}");
            let expected = format!("{neighbor}{expected}");
            visit(&source, &expected);
        }
    }
}

pub fn visit_short_basic_routes(source: &str, mut visit: impl FnMut(&str)) {
    let encoded: String = url::form_urlencoded::byte_serialize(source.as_bytes()).collect();
    for encoded in [encoded.replace('+', "%20"), encoded] {
        visit(&format!("/share/{encoded}"));
    }
}

pub fn visit_seeded_paths(mut visit: impl FnMut(usize, &str)) {
    let mut seed = 0x63e2_819c_74ba_f905_u64;
    let mut random = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as usize % bound
    };
    let atoms = [
        r"\",
        "/",
        "%",
        "@",
        ":",
        "user:pass@db",
        "a:b@c",
        "123-45-6789",
        "%252525252541",
        "%2F",
        "%40",
        "Basic+",
        "dXNlcjpwYXNz",
        "é",
        "密钥",
        " ",
        "docs",
        "x",
        "https:",
        r"\/",
        "\n",
        "\u{a0}",
    ];
    for case in 0..3072 {
        let mut source = String::new();
        for _ in 0..1 + random(10) {
            source.push_str(atoms[random(atoms.len())]);
        }
        let source = match random(4) {
            0 => format!(r"/\host/{source}/user:pass@db"),
            1 => format!("/{source}"),
            2 => format!("see {source} now"),
            _ => format!(r#"<a href="/{source}">link</a>"#),
        };
        visit(case, &source);
    }
}

pub fn visit_social_security_routes(mut visit: impl FnMut(&str)) {
    for code_point in [0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212] {
        let separator = char::from_u32(code_point).unwrap();
        let mut value = format!("123{separator}45{separator}6789");
        for _ in 0..4 {
            let route = format!("/record/{value}");
            visit(&route);
            value = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
        }
    }
}

pub const BACKSLASH_REFERENCES: [&str; 7] = [
    r"/\/host\/a\/user:pass@db",
    r"/\host/x/a:b@c",
    r"see /\evil.example/x/123-45-6789 now",
    r"<a href=/\host/%252525252541>",
    r#"{"u":"https:\/\/host\/r\/123-45-6789"}"#,
    r#"{"u":"https:\/\/host\/x\/user:pass@db"}"#,
    r"error fetching https:\/\/cdn.example\/a%252525252541",
];

pub fn visit_compatibility_credentials(mut visit: impl FnMut(&str)) {
    for value in [
        "sk-ant-abcdefghijklmnopqrstuv",
        "aB7cD9eF2gH4iJ6kL8mN0pQ2rS4tU6vW",
    ] {
        let token: String = value
            .chars()
            .map(|ch| char::from_u32(ch as u32 + 0xfee0).expect("fullwidth code point"))
            .collect();
        let mut route = format!("/share/{token}");
        for _ in 0..4 {
            visit(&route);
            route = route
                .split('/')
                .map(|segment| {
                    url::form_urlencoded::byte_serialize(segment.as_bytes()).collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("/");
        }
    }
}

pub fn visit_deep_escapes(mut visit: impl FnMut(&str, &str)) {
    for tail in ["41", "68%66%5FAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"] {
        let value = format!("%{}{tail}", "25".repeat(20));
        let route = format!("/docs/{value}");
        visit(&route, &value);
    }
}

pub fn visit_nested_separator_credentials(mut visit: impl FnMut(&str)) {
    let mut token = "sk-ant-abcdefghijklmnopqrstuv".to_owned();
    for _ in 0..5 {
        let route = format!("/share/{token}");
        visit(&route);
        token = token.replace('%', "%25").replace('-', "%2D");
    }
}

pub fn visit_opaque_runs_and_credentials(mut visit: impl FnMut(&str, &str, bool)) {
    for token in [
        "aB7cD9eF2gH4iJ6kL8mN0pQ2rS4tU6vW",
        "YWxpY2U6c3VwZXItc2VjcmV0LXBhc3N3b3Jk",
        "550e8400-e29b-41d4-a716-446655440000",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    ] {
        let mut encoded = token.to_owned();
        for _ in 0..4 {
            let route = format!("/share/{encoded}");
            visit(&route, &encoded, true);
            encoded = encoded.bytes().map(|byte| format!("%{byte:02X}")).collect();
        }
    }
    let github_fixture = format!("ghp_{}", "testfixture0".repeat(3));
    for token in ["sk-ant-abcdefghijklmnopqrstuv", github_fixture.as_str()] {
        let mut encoded = token.to_owned();
        for _ in 0..4 {
            let route = format!("/share/{encoded}");
            visit(&route, &encoded, false);
            encoded = encoded.bytes().map(|byte| format!("%{byte:02X}")).collect();
        }
    }
}

pub fn visit_unusual_social_security_routes(mut visit: impl FnMut(&str)) {
    for point in [0x00ad, 0x2027, 0x2043, 0x2e3a, 0x30fc] {
        let separator = char::from_u32(point).unwrap();
        let mut encoded = format!("123{separator}45{separator}6789");
        for _ in 0..4 {
            let route = format!("/record/{encoded}");
            visit(&route);
            encoded = encoded.replace('%', "%25").replace(
                separator,
                &url::form_urlencoded::byte_serialize(separator.to_string().as_bytes())
                    .collect::<String>(),
            );
        }
    }
}

pub fn visit_version_shaped_emails(mut visit: impl FnMut(&str)) {
    for email in VERSION_SHAPED_EMAILS {
        let mut encoded = email.to_owned();
        for _ in 0..4 {
            let route = format!("/u/{encoded}");
            visit(&route);
            encoded = encoded.replace('%', "%25").replace('@', "%40");
        }
    }
}

pub fn visit_word_slugs(mut visit: impl FnMut(&str)) {
    for path in [
        "/ru/новости",
        "/zh/新闻/最新",
        "/ar/أخبار",
        "/wiki/2024_United_States_presidential_election",
        "/wiki/2024_United_States_presidential_election_٢٠٢٤",
        "/wiki/List_of_Apollo_11_mission_crew_members",
        "/docs/Unicode letters and 2024 words",
        "/docs/letter.words.2024.and.more.letter.words",
        "/x/日本語のページ",
        "/x/समाचार",
        "/x/ข่าว",
    ] {
        let mut route = path.to_owned();
        for _ in 0..4 {
            visit(&route);
            route = route
                .split('/')
                .map(|segment| {
                    url::form_urlencoded::byte_serialize(segment.as_bytes())
                        .collect::<String>()
                        .replace('+', "%20")
                })
                .collect::<Vec<_>>()
                .join("/");
        }
    }
}

pub(super) const VERSION_SHAPED_EMAILS: [&str; 2] = ["info@24-7.com", "support@123-reg.co.uk"];

pub fn generic_linear_bound_cases() -> [(&'static str, [String; 2]); 11] {
    let sizes = [64 * 1024, 256 * 1024];
    let repeated = |field: &str| sizes.map(|size| field.repeat(size / field.len()));
    let supplied = basic_credential_routes()
        .iter()
        .map(|route| format!("https://example.com{route} "))
        .collect::<String>();
    let pem = format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        "PRIVATE KEY",
        "aB3+".repeat(16),
        "PRIVATE KEY"
    );
    let basic = format!(
        "Authorization: Basic {} ",
        base64::engine::general_purpose::STANDARD.encode(["user", ":pass"].concat())
    );
    let bearer = format!("Bearer {} ", ["9f8e7d", "6c5b4a"].concat());
    let userinfo = format!("://{}@h ", ["9f8e7d", "6c5b4a"].concat());
    let mcp = format!("service_sk-ant-{} ", "aB3".repeat(8));
    let url_and_mcp = format!("https://example.com/asset {mcp}");
    [
        ("basic", repeated(&basic)),
        ("bearer", repeated(&bearer)),
        ("userinfo", repeated(&userinfo)),
        (
            "long-basic-body",
            sizes.map(|size| {
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("user:{}", "p".repeat(size)))
                )
            }),
        ),
        (
            "repeated-basic-delimiter",
            sizes.map(|size| format!("Basic {}", "+Basic+".repeat(size / 7))),
        ),
        ("pem", repeated(&pem)),
        (
            "nested-escape-url",
            sizes.map(|size| format!("see https://example.com/x/%{}41 now", "25".repeat(size / 2))),
        ),
        (
            "overlapping-basic-url",
            sizes.map(|size| {
                format!(
                    "https://example.com/docs/Basic+{}%2BBasic+dXNlcjpwYXNz",
                    "x".repeat(size)
                )
            }),
        ),
        ("basic-route-corpus", repeated(&supplied)),
        ("embedded-mcp", repeated(&mcp)),
        ("mcp-url-ranges", repeated(&url_and_mcp)),
    ]
}
