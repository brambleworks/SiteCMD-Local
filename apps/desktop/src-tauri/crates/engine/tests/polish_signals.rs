//! A moved signal grades differently, a polish id has no manifest row or runner, or a hosted runner grades what the CLI does not.
//!
//! The pages are every page the polish unit tests build and three hand-written
//! synthetic pages. Regenerate the golden only after an intentional verdict
//! change, with `cargo test -p sitecmd-engine --test polish_signals -- --ignored regenerate`.

use regex::Regex;
use sha2::{Digest, Sha256};
use sitecmd_engine::checks::polish::{
    css_architecture, polish_check_result, run_all_signals, PolishContext, POLISH_SIGNALS,
};
use sitecmd_engine::evaluation::{
    evaluate, EvaluationRequest, PageArtifact, POLISH_RUNNERS, RUNNERS, SEO_RUNNERS,
};
use sitecmd_engine::manifest::{capability_manifest, CheckScope, HostedLane};

const UNIT_PAGES: &str = include_str!("fixtures/polish/unit_pages.jsonl");
const GOLDEN: &str = include_str!("fixtures/polish/golden.jsonl");
const SYNTHETIC_PAGES: [(&str, &str, &str); 3] = [
    (
        "marketing home",
        "https://cedar.invalid/",
        include_str!("fixtures/polish/marketing_home.html"),
    ),
    (
        "docs page",
        "https://cedar.invalid/handbook/first-notebook",
        include_str!("fixtures/polish/docs_page.html"),
    ),
    (
        "tool home",
        "https://pebble.invalid/",
        include_str!("fixtures/polish/tool_home.html"),
    ),
];

const SYNTHETIC_SHA256: [&str; 3] = [
    "2c3c4c5c88953d12a063e7d833d18cab872ea096b008763c5b0018208b3775cf",
    "e0b2915a462c1cc1518fcf60c205dd61e1cf079ae4446285f7d8047267a4d25d",
    "54cd8c44e0d87591ea51fab79dfd05d0b3f33936f530be327b0cbcfe5b9f4142",
];

#[test]
fn synthetic_pages_use_reserved_hosts_and_keep_their_page_shapes() {
    for (_, url, _) in SYNTHETIC_PAGES {
        assert!(url::Url::parse(url)
            .unwrap()
            .host_str()
            .unwrap()
            .ends_with(".invalid"));
    }
    let marketing = SYNTHETIC_PAGES[0].2;
    assert!(marketing.contains("<section"));
    assert!(marketing.contains("<h2"));
    assert!(marketing.contains("rel=\"stylesheet\""));
    let docs = SYNTHETIC_PAGES[1].2;
    assert!(docs.contains("<aside"));
    assert!(docs.contains("<article"));
    assert!(docs.contains("<pre><code>"));
    let tool = SYNTHETIC_PAGES[2].2;
    assert!(tool.contains("<form"));
    assert!(tool.contains("<label"));
    assert!(tool.contains("<output"));
}

#[test]
fn synthetic_pages_keep_their_exact_bytes() {
    for ((name, _, html), expected) in SYNTHETIC_PAGES.iter().zip(SYNTHETIC_SHA256) {
        assert_eq!(
            hex::encode(Sha256::digest(html.as_bytes())),
            expected,
            "{name}"
        );
    }
}

#[test]
fn synthetic_pages_keep_representative_signal_outcomes() {
    for ((name, url, html), expected) in SYNTHETIC_PAGES.into_iter().zip([
        vec![("eyebrow-labels", serde_json::json!({"count": 8}))],
        vec![],
        vec![(
            "no-sitemap-robots",
            serde_json::json!({
                "has_canonical": false, "has_robots_meta": false, "has_sitemap_link": false
            }),
        )],
    ]) {
        let page = Page {
            name: name.into(),
            url: url.into(),
            html: html.into(),
            css: String::new(),
        };
        let results = run_all_signals(&context(&page, ""));
        let fired: Vec<_> = results
            .iter()
            .filter(|row| row.fired)
            .map(|row| (row.id.as_str(), row.data.clone()))
            .collect();
        assert_eq!(fired, expected, "{name}");
    }
}

#[test]
fn no_css_architecture_has_a_revision_for_its_current_markers() {
    let entry = sitecmd_engine::manifest::registry::entries()
        .find(|entry| entry.check == "polish.no-css-architecture")
        .unwrap();
    assert_eq!(entry.revision, 2);
}

/// Stylesheet text carrying every CSS-in-JS marker the no-CSS signal reads.
const MARKER_CSS: &str = ".sc-a{} .css-b{} .emotion-c{} .jss1{} /* makeStyles */";

struct Page {
    name: String,
    url: String,
    html: String,
    css: String,
}

fn pages() -> Vec<Page> {
    let mut pages: Vec<Page> = UNIT_PAGES
        .lines()
        .map(|line| {
            let case: serde_json::Value = serde_json::from_str(line).expect("page line parses");
            let field = |key: &str| case[key].as_str().expect("string field").to_string();
            Page {
                name: field("name"),
                url: field("url"),
                html: field("html"),
                css: field("css"),
            }
        })
        .collect();
    for (name, url, html) in SYNTHETIC_PAGES {
        pages.push(Page {
            name: name.into(),
            url: url.into(),
            html: html.into(),
            css: String::new(),
        });
    }
    pages
}

fn context(page: &Page, css: &str) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse(&page.url).expect("fixture url parses"),
        page.html.clone().into(),
        sitecmd_engine::checks::polish::css_signal_counts(
            css,
            sitecmd_engine::checks::polish::CssTextKind::Stylesheet,
        ),
    )
}

fn golden() -> Vec<(String, serde_json::Value)> {
    GOLDEN
        .lines()
        .map(|line| {
            let case: serde_json::Value = serde_json::from_str(line).expect("golden line parses");
            let name = case["name"].as_str().expect("case name").to_string();
            (name, case["expected"].clone())
        })
        .collect()
}

fn request(page: &Page) -> EvaluationRequest {
    EvaluationRequest {
        page: PageArtifact {
            url: page.url.clone(),
            requested_url: Some(page.url.clone()),
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: page.html.clone(),
            evaluation_time: "2026-10-30T00:00:00Z".parse().expect("static time"),
        },
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        negotiated_protocol: None,
        probe_outcomes: None,
        browser_facts: None,
    }
}

#[test]
fn every_page_grades_as_its_golden() {
    let pages = pages();
    let golden = golden();
    assert_eq!(pages.len(), golden.len(), "one golden case per page");
    let mut differs = Vec::new();
    for (page, (name, expected)) in pages.iter().zip(&golden) {
        assert_eq!(&page.name, name, "golden cases follow page order");
        let results = run_all_signals(&context(page, &page.css));
        let actual = serde_json::to_value(&results).expect("results serialize");
        if &actual != expected {
            differs.push(name.clone());
        }
    }
    assert!(differs.is_empty(), "pages grading differently: {differs:?}");
}

#[test]
fn each_page_only_runner_grades_what_the_cli_grades_with_no_stylesheets() {
    for page in pages() {
        let response = evaluate(&request(&page)).expect("page evaluates");
        let hosted: Vec<serde_json::Value> = response
            .results
            .iter()
            .filter(|row| row.check_id.starts_with("polish."))
            .map(|row| serde_json::to_value(row).expect("row serializes"))
            .collect();
        let ctx = context(&page, "");
        let cli: Vec<serde_json::Value> = POLISH_SIGNALS
            .iter()
            .filter(|signal| !signal.reads_stylesheets)
            .map(|signal| serde_json::to_value(polish_check_result(&(signal.run)(&ctx))))
            .collect::<Result<_, _>>()
            .expect("rows serialize");
        assert_eq!(hosted, cli, "{}", page.name);
    }
}

#[test]
fn no_css_architecture_is_one_verdict_with_and_without_the_linked_css() {
    let linked = Regex::new(r#"(?i)<link\b[^>]*\brel\s*=\s*["']?stylesheet"#).expect("regex");
    let mut pages = pages();
    for (name, html) in [
        (
            "href first",
            r#"<link href="/a.css" rel="stylesheet"><p>x</p>"#,
        ),
        (
            "single quotes",
            "<LINK REL='stylesheet' HREF='/a.css'><p>x</p>",
        ),
        ("no stylesheet", "<p>unstyled</p>"),
    ] {
        pages.push(Page {
            name: name.into(),
            url: "https://example.com/".into(),
            html: html.into(),
            css: String::new(),
        });
    }
    for page in pages {
        let css = if !page.css.is_empty() {
            page.css.clone()
        } else if linked.is_match(&page.html) {
            MARKER_CSS.to_string()
        } else {
            // A page that links no stylesheet has no stylesheet to fetch.
            String::new()
        };
        let without = css_architecture::no_css_architecture(&context(&page, ""));
        let with = css_architecture::no_css_architecture(&context(&page, &css));
        assert_eq!(
            serde_json::to_value(&without).expect("serializes"),
            serde_json::to_value(&with).expect("serializes"),
            "{}",
            page.name
        );
    }
}

#[test]
fn every_polish_signal_has_one_manifest_row_and_each_artifact_row_one_runner() {
    let manifest = capability_manifest();
    for signal in POLISH_SIGNALS {
        let check = format!("polish.{}", signal.id);
        let rows: Vec<_> = manifest
            .entries
            .iter()
            .filter(|entry| entry.check == check)
            .collect();
        assert_eq!(rows.len(), 1, "{check} has one manifest row");
        let (lane, scope) = if signal.reads_stylesheets {
            (HostedLane::ProbeAdapter, CheckScope::Origin)
        } else {
            (HostedLane::Artifact, CheckScope::Page)
        };
        assert_eq!((rows[0].hosted, rows[0].scope), (lane, scope), "{check}");
    }
    let runners: Vec<&str> = RUNNERS
        .iter()
        .chain(SEO_RUNNERS)
        .chain(POLISH_RUNNERS)
        .flat_map(|runner| runner.covers.iter().copied())
        .collect();
    for entry in manifest
        .entries
        .iter()
        .filter(|entry| entry.check.starts_with("polish.") && entry.hosted == HostedLane::Artifact)
    {
        let claims = runners.iter().filter(|id| **id == entry.check).count();
        assert_eq!(claims, 1, "{} has one runner", entry.check);
    }
    for runner in POLISH_RUNNERS {
        assert_eq!(runner.covers.len(), 1, "a polish runner covers one signal");
    }
}

// Rewrites the golden from the current signals; run only after an intentional
// verdict change. Non-ASCII is escaped so the file stays plain ASCII.
#[test]
#[ignore]
fn regenerate() {
    let mut out = String::new();
    for page in pages() {
        let case = serde_json::json!({
            "name": page.name,
            "expected": run_all_signals(&context(&page, &page.css)),
        });
        let line = serde_json::to_string(&case).expect("case serializes");
        for c in line.chars() {
            if c.is_ascii() {
                out.push(c);
            } else {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
        out.push('\n');
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/polish/golden.jsonl"
    );
    std::fs::write(path, out).expect("write golden.jsonl");
}
