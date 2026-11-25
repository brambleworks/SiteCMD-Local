use super::*;
use crate::cli::autofix::github_api::GitHubApi;
use crate::connected_service::test_double::{request_line, respond_during};
use crate::core::project_listing::list_project;

const PATH: &str = "app.js";
const KEEP: &str = "const context = 'unchanged customer code';";
const REMOVE: &str = "const setting = 'old';";
const ADD: &str = "const setting = 'new';";

fn issue(body: &str) -> Brief {
    Brief {
        body: body.into(),
        title: "SiteCMD: Fix a setting".into(),
    }
}

fn input() -> (Listing, HandedLines, Patch) {
    let root = tempfile::tempdir().unwrap();
    let before = format!("{KEEP}\n{REMOVE}\n");
    std::fs::write(root.path().join(PATH), &before).unwrap();
    let listing = list_project(root.path()).unwrap().wire().clone();
    let path = RelPath::parse(PATH).unwrap();
    let mut handed = HandedLines::default();
    handed.record(&path, before.as_bytes());
    handed.record(
        &RelPath::parse("other.js").unwrap(),
        format!("{ADD}\n").as_bytes(),
    );
    let patch = Patch {
        base_sha256: Patch::hash_base(before.as_bytes()),
        path,
        content: format!("{KEEP}\n{ADD}\n"),
    };
    (listing, handed, patch)
}

async fn publish(
    listing: &Listing,
    brief: Brief,
    handed: &HandedLines,
    patches: &[Patch],
) -> (Result<u64, ExitRefusal>, Vec<String>) {
    respond_during(
        vec![(r#"{"number":42}"#.into(), "201 Created")],
        async |origin| {
            let brief = check_publish_brief(listing, brief, handed, patches)?;
            let api = GitHubApi::for_test(&origin).unwrap();
            let number = api
                .create_issue("fake-token", "example/site", &brief)
                .await
                .unwrap();
            Ok(number)
        },
    )
    .await
}

#[tokio::test]
async fn a_brief_quoting_a_handed_line_is_refused_before_any_request() {
    // User code published beyond the fix itself.
    let (listing, handed, _) = input();
    let (outcome, requests) = publish(&listing, issue(&format!("  {KEEP}  ")), &handed, &[]).await;
    assert_eq!((outcome, requests.len()), (Err(ExitRefusal::HandedLine), 0));
}

#[tokio::test]
async fn a_title_quoting_a_handed_line_is_refused_before_any_request() {
    // A title can carry a handed line even when the body is safe.
    let (_, handed, _) = input();
    let brief = Brief {
        title: KEEP.into(),
        ..issue("Update the setting.")
    };
    let (outcome, requests) = respond_during(
        vec![(r#"{"number":42}"#.into(), "201 Created")],
        async |origin| {
            let brief = CheckedBrief::issue(brief, &handed)?;
            let api = GitHubApi::for_test(&origin).unwrap();
            Ok(api
                .create_issue("fake-token", "example/site", &brief)
                .await
                .unwrap())
        },
    )
    .await;
    assert_eq!((outcome, requests.len()), (Err(ExitRefusal::HandedLine), 0));
}

#[tokio::test]
async fn a_pull_request_title_quoting_a_handed_line_is_refused_before_any_request() {
    // The shared pull request title and commit subject can quote unchanged code.
    let titles = [" = ", " =\n", " =\n\u{a0}\n", " =\r\r"]
        .map(|separator| KEEP.replacen(" = ", separator, 1));
    for title in titles {
        let (listing, handed, patch) = input();
        let brief = Brief {
            title: title.clone(),
            ..issue(REMOVE)
        };
        let (outcome, requests) = respond_during(
            vec![(
                r#"{"number":42,"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#.into(),
                "201 Created",
            )],
            async |origin| {
                let brief = check_publish_brief(&listing, brief, &handed, &[patch])?;
                let api = GitHubApi::for_test(&origin).unwrap();
                Ok(api
                    .create_pull_request("fake-token", "example/site", "fix", "main", &brief)
                    .await
                    .unwrap()
                    .number)
            },
        )
        .await;
        assert_eq!(
            (outcome, requests.len()),
            (Err(ExitRefusal::HandedLine), 0),
            "outbound title: {title:?}",
        );
    }
}

#[test]
fn a_redacted_quote_of_a_raw_handed_line_is_refused() {
    // Redaction can hide an exact quote from the handed-line check.
    let mut handed = HandedLines::default();
    let raw = format!("credential glpat-{}", "aB3".repeat(8));
    handed.record_lines(raw.as_bytes());
    for body in [raw.as_str(), "credential glpat-***"] {
        assert_eq!(
            check_brief(issue(body), &handed, &[]),
            Err(ExitRefusal::HandedLine),
            "quoted form: {body}",
        );
    }
}

#[test]
fn a_quote_between_lone_carriage_returns_is_refused() {
    // CommonMark recognizes bare carriage returns around a quoted line.
    let (_, handed, _) = input();
    assert_eq!(
        check_brief(issue(&format!("x\r{KEEP}\ry")), &handed, &[]),
        Err(ExitRefusal::HandedLine),
    );
}

#[test]
fn a_quote_from_a_carriage_return_delimited_file_is_refused() {
    // A bare carriage return can hide a handed line inside a file answer.
    let mut handed = HandedLines::default();
    handed.record_lines(format!("x\r{KEEP}\ry\r").as_bytes());
    assert_eq!(
        check_brief(issue(KEEP), &handed, &[]),
        Err(ExitRefusal::HandedLine),
    );
}

#[test]
fn equivalent_line_formats_are_refused_on_either_side() {
    // Formatting and invisible characters can disguise an exact quote.
    let plain = "const setting = 'unchanged';";
    let formats = [
        ("blockquote", "> const setting = 'unchanged';"),
        ("dash list", "- const setting = 'unchanged';"),
        ("asterisk list", "* const setting = 'unchanged';"),
        ("plus list", "+ const setting = 'unchanged';"),
        ("ordered list", "1. const setting = 'unchanged';"),
        ("inline code", "`const setting = 'unchanged';`"),
        ("HTML comment", "<!-- const setting = 'unchanged'; -->"),
        ("HTML comment opener", "<!-- const setting = 'unchanged';"),
        ("HTML comment closer", "const setting = 'unchanged'; -->"),
        ("whitespace", "const  setting\t=   'unchanged';"),
        (
            "zero-width characters",
            "const se\u{200b}t\u{200c}t\u{200d}in\u{2060}g = 'unchanged';",
        ),
        ("byte-order mark", "\u{feff}const setting = 'unchanged';"),
        ("NFKC", "const \u{ff53}etting = 'unchanged';"),
        (
            "nested markers",
            "> - `<!-- const setting = 'unchanged'; -->`",
        ),
    ];
    let failures: Vec<_> = formats
        .into_iter()
        .filter(|(_, formatted)| {
            [(plain, *formatted), (*formatted, plain)]
                .into_iter()
                .any(|(source, body)| {
                    let mut handed = HandedLines::default();
                    handed.record_lines(source.as_bytes());
                    check_brief(issue(body), &handed, &[]) != Err(ExitRefusal::HandedLine)
                })
        })
        .map(|(format, _)| format)
        .collect();
    assert!(failures.is_empty(), "formats that escaped: {failures:?}");
}

#[test]
fn formatted_and_embedded_handed_lines_are_refused() {
    // Markdown, Unicode, and surrounding text can hide a same-line quote.
    let plain = "const setting = 'unchanged';";
    let embedded = [
        ("backtick fence info", "```const setting = 'unchanged';"),
        ("tilde fence info", "~~~ const setting = 'unchanged';"),
        ("heading", "# const setting = 'unchanged';"),
        ("subheading", "### const setting = 'unchanged';"),
        ("task list", "- [ ] const setting = 'unchanged';"),
        ("table cell", "| const setting = 'unchanged'; |"),
        ("link text", "[const setting = 'unchanged';](#location)"),
        ("trailing escape", "const setting = 'unchanged';\\"),
        (
            "same-line prose",
            "The file sets `const setting = 'unchanged';` today.",
        ),
    ];
    let equivalent = [
        ("bold", "const **setting** = 'unchanged';"),
        ("asterisk emphasis", "const *setting* = 'unchanged';"),
        ("underscore emphasis", "const _setting_ = 'unchanged';"),
        ("strikethrough", "const ~~setting~~ = 'unchanged';"),
        ("decimal entity", "const setting = &#39;unchanged&#39;;"),
        ("hex entity", "const setting = &#x27;unchanged&#X27;;"),
        ("HTML code", "const <code>setting</code> = 'unchanged';"),
        ("escape", "const setting = \\'unchanged\\';"),
        ("variation selector", "const se\u{fe0f}tting = 'unchanged';"),
        ("tag character", "const se\u{e0041}tting = 'unchanged';"),
        (
            "Hangul filler as a space",
            "const\u{3164}setting = 'unchanged';",
        ),
        (
            "Hangul filler within a word",
            "const se\u{3164}tting = 'unchanged';",
        ),
        ("curly quotes", "const setting = \u{2018}unchanged\u{2019};"),
        ("Cyrillic e", "const s\u{0435}tting = 'unchanged';"),
        ("NUL", "const setting\u{0} = 'unchanged';"),
        (
            "line separator",
            "Context\u{2028}const setting = 'unchanged';",
        ),
        ("next line", "Context\u{85}const setting = 'unchanged';"),
        ("form feed", "Context\u{c}const setting = 'unchanged';"),
    ];
    let refusals = |source: &str, body| {
        let mut handed = HandedLines::default();
        handed.record_lines(source.as_bytes());
        check_brief(issue(body), &handed, &[]) == Err(ExitRefusal::HandedLine)
    };
    let escaped: Vec<_> =
        embedded
            .into_iter()
            .filter(|(_, formatted)| !refusals(plain, formatted))
            .chain(equivalent.into_iter().filter(|(_, formatted)| {
                !refusals(plain, formatted) || !refusals(formatted, plain)
            }))
            .map(|(format, _)| format)
            .chain(
                (!refusals(
                    r#"const markup = "<a>&</a>";"#,
                    "const markup = &quot;&lt;a&gt;&amp;&lt;/a&gt;&quot;;",
                ))
                .then_some("named entities"),
            )
            .collect();
    assert!(escaped.is_empty(), "formats that escaped: {escaped:?}");
}

#[test]
fn only_long_handed_lines_match_inside_other_text() {
    // Exact matching misses embedded quotes, and short substrings collide with prose.
    let mut handed = HandedLines::default();
    let short = "abcdefghijklnopqrstuvwx";
    let long = "abcdefghijklnopqrstuvwxy";
    handed.record_lines(format!("{short}\n{long}").as_bytes());
    let short_in_prose = issue(&format!("prefix {short} suffix"));
    assert_eq!(
        check_brief(short_in_prose.clone(), &handed, &[]),
        Ok(short_in_prose)
    );
    for body in [short.to_string(), format!("prefix {long} suffix")] {
        assert_eq!(
            check_brief(issue(&body), &handed, &[]),
            Err(ExitRefusal::HandedLine)
        );
    }
}

#[test]
fn fixed_renderer_lines_are_exempt_only_as_written() {
    // A checkout may have the same headings as the rendered brief.
    let mut handed = HandedLines::default();
    handed.record_lines(b"## How to fix\nPlease rotate this customer credential.\n");
    let fixed = issue("## How to fix\n\nUpdate the setting.");
    assert_eq!(check_brief(fixed.clone(), &handed, &[]), Ok(fixed));
    for body in [
        "### How to fix",
        "## How to fix\nPlease rotate this customer credential.",
    ] {
        assert_eq!(
            check_brief(issue(body), &handed, &[]),
            Err(ExitRefusal::HandedLine)
        );
    }
}

#[test]
fn the_whole_title_is_checked_across_paragraph_breaks() {
    // Git folds only the first paragraph, while GitHub receives the whole title.
    let (_, handed, _) = input();
    let brief = Brief {
        title: KEEP.replacen(" = ", " =\n\n", 1),
        ..issue("Update the setting.")
    };
    assert_eq!(
        check_brief(brief, &handed, &[]),
        Err(ExitRefusal::HandedLine)
    );
}

#[test]
fn provider_tokens_are_masked_and_masked_quotes_refused() {
    // An unmasked provider token can leave in a title or body and evade quote comparison.
    let raw = format!("customer credential: npm_{}", "aB3".repeat(12));
    let masked = "customer credential: npm_***";
    let brief = Brief {
        title: raw.clone(),
        body: raw.clone(),
    };
    let redacted = check_brief(brief, &HandedLines::default(), &[]).unwrap();
    assert_eq!(
        (redacted.title.as_str(), redacted.body.as_str()),
        (masked, masked)
    );
    let mut handed = HandedLines::default();
    handed.record_lines(raw.as_bytes());
    assert_eq!(
        check_brief(issue(masked), &handed, &[]),
        Err(ExitRefusal::HandedLine)
    );
}

#[test]
fn lines_that_are_trivial_after_normalization_do_not_count() {
    // Markdown wrappers and full-width punctuation can make trivial lines look significant.
    let mut handed = HandedLines::default();
    let brief = issue("> `\u{ff5d};`\n<!-- -->");
    handed.record_lines(brief.body.as_bytes());
    assert_eq!(check_brief(brief.clone(), &handed, &[]), Ok(brief));
}

#[test]
fn long_punctuation_lines_do_not_count() {
    // A trivial line can be long enough to share a shingle with source code.
    let punctuation = "}".repeat(24);
    let mut handed = HandedLines::default();
    handed.record_lines(format!("const example = '{punctuation}';").as_bytes());
    let brief = issue(&punctuation);
    assert_eq!(check_brief(brief.clone(), &handed, &[]), Ok(brief));
}

#[tokio::test]
async fn a_brief_quoting_only_patch_lines_publishes() {
    // User code published beyond the fix itself.
    let (listing, handed, patch) = input();
    let body = format!("{REMOVE}\n{ADD}");
    let (outcome, requests) = publish(
        &listing,
        issue(&body),
        &handed,
        std::slice::from_ref(&patch),
    )
    .await;
    assert_eq!((outcome, requests.len()), (Ok(42), 1));
    assert_eq!(
        request_line(&requests[0]),
        "POST /repos/example/site/issues HTTP/1.1"
    );
    let payload: serde_json::Value =
        serde_json::from_str(requests[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(payload["body"], body);

    let (outcome, requests) = publish(&listing, issue(KEEP), &handed, &[patch]).await;
    assert_eq!((outcome, requests.len()), (Err(ExitRefusal::HandedLine), 0));
}

#[test]
fn trivial_lines_do_not_count() {
    // User code published beyond the fix itself.
    let mut handed = HandedLines::default();
    let trivial = "\n  \t\n  });\n  [{()}],;\n";
    handed.record(
        &RelPath::parse(PATH).unwrap(),
        format!("{trivial};\n  {KEEP}\n").as_bytes(),
    );
    let brief = issue(trivial);
    assert_eq!(check_brief(brief.clone(), &handed, &[]), Ok(brief));
    assert_eq!(
        check_brief(issue(&format!("{trivial}{KEEP}")), &handed, &[]),
        Err(ExitRefusal::HandedLine),
    );
}

#[tokio::test]
async fn a_patch_outside_the_listing_stops_the_publish() {
    // User code published beyond the fix itself.
    let (listing, handed, mut patch) = input();
    patch.path = RelPath::parse("other.js").unwrap();
    let (outcome, requests) =
        publish(&listing, issue("Update the setting."), &handed, &[patch]).await;
    assert_eq!(
        (outcome, requests.len()),
        (Err(ExitRefusal::PatchOutsideListing), 0)
    );
}

#[test]
fn the_brief_is_redacted_before_the_check() {
    // User code published beyond the fix itself.
    let mut handed = HandedLines::default();
    let raw = format!("credential glpat-{}", "aB3".repeat(8));
    let masked = "credential glpat-***";
    handed.record(&RelPath::parse(PATH).unwrap(), masked.as_bytes());
    assert_eq!(
        check_brief(issue(&raw), &handed, &[]),
        Err(ExitRefusal::HandedLine)
    );
    let brief = Brief {
        title: raw.clone(),
        body: format!("{raw}\nowner@example.com"),
    };
    let sanitized = check_brief(brief, &HandedLines::default(), &[]).unwrap();
    assert_eq!(sanitized.title, masked);
    assert_eq!(sanitized.body, format!("{masked}\n[email]"));
}

#[path = "exit_check_shingle_tests.rs"]
mod shingle_tests;

#[test]
fn standin_corpus_refuses_handed_lines() {
    // Bug: A guest can quote a file handed to it when rendering a brief.
    use sitecmd_protocol::engine_abi::{BriefTarget, Done, Task};

    if sitecmd_engine_host::load().unwrap().info().module_version != "standin" {
        return;
    }
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/engine-host/standin/corpus.json"
    ))
    .unwrap();
    let case = &corpus["quote"];
    let path = case["path"].as_str().unwrap();
    let line = case["line"].as_str().unwrap();
    assert_eq!(case["refusal"], "handed_line");

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(path), format!("{line}\n")).unwrap();
    let project = list_project(root.path()).unwrap();
    let target: BriefTarget = serde_json::from_value(serde_json::json!({
        "agent": "fixture", "attempt": 1, "check_id": "standin.rule", "description": "",
        "detected_stack": null, "likely_fix": null, "locations": [], "severity": "low",
        "site_url": "https://example.test", "title": "", "why_now": null
    }))
    .unwrap();
    let mut handed = HandedLines::default();
    let result = crate::core::fixes::request_with_file(
        Task::Brief { target },
        Some(&project),
        |path, bytes| handed.record(path, bytes),
    )
    .unwrap();
    let Done::Brief(brief) = result else {
        panic!("missing quoted brief");
    };
    assert_eq!(brief.body, line);
    assert!(matches!(
        check_publish_brief(project.wire(), brief, &handed, &[]),
        Err(ExitRefusal::HandedLine)
    ));
}
