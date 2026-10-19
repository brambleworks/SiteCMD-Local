use super::*;

fn unsafe_php_output_reports(source: &str) -> bool {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "templates/link.php", source);
    audit_project(temp.path())
        .unwrap()
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("unsafe-html:templates/link.php:"))
}

#[test]
fn php_output_after_url_path_words_is_a_live_sink() {
    let missing = [
        r#"<a href="/print/<?= $_GET['id'] ?>">Print</a>"#,
        r#"<a href="/print?id=<?php echo $_GET['id']; ?>">Print</a>"#,
        r#"<a href="/echo/<?= $_GET['id'] ?>">Print</a>"#,
        r#"<a href="/echo?id=<?php echo $_GET['id']; ?>">Print</a>"#,
    ]
    .into_iter()
    .filter(|source| !unsafe_php_output_reports(source))
    .collect::<Vec<_>>();
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn quoted_output_words_do_not_hide_later_php_sinks() {
    let missing = [
        r#"<a href="print.php?id=<?= $_GET['id'] ?>">Print</a>"#,
        r#"<a href="print.php?id=<?php echo $_GET['id']; ?>">Print</a>"#,
        r#"<a href="echo.php?id=<?php echo $_GET['id']; ?>">Print</a>"#,
        r#"<a href="print.php?id={!! $_GET['id'] !!}">Print</a>"#,
    ]
    .into_iter()
    .filter(|source| !unsafe_php_output_reports(source))
    .collect::<Vec<_>>();
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn inner_html_assignment_regex_literals_are_data() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "tools/rules.mjs",
        "export const rules = [[/innerHTML =/, isScript, 'render as text']];",
    );
    let report = audit_project(temp.path()).unwrap();
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("unsafe-html:")));
}

#[test]
fn comment_closers_do_not_hide_live_html_sinks() {
    for (path, source) in [("src/bio.tsx", "export const Bio = ({ post }) => <div /*raw*/dangerouslySetInnerHTML={{ __html: post.body }} />;"), ("src/bio.php", "<?php /* x */echo $_GET['q'];")] {
        let temp = TempDir::new().unwrap();
        write_file(temp.path(), path, source);
        let report = audit_project(temp.path()).unwrap();
        assert!(report.issues.iter().any(|issue| issue.id.starts_with("unsafe-html:")), "{path}");
    }
}

#[test]
fn analytics_beacons_are_not_structured_server_logging() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "package.json",
        r#"{ "name": "worker-app", "dependencies": { "hono": "^4.0.0" } }"#,
    );
    for name in ["orders", "account", "billing"] {
        write_file(
            temp.path(),
            &format!("src/routes/{name}.ts"),
            "export async function POST() { return Response.json({ ok: true }); }",
        );
    }
    write_file(
        temp.path(),
        "src/log.ts",
        r#"export function logEvent(event, props) { const payload = { event, ...props }; navigator.sendBeacon("/a", JSON.stringify(payload)); }"#,
    );
    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("structured-logging-missing:")));
    for sink in ["console.log(text);", "process.stdout.write(text);"] {
        write_file(temp.path(), "src/log.ts", &format!("export function logEvent(event) {{ const line = {{ event }}; const text = JSON.stringify(line); {sink} }}"));
        let report = audit_project(temp.path()).unwrap();
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.id.starts_with("structured-logging-missing:")),
            "{sink}"
        );
    }
}
