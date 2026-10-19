use super::super::*;

#[test]
fn recognizes_a_structured_log_event_wrapper_that_builds_the_line_first() {
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
    let missing = audit_project(temp.path()).unwrap();
    assert!(missing
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("structured-logging-missing:")));
    write_file(
        temp.path(),
        "src/log.ts",
        r#"
export function logEvent(event: string, fields: Record<string, string> = {}): void {
  const line: Record<string, string> = { event };
  for (const [name, value] of Object.entries(fields)) line[name] = value;
  console.log(JSON.stringify(line));
}
"#,
    );
    let report = audit_project(temp.path()).unwrap();
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("structured-logging-missing:")));
}
