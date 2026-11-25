use std::process::{Command, Output};

#[path = "support/cli_binary.rs"]
mod cli_binary;
use cli_binary::cli_binary;

const SIGNED_OUT: &str = concat!(
    "Scanning a public site runs on SiteCMD's hosted scanner, so it needs a SiteCMD account.\n",
    "Sign in with `sitecmd login`, or set SITECMD_TOKEN in CI.\n",
    "To check a site without an account, use the free scan at https://sitecmd.com/scan.\n",
);

fn signed_out_scan(flags: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(cli_binary())
        .current_dir(dir.path())
        .env_remove("SITECMD_TOKEN")
        .env("SITECMD_CONNECT_ORIGIN", "https://connect.invalid")
        .args(["scan", "--url", "https://93.184.215.14"])
        .args(flags)
        .output()
        .unwrap()
}

#[test]
fn signed_out_prints_the_three_lines_and_exits_2() {
    // Bug: A signed-out public scan runs locally or omits the sign-in instructions.
    let output = signed_out_scan(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8(output.stderr).unwrap(), SIGNED_OUT);
}

#[test]
fn check_and_watch_exit_2_with_the_refusal_code() {
    // Bug: Public check and watch pass or scan natively after a sign-in or configuration refusal.
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join(".sitecmd");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(
        config.join("config.json"),
        r#"{"version":1,"url":"https://93.184.215.14","name":"Public site","fail_under":80}"#,
    )
    .unwrap();
    for command in ["check", "watch"] {
        for (origin, message) in [
            (
                "https://connect.invalid",
                format!("Error: signed_out\n{SIGNED_OUT}"),
            ),
            (
                "http://connect.invalid",
                concat!(
                    "Error: invalid_configuration\n",
                    "Configure a valid SiteCMD Connect origin with SITECMD_CONNECT_ORIGIN.\n",
                )
                .into(),
            ),
        ] {
            let output = Command::new(cli_binary())
                .current_dir(directory.path())
                .env("SITECMD_TOKEN", "")
                .env("SITECMD_CONNECT_ORIGIN", origin)
                .arg(command)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{command}: {output:?}");
            assert!(output.stdout.is_empty(), "{command}: {output:?}");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.ends_with(&message), "{stderr}");
        }
    }
}

#[test]
fn json_signed_out_is_the_closed_shape() {
    // Bug: Signed-out JSON contains fields outside the machine refusal contract.
    let output = signed_out_scan(&["--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"{\"error\":{\"code\":\"signed_out\"}}\n");
}

#[test]
fn empty_token_is_signed_out_and_a_bad_origin_is_invalid_configuration() {
    // Bug: Bad Connect configuration or an empty CI token is reported as an outage.
    for (origin, token, code) in [
        ("https://connect.invalid", "", "signed_out"),
        ("http://connect.invalid", "fixture", "invalid_configuration"),
        ("", "fixture", "invalid_configuration"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut command = Command::new(cli_binary());
        command
            .current_dir(dir.path())
            .env_remove("SITECMD_CONNECT_ORIGIN")
            .env("SITECMD_TOKEN", token)
            .args(["scan", "--url", "https://93.184.215.14", "--json"]);
        if !origin.is_empty() {
            command.args(["--connect-origin", origin]);
        } else if option_env!("SITECMD_CONNECTED_ENDPOINT").is_some() {
            continue;
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{{\"error\":{{\"code\":\"{code}\"}}}}\n")
        );
    }
}

#[test]
fn fix_reports_both_artifact_parse_errors() {
    // Bug: The untagged scan enum hides the field that made fix reject each shape.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".sitecmd");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(
        config.join("last-scan.json"),
        r#"{"hosted":{"connectOrigin":5},"url":false}"#,
    )
    .unwrap();
    let output = Command::new(cli_binary())
        .current_dir(dir.path())
        .arg("fix")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Hosted scan: invalid type: integer `5`, expected a string"));
    assert!(stderr.contains("Local scan: invalid type: boolean `false`, expected a string"));
}

fn fix_hosted_finding(fix_guide: &str) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".sitecmd");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(
        config.join("last-scan.json"),
        format!(
            r#"{{"hosted":{{"connectOrigin":"https://connect.sitecmd.com","siteId":"site_a",
            "scanId":"hs_a","url":"https://example.com","overallScore":80,
            "timestamp":"2026-11-21T16:00:00.000Z","categoryScores":{{}},
            "issues":[{{"checkId":"security.headers","title":"Missing headers",
            "category":"security","severity":"high","occurrences":4{fix_guide}}}]}}}}"#
        ),
    )
    .unwrap();
    Command::new(cli_binary())
        .current_dir(dir.path())
        .args(["fix", "--id", "security.headers"])
        .output()
        .unwrap()
}

#[test]
fn a_hosted_finding_without_a_guide_says_so() {
    // Bug: A hosted finding Connect has no guide for prints empty or module-written fix text.
    let output = fix_hosted_finding(r#","fixGuide":null"#);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "security.headers - Missing headers\n\n",
            "SiteCMD doesn't have fix text for this check yet.\n",
            "\n---\nFix applied? Run `sitecmd scan --diff` to verify.\n",
        )
    );
}

#[test]
fn fix_reads_an_old_last_scan_as_missing() {
    // Bug: A hosted last-scan.json saved before fix guides crashes fix or prints module-written text.
    let output = fix_hosted_finding("");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "security.headers - Missing headers\n\n",
            "Run `sitecmd scan` again to fetch the fix text for this check.\n",
            "\n---\nFix applied? Run `sitecmd scan --diff` to verify.\n",
        )
    );
}
