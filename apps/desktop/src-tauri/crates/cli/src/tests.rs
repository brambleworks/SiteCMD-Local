use super::*;

#[test]
fn gate_threshold_consumes_exactly_one_value() {
    let args = parse_gate_args(
        [
            "--connection-export",
            "connection.sitecmd",
            "--threshold",
            "medium",
            "--strict",
            "--path",
            ".",
        ]
        .into_iter()
        .map(str::to_string),
    )
    .expect("valid gate arguments");

    assert_eq!(args.threshold, "medium");
    assert!(args.strict);
    assert_eq!(args.project_path, Some(".".into()));
}

#[test]
fn gate_threshold_is_valid_as_the_last_option() {
    let args = parse_gate_args(
        [
            "--connection-export",
            "connection.sitecmd",
            "--threshold",
            "high",
        ]
        .into_iter()
        .map(str::to_string),
    )
    .expect("valid gate arguments");

    assert_eq!(args.threshold, "high");
}

#[test]
fn category_options_accept_exactly_the_ten_keys() {
    // A category option accepts an old word or misses a key.
    let keys = "security, domain_https, email, seo, ai_visibility, performance, accessibility, privacy, polish, reliability";
    for key in keys.split(", ") {
        assert!(
            parse_scan_args(["--categories", key].into_iter().map(str::to_string)).is_ok(),
            "scan rejects {key}"
        );
        assert!(
            parse_fix_args(["--category", key].into_iter().map(str::to_string)).is_ok(),
            "fix rejects {key}"
        );
    }
    for key in [
        "compliance",
        "config",
        "code_quality",
        "health",
        "uptime",
        "domain-https",
        "ai-search",
        "",
        "seo,email",
    ] {
        let expected = format!(
            "Unknown category: {}. Use: {keys}",
            if key.is_empty() { "<empty>" } else { key }
        );
        let fix_error = parse_fix_args(["--category", key].into_iter().map(str::to_string)).err();
        assert_eq!(fix_error, Some(expected.clone()), "fix accepts {key}");
        if key != "seo,email" {
            let scan_error =
                parse_scan_args(["--categories", key].into_iter().map(str::to_string)).err();
            assert_eq!(scan_error, Some(expected), "scan accepts {key}");
        }
    }
}

#[test]
fn scan_has_no_type_option() {
    // Scan still accepts a phase option that bypasses category selection.
    let error = parse_scan_args(["--type", "security"].into_iter().map(str::to_string)).err();
    assert_eq!(error.as_deref(), Some("Unknown option: --type"));
}

#[test]
fn categories_are_normalized_and_deduplicated() {
    // Category filters lose normalization or repeat the same selection.
    let args = parse_scan_args(
        ["--categories", " SEO , email,seo"]
            .into_iter()
            .map(str::to_string),
    )
    .expect("normalized categories");
    assert_eq!(args.categories, Some(vec![Category::Seo, Category::Email]));
    for value in ["seo,", ",seo", "seo, ,email"] {
        let error = parse_scan_args(["--categories", value].into_iter().map(str::to_string))
            .err()
            .expect("empty category rejected");
        assert_eq!(error, "Unknown category: <empty>. Use: security, domain_https, email, seo, ai_visibility, performance, accessibility, privacy, polish, reliability");
    }
    let fix = parse_fix_args(
        ["--category", " EMAIL ", "--type", "config"]
            .into_iter()
            .map(str::to_string),
    )
    .expect("normalized fix category and applicability");
    assert_eq!(fix.category, Some(Category::Email));
    assert_eq!(fix.type_filter.as_deref(), Some("config"));
}

#[test]
fn cwv_and_no_browser_are_unknown_flags() {
    // Bug: The scan parser still accepts flags for a local browser pass.
    for flag in ["--cwv", "--no-browser"] {
        let error = parse_scan_args([flag.to_string()].into_iter())
            .err()
            .unwrap();
        assert_eq!(error, format!("Unknown option: {flag}"));
    }
}

#[test]
fn check_accepts_fail_under_and_its_deprecated_threshold_alias() {
    let new = parse_check_args(["--fail-under", "80"].into_iter().map(str::to_string))
        .expect("fail-under");
    assert_eq!(new.threshold, Some(80));
    let old = parse_check_args(["--threshold", "75"].into_iter().map(str::to_string))
        .expect("threshold alias");
    assert_eq!(old.threshold, Some(75));
}

#[test]
fn gate_names_the_file_its_verdict_is_written_to() {
    let args = parse_gate_args(
        [
            "--connection-export",
            "c.sitecmd",
            "--outputs",
            "gate-outputs.txt",
        ]
        .into_iter()
        .map(str::to_string),
    )
    .expect("outputs");
    assert_eq!(args.outputs, Some("gate-outputs.txt".into()));

    let bare = parse_gate_args(
        ["--connection-export", "c.sitecmd"]
            .into_iter()
            .map(str::to_string),
    )
    .expect("no outputs");
    assert_eq!(bare.outputs, None);
}

#[test]
fn gate_accepts_fail_on_and_its_deprecated_threshold_alias() {
    let new = parse_gate_args(
        ["--connection-export", "c.sitecmd", "--fail-on", "medium"]
            .into_iter()
            .map(str::to_string),
    )
    .expect("fail-on");
    assert_eq!(new.threshold, "medium");
    let rejected = parse_gate_args(
        ["--connection-export", "c.sitecmd", "--fail-on", "urgent"]
            .into_iter()
            .map(str::to_string),
    )
    .expect_err("unknown severity");
    assert!(rejected.contains("--fail-on must be critical, high, medium, or low"));
}

#[test]
fn scan_accepts_a_findings_gate_beside_the_score_gate() {
    let args = parse_scan_args(
        ["--fail-under", "90", "--fail-on", "high"]
            .into_iter()
            .map(str::to_string),
    )
    .expect("both gates");
    assert_eq!(args.fail_under, Some(90));
    assert_eq!(
        args.fail_on,
        Some(sitecmd_runtime::core::scan_types::Severity::High)
    );
}

#[test]
fn i3_provider_flags_survive_the_deploy_and_submit_parsers() {
    // I3: accepted provider refs and targets became empty wire values.
    for (reference, target) in [
        ("main", "deploy-preview"),
        ("refs/pull/12/merge", "branch-deploy"),
        ("refs/heads/renovate/@types-node-20.x", "staging"),
    ] {
        let flags = [
            "--deployment-id",
            "github:owner/repo@42",
            "--commit",
            "c0ffee1",
            "--ref",
            reference,
            "--target",
            target,
        ];
        let deploy =
            parse_deploy_args(flags.into_iter().map(str::to_string)).expect("provider flags");
        assert_eq!(deploy.deployment.git_ref.as_deref(), Some(reference));
        assert_eq!(deploy.deployment.target.as_deref(), Some(target));
        let submit = parse_connected_args(
            ["--submit", "--connection-export", "site.sitecmd"]
                .into_iter()
                .chain(flags)
                .map(str::to_string),
        )
        .expect("provider submit flags");
        let ConnectedInvocation::Submit(submit) = submit else {
            panic!("submit invocation");
        };
        assert_eq!(
            submit.deployment.provider_deployment_id.as_str(),
            "github:owner/repo@42"
        );
        assert_eq!(submit.deployment.git_ref.as_deref(), Some(reference));
    }
}

#[test]
fn i4_uppercase_sha_reports_case_instead_of_lost_length() {
    // I4: the constructor discarded uppercase input before the flag validator saw it.
    let error = parse_deploy_args(
        ["--deployment-id", "run-42", "--commit", "C0FFEE1"]
            .into_iter()
            .map(str::to_string),
    )
    .expect_err("case error");
    assert_eq!(
        error,
        "--commit must be lowercase; the service matches deployment SHAs exactly"
    );
}

#[test]
fn i4_oversized_ref_reports_length_instead_of_empty_input() {
    // I4: the oversized ref assertion passed on an unrelated empty-value error.
    let error = parse_deploy_args(
        [
            "--deployment-id".into(),
            "run-42".into(),
            "--commit".into(),
            "c0ffee1".into(),
            "--ref".into(),
            "r".repeat(257),
        ]
        .into_iter(),
    )
    .expect_err("length error");
    assert_eq!(error, "--ref must be at most 256 characters");
}

#[test]
fn login_and_logout_parse_only_the_connect_origin() {
    // Bug: authentication commands can accept ignored arguments or print a secret argument.
    let parsed = login_dispatch::parse_login_args(
        ["--connect-origin", "https://connect.example"]
            .into_iter()
            .map(str::to_string),
    )
    .unwrap();
    assert_eq!(
        parsed.connect_origin.as_deref(),
        Some("https://connect.example")
    );
    assert!(login_dispatch::parse_login_args(std::iter::empty())
        .unwrap()
        .connect_origin
        .is_none());
    for args in [
        vec!["--connect-origin"],
        vec!["secret-bearer"],
        vec!["--token", "secret-bearer"],
        vec![
            "--connect-origin",
            "https://first.example",
            "--connect-origin",
            "https://second.example",
        ],
    ] {
        let error = login_dispatch::parse_login_args(args.into_iter().map(str::to_string))
            .err()
            .unwrap();
        assert!(!error.contains("secret-bearer"));
    }
}

#[test]
fn login_interruption_uses_the_shell_exit_status() {
    // Bug: interrupted authentication can exit as an ordinary refusal.
    assert_eq!(sitecmd_runtime::cli::login::failure_exit_code(""), 130);
}

#[test]
fn site_not_in_account_exits_two_with_closed_json() {
    // Bug: The CLI dispatcher prints extra fields or returns the wrong status for an unlisted site.
    const CHILD: &str = "SITECMD_HOSTED_REFUSAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let status = dispatch_scan_with(
            ["--url", "https://example.com", "--json"]
                .map(str::to_string)
                .into_iter(),
            |args| {
                assert!(args.json);
                Err(scan::ScanFailure::Hosted(
                    sitecmd_runtime::cli::hosted::HostedError::SiteNotInAccount,
                ))
            },
        );
        std::process::exit(if status == ExitCode::from(2) { 2 } else { 99 });
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::site_not_in_account_exits_two_with_closed_json",
            "--quiet",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.lines().last(),
        Some(r#"{"error":{"code":"site_not_in_account"}}"#)
    );
}
