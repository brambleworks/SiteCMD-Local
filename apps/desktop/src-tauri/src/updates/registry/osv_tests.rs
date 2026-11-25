//! Tests for the OSV.dev client.

use super::*;

fn vuln_from_json(value: serde_json::Value) -> OsvVuln {
    serde_json::from_value(value).expect("vuln deserialise")
}

fn npm_package(name: &str, version: &str) -> InstalledPackage {
    InstalledPackage {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Npm,
        source: "package-lock.json".to_string(),
        is_dev: false,
        workspace_members: Vec::new(),
    }
}

// One-shot local HTTP server: answers every accepted connection with
// `status_line` + `body`, so the OSV client can be driven offline.
async fn spawn_osv_stub(status_line: &'static str, body: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind OSV stub");
    let address = listener.local_addr().expect("OSV stub address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "{}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                status_line,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{}", address)
}

#[tokio::test]
async fn failed_batch_returns_no_vulnerabilities() {
    let base = spawn_osv_stub("HTTP/1.1 500 Internal Server Error", "").await;

    let scan = check_vulnerabilities_at(&[npm_package("left-pad", "1.3.0")], &base).await;

    assert!(scan.vulns.is_empty());
}

#[tokio::test]
async fn successful_empty_batch_returns_no_vulnerabilities() {
    let base = spawn_osv_stub("HTTP/1.1 200 OK", r#"{"results":[{}]}"#).await;

    let scan = check_vulnerabilities_at(&[npm_package("left-pad", "1.3.0")], &base).await;

    assert!(scan.vulns.is_empty());
}

#[tokio::test]
async fn incomplete_batch_returns_no_vulnerabilities() {
    let base = spawn_osv_stub("HTTP/1.1 200 OK", r#"{"results":[]}"#).await;

    let scan = check_vulnerabilities_at(&[npm_package("left-pad", "1.3.0")], &base).await;

    assert!(scan.vulns.is_empty());
}

#[tokio::test]
async fn empty_queryable_set_returns_no_vulnerabilities() {
    let scan = check_vulnerabilities(&[]).await;
    assert!(scan.vulns.is_empty());
}

#[test]
fn build_vuln_infos_uses_fetched_detail_not_querybatch_defaults() {
    let pkg = InstalledPackage {
        name: "lodash".to_string(),
        version: "4.17.10".to_string(),
        ecosystem: Ecosystem::Npm,
        source: "package-lock.json".to_string(),
        is_dev: false,
        workspace_members: Vec::new(),
    };
    let packages = vec![&pkg];
    let batch = OsvBatchResponse {
        results: vec![OsvQueryResult {
            // Shallow, exactly as querybatch returns it: id only.
            vulns: Some(vec![vuln_from_json(
                serde_json::json!({"id": "GHSA-p6mc-m28x-1234"}),
            )]),
        }],
    };
    let mut details = HashMap::new();
    details.insert(
        "GHSA-p6mc-m28x-1234".to_string(),
        vuln_from_json(serde_json::json!({
            "id": "GHSA-p6mc-m28x-1234",
            "summary": "Prototype pollution in lodash",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}],
            "references": [{"type": "ADVISORY", "url": "https://example.test/GHSA"}]
        })),
    );

    let infos = build_vuln_infos(&packages, &batch, &details);
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].summary, "Prototype pollution in lodash");
    assert_eq!(infos[0].severity, Severity::Critical);
    assert_eq!(infos[0].source, "package-lock.json");
    assert!(!infos[0].is_dev);
    assert_eq!(
        infos[0].advisory_url.as_deref(),
        Some("https://example.test/GHSA")
    );

    // A failed detail fetch (id absent from the map) degrades to defaults
    // instead of panicking, and the advisory URL still resolves from the ID.
    let fallback = build_vuln_infos(&packages, &batch, &HashMap::new());
    assert_eq!(fallback[0].summary, "Security vulnerability");
    assert_eq!(fallback[0].severity, Severity::High);
    assert_eq!(
        fallback[0].advisory_url.as_deref(),
        Some("https://osv.dev/vulnerability/GHSA-p6mc-m28x-1234")
    );
}

#[test]
fn osv_ecosystem_maps_supported_ecosystems() {
    assert_eq!(osv_ecosystem(&Ecosystem::Npm), Some("npm"));
    assert_eq!(osv_ecosystem(&Ecosystem::Composer), Some("Packagist"));
    assert_eq!(osv_ecosystem(&Ecosystem::Python), Some("PyPI"));
    assert_eq!(osv_ecosystem(&Ecosystem::Ruby), Some("RubyGems"));
    assert_eq!(osv_ecosystem(&Ecosystem::Go), Some("Go"));
    assert_eq!(osv_ecosystem(&Ecosystem::Rust), Some("crates.io"));
}

#[test]
fn osv_ecosystem_returns_none_for_unsupported() {
    assert!(osv_ecosystem(&Ecosystem::WordPress).is_none());
    assert!(osv_ecosystem(&Ecosystem::Drupal).is_none());
}

#[test]
fn parse_cvss_score_parses_plain_numeric_string() {
    assert_eq!(parse_cvss_score("9.8"), Some(9.8));
    assert_eq!(parse_cvss_score("0"), Some(0.0));
    assert_eq!(parse_cvss_score("10.0"), Some(10.0));
}

#[test]
fn parse_cvss_score_scores_v3_and_v4_vectors() {
    assert_eq!(
        parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        Some(9.8)
    );
    assert_eq!(
        parse_cvss_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
        Some(10.0)
    );
}

#[test]
fn parse_cvss_score_returns_none_for_garbage() {
    assert!(parse_cvss_score("").is_none());
    assert!(parse_cvss_score("not a number").is_none());
    assert!(parse_cvss_score("11.0").is_none());
}

#[test]
fn cvss_to_severity_uses_industry_standard_thresholds() {
    // Standard CVSS v3 severity bands.
    assert_eq!(cvss_to_severity(10.0), Severity::Critical);
    assert_eq!(cvss_to_severity(9.0), Severity::Critical);
    assert_eq!(cvss_to_severity(8.9), Severity::High);
    assert_eq!(cvss_to_severity(7.0), Severity::High);
    assert_eq!(cvss_to_severity(6.9), Severity::Medium);
    assert_eq!(cvss_to_severity(4.0), Severity::Medium);
    assert_eq!(cvss_to_severity(3.9), Severity::Low);
    assert_eq!(cvss_to_severity(0.1), Severity::Low);
    assert_eq!(cvss_to_severity(0.0), Severity::Low);
}

#[test]
fn extract_severity_returns_high_when_no_severity_block() {
    let vuln = vuln_from_json(serde_json::json!({"id": "GHSA-xxxx"}));
    assert_eq!(
        extract_severity(&vuln, &npm_package("lodash", "1.0.0")),
        Severity::High
    );
}

#[test]
fn extract_severity_uses_numeric_score_when_present() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "GHSA-yyy",
        "severity": [{"type": "CVSS_V3", "score": "9.5"}]
    }));
    assert_eq!(
        extract_severity(&vuln, &npm_package("lodash", "1.0.0")),
        Severity::Critical
    );
}

#[test]
fn extract_severity_scores_full_cvss_vector() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "GHSA-zzz",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }]
    }));
    assert_eq!(
        extract_severity(&vuln, &npm_package("lodash", "1.0.0")),
        Severity::Critical
    );
}

#[test]
fn extract_severity_scores_cvss_v2_vectors_with_v2_bands() {
    let high = vuln_from_json(serde_json::json!({
        "id": "GHSA-v2-high",
        "severity": [{
            "type": "CVSS_V2",
            "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        }]
    }));
    assert_eq!(
        extract_severity(&high, &npm_package("lodash", "1.0.0")),
        Severity::High
    );

    let medium = vuln_from_json(serde_json::json!({
        "id": "GHSA-v2-medium",
        "severity": [{
            "type": "CVSS_V2",
            "score": "CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:P/A:P"
        }]
    }));
    assert_eq!(
        extract_severity(&medium, &npm_package("lodash", "1.0.0")),
        Severity::Medium
    );
}

#[test]
fn extract_severity_falls_back_to_high_when_score_field_missing() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "GHSA-aaa",
        "severity": [{"type": "CVSS_V3"}]
    }));
    assert_eq!(
        extract_severity(&vuln, &npm_package("lodash", "1.0.0")),
        Severity::High
    );
}

#[test]
fn extract_severity_falls_back_to_high_for_a_malformed_vector() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "GHSA-malformed",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/not-a-vector"}]
    }));

    assert_eq!(
        extract_severity(&vuln, &npm_package("lodash", "1.0.0")),
        Severity::High
    );
}

#[test]
fn extract_severity_uses_only_the_matching_package_entry() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "GHSA-package-specific",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "severity": [{"type": "CVSS_V3", "score": "4.2"}]
            },
            {
                "package": {"ecosystem": "npm", "name": "other-package"},
                "severity": [{"type": "CVSS_V3", "score": "9.9"}]
            }
        ]
    }));
    assert_eq!(
        extract_severity(&vuln, &npm_package("lodash", "1.0.0")),
        Severity::Medium
    );
}

#[test]
fn extract_severity_normalizes_python_package_names() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "PYSEC-package-specific",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "Example.Package_Name"},
            "severity": [{"type": "CVSS_V3", "score": "7.5"}]
        }]
    }));
    let package = InstalledPackage {
        name: "example-package-name".to_string(),
        version: "1.0.0".to_string(),
        ecosystem: Ecosystem::Python,
        ..Default::default()
    };
    assert_eq!(extract_severity(&vuln, &package), Severity::High);
}

#[test]
fn extract_advisory_url_prefers_advisory_type() {
    // Multiple references - ADVISORY type beats WEB beats anything else.
    let vuln = vuln_from_json(serde_json::json!({
        "id": "x",
        "references": [
            {"type": "WEB", "url": "https://blog.example/post"},
            {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-xxx"},
            {"type": "FIX", "url": "https://github.com/repo/pull/42"}
        ]
    }));
    assert_eq!(
        extract_advisory_url(&vuln).as_deref(),
        Some("https://github.com/advisories/GHSA-xxx"),
    );
}

#[test]
fn extract_advisory_url_falls_back_to_web_when_no_advisory() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "x",
        "references": [
            {"type": "FIX", "url": "https://github.com/repo/pull/42"},
            {"type": "WEB", "url": "https://blog.example/post"}
        ]
    }));
    assert_eq!(
        extract_advisory_url(&vuln).as_deref(),
        Some("https://blog.example/post")
    );
}

#[test]
fn extract_advisory_url_falls_back_to_first_url_when_no_priority_type() {
    let vuln = vuln_from_json(serde_json::json!({
        "id": "x",
        "references": [
            {"type": "FIX", "url": "https://github.com/repo/pull/42"},
            {"type": "REPORT", "url": "https://example.com/report"}
        ]
    }));
    assert_eq!(
        extract_advisory_url(&vuln).as_deref(),
        Some("https://github.com/repo/pull/42"),
    );
}

#[test]
fn extract_advisory_url_synthesises_osv_url_when_no_references() {
    // Even without references we should give the user something to
    // click - link to the OSV vuln page directly.
    let vuln = vuln_from_json(serde_json::json!({"id": "GHSA-test-1234"}));
    assert_eq!(
        extract_advisory_url(&vuln).as_deref(),
        Some("https://osv.dev/vulnerability/GHSA-test-1234"),
    );
}

fn vuln_info(
    eco: Ecosystem,
    name: &str,
    severity: Severity,
    advisory_id: &str,
) -> VulnerabilityInfo {
    VulnerabilityInfo {
        package_name: name.into(),
        ecosystem: eco,
        current_version: "1.0.0".into(),
        source: "package-lock.json".into(),
        is_dev: false,
        workspace_members: Vec::new(),
        advisory_id: advisory_id.into(),
        severity,
        summary: "test".into(),
        advisory_url: None,
    }
}

#[test]
fn deduplicate_vulns_keeps_highest_severity_per_package() {
    let mut vulns = vec![
        vuln_info(Ecosystem::Npm, "lodash", Severity::Low, "ADV-1"),
        vuln_info(Ecosystem::Npm, "lodash", Severity::Critical, "ADV-2"),
        vuln_info(Ecosystem::Npm, "lodash", Severity::Medium, "ADV-3"),
    ];
    deduplicate_vulns(&mut vulns);
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0].advisory_id, "ADV-2");
    assert_eq!(vulns[0].severity, Severity::Critical);
}

#[test]
fn deduplicate_vulns_keeps_separate_packages() {
    let mut vulns = vec![
        vuln_info(Ecosystem::Npm, "lodash", Severity::High, "ADV-1"),
        vuln_info(Ecosystem::Npm, "react", Severity::Critical, "ADV-2"),
    ];
    deduplicate_vulns(&mut vulns);
    assert_eq!(vulns.len(), 2);
}

#[test]
fn deduplicate_vulns_scopes_dedup_by_ecosystem_and_name() {
    // Same name in different ecosystems must both survive - `requests`
    // is a real package on PyPI AND something else somewhere else.
    let mut vulns = vec![
        vuln_info(Ecosystem::Python, "requests", Severity::High, "PY-1"),
        vuln_info(Ecosystem::Npm, "requests", Severity::High, "NPM-1"),
    ];
    deduplicate_vulns(&mut vulns);
    assert_eq!(vulns.len(), 2);
}

#[test]
fn deduplicate_vulns_preserves_first_occurrence_on_tie() {
    // Equal severities - keep the first one seen so pagination is stable.
    let mut vulns = vec![
        vuln_info(Ecosystem::Npm, "lodash", Severity::High, "ADV-FIRST"),
        vuln_info(Ecosystem::Npm, "lodash", Severity::High, "ADV-SECOND"),
    ];
    deduplicate_vulns(&mut vulns);
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0].advisory_id, "ADV-FIRST");
}

#[test]
fn deduplicate_vulns_handles_empty_input() {
    let mut vulns: Vec<VulnerabilityInfo> = Vec::new();
    deduplicate_vulns(&mut vulns);
    assert!(vulns.is_empty());
}
