use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
use cli_binary::cli_binary;

#[test]
fn audit_rejects_legacy_suppression_fingerprints_with_regeneration_guidance() {
    // Bug N5: old sha256 suppression fingerprints can silently stop hiding findings.
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("package.json"), r#"{"name":"fixture"}"#).unwrap();
    std::fs::create_dir(project.path().join(".sitecmd")).unwrap();
    let fingerprint = format!("sha256:{}", "a".repeat(64));
    std::fs::write(project.path().join(".sitecmd/config.json"), format!(
        r#"{{"version":1,"url":"https://example.com","name":"fixture","code_scan":{{"suppressions":[{{"match":{{"fingerprint":"{fingerprint}"}},"reason":"Reviewed fixture"}}]}}}}"#
    )).unwrap();
    let output = Command::new(cli_binary())
        .args(["audit", ".", "--format", "json"])
        .current_dir(project.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("regenerate old suppressions"));
}
