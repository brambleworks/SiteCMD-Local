//! Code findings reach the fix job as keyed location hashes. The runtime
//! re-audits the checkout, hashes every issue with the connection's
//! fingerprint key, and turns the matches into the prose-free `BriefArtifact`
//! the publish job renders from.

use std::path::Path;

use sitecmd_engine::identity::code_producer_rule_id;
use sitecmd_engine::sync::ProjectFingerprintKey;

use super::artifact::{BriefArtifact, BriefArtifactLocation, BriefFinding};
use crate::core::code_scan::{audit_project, canonical_code_check_id, CodeIssue};

/// The Code Scan rule behind a canonical check ID, or `None` for a web check.
pub fn code_slug(check_id: &str) -> Option<&str> {
    check_id
        .strip_prefix("code_scan.")
        .filter(|slug| !slug.is_empty())
}

/// One code issue in this checkout that a job's `(check_id, identity)` pair
/// named, carrying the identity the job already knows it by.
#[derive(Debug, Clone)]
pub struct MatchedLocation {
    pub check_id: String,
    pub identity: String,
    pub issue: CodeIssue,
}

/// Audit the checkout once and keep the issues whose canonical check ID and
/// keyed location hash both match one of the wanted pairs. A different
/// fingerprint key therefore matches nothing.
pub fn locate_findings(
    root: &Path,
    key: &ProjectFingerprintKey,
    wanted: &[(String, String)],
) -> Result<Vec<MatchedLocation>, String> {
    let report = audit_project(root)?;
    let mut matches = Vec::new();
    for issue in report.issues {
        let check_id = canonical_code_check_id(&issue.id);
        let identity = key.location_hash(code_producer_rule_id(&issue.id), &issue.relative_path);
        if wanted.iter().any(|(wanted_check, wanted_identity)| {
            *wanted_check == check_id && *wanted_identity == identity
        }) {
            matches.push(MatchedLocation {
                check_id,
                identity,
                issue,
            });
        }
    }
    Ok(matches)
}

/// Every code issue in this checkout as `(check_id, identity, path, line)`.
///
/// The row is the printed line, so it stays a plain tuple rather than a
/// struct that only `locate` would ever read.
#[allow(clippy::type_complexity)]
pub fn identities(
    root: &Path,
    key: &ProjectFingerprintKey,
) -> Result<Vec<(String, String, String, Option<u32>)>, String> {
    let report = audit_project(root)?;
    Ok(report
        .issues
        .into_iter()
        .map(|issue| {
            let identity =
                key.location_hash(code_producer_rule_id(&issue.id), &issue.relative_path);
            (
                canonical_code_check_id(&issue.id),
                identity,
                issue.relative_path,
                issue.line,
            )
        })
        .collect())
}

/// Fold matched issues into the prose-free brief artifact: one finding per
/// `(check_id, identity)` pair, one location per issue. An issue without a
/// line has nothing to point at, so it is skipped.
pub fn brief_artifact(job_id: &str, attempt: u32, matches: &[MatchedLocation]) -> BriefArtifact {
    let mut findings: Vec<BriefFinding> = Vec::new();
    for matched in matches {
        let Some(line) = matched.issue.line else {
            continue;
        };
        let location = BriefArtifactLocation {
            end_line: line,
            excerpt: matched.issue.source_excerpt.clone().unwrap_or_default(),
            path: matched.issue.relative_path.clone(),
            start_line: line,
        };
        match findings.iter_mut().find(|finding| {
            finding.check_id == matched.check_id && finding.identity == matched.identity
        }) {
            Some(finding) => finding.locations.push(location),
            None => findings.push(BriefFinding {
                check_id: matched.check_id.clone(),
                identity: matched.identity.clone(),
                locations: vec![location],
            }),
        }
    }
    BriefArtifact {
        attempt,
        findings,
        job_id: job_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sitecmd_engine::sync::ProjectFingerprintKey;

    fn open_redirect_repo() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("package.json"),
            r#"{ "name": "redirect-app" }"#,
        )
        .unwrap();
        std::fs::create_dir_all(temp.path().join("app/api/signin")).unwrap();
        std::fs::write(
            temp.path().join("app/api/signin/route.ts"),
            "export async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const returnTo = searchParams.get(\"returnTo\") ?? \"/\";\n  return Response.redirect(new URL(returnTo, request.url), 302);\n}\n",
        )
        .unwrap();
        temp
    }

    #[test]
    fn code_slug_reads_code_scan_ids_only() {
        assert_eq!(code_slug("code_scan.open-redirect"), Some("open-redirect"));
        assert_eq!(code_slug("security.headers.x_content_type_options"), None);
    }

    #[test]
    fn matches_a_job_finding_by_its_keyed_location_hash() {
        let temp = open_redirect_repo();
        let key = ProjectFingerprintKey::from_bytes([7_u8; 32]);
        let identity = key.location_hash("open-redirect", "app/api/signin/route.ts");
        let matches = locate_findings(
            temp.path(),
            &key,
            &[("code_scan.open-redirect".to_string(), identity.clone())],
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].issue.relative_path, "app/api/signin/route.ts");
        let artifact = brief_artifact("job_0123456789abcdef", 1, &matches);
        assert_eq!(artifact.findings[0].identity, identity);
        let location = &artifact.findings[0].locations[0];
        assert_eq!(location.path, "app/api/signin/route.ts");
        assert_eq!(location.start_line, location.end_line);
        assert!(
            location.excerpt.contains("Response.redirect"),
            "{}",
            location.excerpt
        );
        let other_key = ProjectFingerprintKey::from_bytes([9_u8; 32]);
        assert!(locate_findings(
            temp.path(),
            &other_key,
            &[("code_scan.open-redirect".to_string(), identity)]
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn lists_every_identity_for_locate() {
        let temp = open_redirect_repo();
        let key = ProjectFingerprintKey::from_bytes([7_u8; 32]);
        let rows = identities(temp.path(), &key).unwrap();
        assert!(rows.iter().any(
            |(check, identity, path, _)| check == "code_scan.open-redirect"
                && *identity == key.location_hash("open-redirect", "app/api/signin/route.ts")
                && path == "app/api/signin/route.ts"
        ));
    }
}
