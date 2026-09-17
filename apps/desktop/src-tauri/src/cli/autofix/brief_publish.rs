//! The agent path of the publish job: the fix job's artifact supplies check
//! ids, identities and locations, and every word of the issue comes from the
//! binary's own check text, the publish claim and the checkout the publish
//! job itself made.

use std::path::{Component, Path};

use sitecmd_engine::identity::code_producer_rule_id;

use super::artifact::{BriefArtifact, BriefArtifactLocation, Manifest};
use super::brief::code_slug;
use super::github_api::GitHubApi;
use super::publish_job::finding_reports;
use super::redact;
use crate::connected_service::{
    ClaimedJob, ConnectedServiceClient, FindingOutcomeReport, ResultReport,
};
use crate::core::code_scan::{audit_project, CodeIssue};
use crate::core::detector::DetectedStack;
use crate::core::fix_brief::{build_fix_brief_with_mode, BriefLocation, BriefMode, FixBriefInput};
use crate::core::fix_templates::{build_check::package_json, hosts, HostKind};

/// Server-side frameworks the brief names. A checkout that depends on more
/// than one is read in this order, and the first match names the framework.
const FRAMEWORK_PACKAGES: &[(&str, &str)] = &[
    ("next", "Next.js"),
    ("nuxt", "Nuxt.js"),
    ("express", "Express.js"),
    ("astro", "Astro"),
    ("@sveltejs/kit", "SvelteKit"),
    ("@remix-run/react", "Remix"),
    ("gatsby", "Gatsby"),
];

/// Client frameworks the brief names, read the same way.
const CLIENT_PACKAGES: &[(&str, &str)] =
    &[("react", "React"), ("vue", "Vue.js"), ("svelte", "Svelte")];

/// Why a brief was not published. The reason is the binary's own sentence,
/// and it names the offending location by its position in the brief, so no
/// text the artifact chose reaches the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefRejected {
    pub reason: String,
}

/// One location the publish job's own audit confirmed, carrying the issue the
/// audit reported there.
#[derive(Debug, Clone)]
pub struct VerifiedFinding {
    pub check_id: String,
    pub identity: String,
    pub issue: CodeIssue,
    pub location: BriefArtifactLocation,
}

fn rejected(reason: String) -> BriefRejected {
    BriefRejected { reason }
}

/// Where a refusal happened, by zero-based position in the brief's arrays.
fn at(finding: usize, location: usize) -> String {
    format!("brief finding {finding}, location {location}")
}

/// Audit the publish job's own checkout once and confirm every location the
/// brief names: a relative path to a file inside the tree, the brief's rule
/// reported at that path, a reported line inside the brief's range, and the
/// excerpt the checkout itself shows there. Anything else is a refusal,
/// because the artifact crossed an untrusted boundary.
///
/// The brief's line range only selects which reported issue a location means,
/// so a file the audit reports the rule at more than once still resolves.
pub fn check_brief(
    root: &Path,
    brief: &BriefArtifact,
) -> Result<Vec<VerifiedFinding>, BriefRejected> {
    let report = audit_project(root).map_err(rejected)?;
    let mut verified = Vec::new();
    for (finding_index, finding) in brief.findings.iter().enumerate() {
        let slug = code_slug(&finding.check_id).ok_or_else(|| {
            rejected(format!(
                "brief finding {finding_index} does not name a code check"
            ))
        })?;
        for (location_index, location) in finding.locations.iter().enumerate() {
            let at = at(finding_index, location_index);
            let relative = Path::new(&location.path);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
            {
                return Err(rejected(format!(
                    "{at}: the path reaches outside the checkout"
                )));
            }
            if !root.join(relative).is_file() {
                return Err(rejected(format!(
                    "{at}: the path is not a file in the checkout"
                )));
            }
            let reported: Vec<&CodeIssue> = report
                .issues
                .iter()
                .filter(|issue| {
                    code_producer_rule_id(&issue.id) == slug && issue.relative_path == location.path
                })
                .collect();
            if reported.is_empty() {
                return Err(rejected(format!(
                    "{at}: the checkout does not report this finding there"
                )));
            }
            // The range picks which reported issue this location means, so a
            // rule the audit reports twice in one file still resolves.
            let issue = reported
                .into_iter()
                .find(|issue| {
                    issue.line.is_some_and(|line| {
                        line >= location.start_line && line <= location.end_line
                    })
                })
                .ok_or_else(|| {
                    rejected(format!(
                        "{at}: the reported line is outside the brief's line range"
                    ))
                })?;
            if issue.source_excerpt.as_deref().unwrap_or("") != location.excerpt {
                return Err(rejected(format!(
                    "{at}: the brief's excerpt is not what the checkout shows"
                )));
            }
            verified.push(VerifiedFinding {
                check_id: finding.check_id.clone(),
                identity: finding.identity.clone(),
                issue: issue.clone(),
                location: location.clone(),
            });
        }
    }
    if verified.is_empty() {
        return Err(rejected("the brief names no location".into()));
    }
    Ok(verified)
}

/// Whether the checkout's manifest depends on a package, in either its
/// runtime or its development dependencies.
fn depends_on(manifest: Option<&serde_json::Value>, package: &str) -> bool {
    manifest.is_some_and(|manifest| {
        ["dependencies", "devDependencies"]
            .iter()
            .any(|key| !manifest[key][package].is_null())
    })
}

fn first_match(manifest: Option<&serde_json::Value>, table: &[(&str, &str)]) -> Option<String> {
    table
        .iter()
        .find(|(package, _)| depends_on(manifest, package))
        .map(|(_, name)| (*name).to_string())
}

/// The stack the publish job's own checkout shows, in the shape the fix brief
/// reads it. Nothing here comes from the artifact: the frameworks are read
/// out of the checkout's `package.json` and the host out of its own host
/// configuration. `None` when the checkout shows nothing.
pub fn checkout_stack(root: &Path) -> Option<serde_json::Value> {
    let manifest = package_json(root);
    let stack = DetectedStack {
        cdn: hosts::detect(root).first().map(|target| match target.kind {
            HostKind::Vercel => "Vercel".to_string(),
        }),
        framework: first_match(manifest.as_ref(), FRAMEWORK_PACKAGES),
        js_framework: first_match(manifest.as_ref(), CLIENT_PACKAGES),
        ..DetectedStack::default()
    };
    if stack.cdn.is_none() && stack.framework.is_none() && stack.js_framework.is_none() {
        return None;
    }
    serde_json::to_value(stack).ok()
}

/// The issue SiteCMD opens for an agent: the hosted fix brief, addressed to
/// the agent the claim names. Every sentence is the binary's own or the
/// claim's, and every path, line and excerpt it prints is the audit's own:
/// the brief's range only chose which reported issue each location meant.
///
/// `verified` must not be empty, which is what [`check_brief`] returns.
pub fn render_issue(
    claimed: &ClaimedJob,
    verified: &[VerifiedFinding],
    stack: Option<serde_json::Value>,
) -> (String, String) {
    let first = &verified[0];
    let locations: Vec<BriefLocation> = verified
        .iter()
        .map(|v| BriefLocation {
            end_line: v.issue.line,
            excerpt: v.issue.source_excerpt.clone(),
            label: "Reported location".into(),
            line: v.issue.line,
            path: v.issue.relative_path.clone(),
            reason: "the check matched here".into(),
            start_line: v.issue.line,
        })
        .collect();
    let input = FixBriefInput {
        attempt_id: i64::from(claimed.attempt),
        check_id: first.check_id.clone(),
        description: first.issue.description.clone(),
        detected_stack: stack,
        evidence: None,
        manual_fix: first.issue.likely_fix.clone(),
        occurrence_target: locations.first().cloned(),
        previous_failure: claimed.previous_failure.clone(),
        severity: first.issue.severity,
        title: first.issue.title.clone(),
        url: claimed.site_url.clone(),
        why_it_matters: first.issue.why_now.clone(),
    };
    let brief = build_fix_brief_with_mode(&input, &locations, BriefMode::Hosted);
    let body = if claimed.agent == "claude" {
        format!(
            "@claude please fix the finding below and open a pull request that references this issue.\n\n{brief}"
        )
    } else {
        brief
    };
    (format!("SiteCMD: {}", first.issue.title), body)
}

/// Confirm the brief against this checkout, render the issue, open it with a
/// per-operation issue token, hand the token back, and report. A brief the
/// checkout does not confirm is a reported refusal, not a failure that would
/// leave the job waiting.
pub async fn publish_brief(
    root: &Path,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    job_client: &ConnectedServiceClient,
) -> Result<(u8, ResultReport), String> {
    let brief = manifest.brief.as_ref().ok_or("manifest carries no brief")?;
    let declined = |code: &str, summary: String, revoked: bool| ResultReport {
        attempt: claimed.attempt,
        findings: finding_reports(manifest, "unsupported"),
        issue_number: None,
        outcome_code: code.into(),
        pull_request: None,
        summary: redact::summary(root, &summary),
        token_revoked: revoked,
    };
    let verified = match check_brief(root, brief) {
        Ok(verified) => verified,
        Err(rejected) => return Ok((1, declined("brief_rejected", rejected.reason, true))),
    };
    let (title, body) = render_issue(claimed, &verified, checkout_stack(root));
    let minted = job_client
        .issue_token(&claimed.job_id)
        .await
        .map_err(|error| format!("issue token refused: {} ({})", error.code, error.message))?;
    let api = GitHubApi::new();
    let created = api
        .create_issue(&minted.token, &claimed.repository, &title, &body)
        .await;
    let revoked = api.revoke_installation_token(&minted.token).await;
    match created {
        Ok(number) => Ok((
            0,
            ResultReport {
                attempt: claimed.attempt,
                findings: manifest
                    .findings
                    .iter()
                    .map(|f| FindingOutcomeReport {
                        check_id: f.check_id.clone(),
                        identity: f.identity.clone(),
                        outcome: if verified
                            .iter()
                            .any(|v| v.check_id == f.check_id && v.identity == f.identity)
                        {
                            "issue_opened".into()
                        } else {
                            "unsupported".into()
                        },
                    })
                    .collect(),
                issue_number: Some(number),
                outcome_code: "issue_opened".into(),
                pull_request: None,
                summary: redact::summary(root, &format!("opened issue #{number}")),
                token_revoked: revoked,
            },
        )),
        Err(error) => Ok((1, declined("issue_failed", error, revoked))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::autofix::artifact::BriefArtifact;
    use crate::cli::autofix::brief::locate_findings;
    use crate::cli::autofix::repo::init_test_repo;
    use crate::connected_service::{ClaimedFinding, ClaimedJob};
    use sitecmd_engine::sync::ProjectFingerprintKey;

    const ROUTE: &str = "export async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const returnTo = searchParams.get(\"returnTo\") ?? \"/\";\n  return Response.redirect(new URL(returnTo, request.url), 302);\n}\n";

    fn fixture() -> (tempfile::TempDir, BriefArtifact, String) {
        let (repo, head) = init_test_repo(&[
            ("package.json", "{\"name\":\"loop\"}"),
            ("app/api/signin/route.ts", ROUTE),
        ])
        .unwrap();
        let key = ProjectFingerprintKey::from_bytes([7_u8; 32]);
        let identity = key.location_hash("open-redirect", "app/api/signin/route.ts");
        let matches = locate_findings(
            repo.path(),
            &key,
            &[("code_scan.open-redirect".into(), identity.clone())],
        )
        .unwrap();
        let brief = crate::cli::autofix::brief::brief_artifact("job_0123456789abcdef", 1, &matches);
        (repo, brief, head)
    }

    fn claimed(base: &str, identity: &str) -> ClaimedJob {
        ClaimedJob {
            agent: "claude".into(),
            attempt: 1,
            base_sha: base.into(),
            committer: None,
            default_branch: "main".into(),
            expires_at: "x".into(),
            findings: vec![ClaimedFinding {
                category: "security".into(),
                check_id: "code_scan.open-redirect".into(),
                class: "agent-easy".into(),
                fallback_class: None,
                identity: identity.into(),
            }],
            job_id: "job_0123456789abcdef".into(),
            job_token: "t".into(),
            opt_in_fixers: vec![],
            previous_failure: Some("the earlier attempt left the redirect".into()),
            purpose: "publish".into(),
            repository: "example-org/example-site".into(),
            site_url: "https://loop.example.com".into(),
        }
    }

    #[test]
    fn accepts_a_brief_the_checkout_confirms_and_renders_the_issue() {
        let (repo, mut brief, head) = fixture();
        // A wider range than the audit reported still selects the same issue,
        // and the issue's own line is what the brief prints.
        brief.findings[0].locations[0].start_line = 1;
        let verified = check_brief(repo.path(), &brief).unwrap();
        assert_eq!(verified.len(), 1);
        let line = verified[0].issue.line.unwrap();
        let (title, body) = render_issue(
            &claimed(&head, &brief.findings[0].identity),
            &verified,
            checkout_stack(repo.path()),
        );
        assert!(title.starts_with("SiteCMD: "));
        assert!(body.starts_with("@claude "));
        assert!(body.contains("## Where to look"));
        assert!(
            body.contains(&format!("`app/api/signin/route.ts:{line}`")),
            "{body}"
        );
        assert!(!body.contains("`app/api/signin/route.ts:1`"), "{body}");
        assert!(body.contains("Response.redirect"));
        assert!(body.contains("Open a pull request"));
        assert!(body.contains("## Previous attempt"));
        assert!(!body.contains("request_verification"));
    }

    #[test]
    fn rejects_an_excerpt_that_is_not_what_the_checkout_says() {
        let (repo, mut brief, _) = fixture();
        brief.findings[0].locations[0].excerpt = "something else".into();
        let rejected = check_brief(repo.path(), &brief).unwrap_err();
        assert!(rejected.reason.contains("excerpt"), "{}", rejected.reason);
    }

    #[test]
    fn rejects_a_path_outside_the_tree_and_a_line_the_audit_did_not_report() {
        let (repo, mut brief, _) = fixture();
        brief.findings[0].locations[0].path = "../etc/passwd".into();
        assert!(check_brief(repo.path(), &brief)
            .unwrap_err()
            .reason
            .contains("outside"));
        let (repo2, mut brief2, _) = fixture();
        brief2.findings[0].locations[0].start_line = 1;
        brief2.findings[0].locations[0].end_line = 1;
        assert!(check_brief(repo2.path(), &brief2)
            .unwrap_err()
            .reason
            .contains("line"));
    }

    #[test]
    fn reads_the_stack_from_the_checkout_and_nothing_from_a_bare_one() {
        let (repo, _) = init_test_repo(&[
            ("vercel.json", "{}"),
            (
                "package.json",
                "{\"dependencies\":{\"next\":\"14.2.3\"},\"devDependencies\":{\"react\":\"18.3.1\"}}",
            ),
        ])
        .unwrap();
        let stack = checkout_stack(repo.path()).unwrap();
        assert_eq!(stack["framework"], "Next.js");
        assert_eq!(stack["js_framework"], "React");
        assert_eq!(stack["cdn"], "Vercel");
        let (bare, _) = init_test_repo(&[("readme.md", "# loop\n")]).unwrap();
        assert!(checkout_stack(bare.path()).is_none());
    }

    #[test]
    fn verifies_every_location_when_a_rule_is_reported_twice_in_one_file() {
        let module = "import { pad } from \"left-pad\";\nimport { trim } from \"right-pad\";\n\nexport const value = pad(trim(\"x\"));\n";
        let (repo, _) = init_test_repo(&[
            ("package.json", "{\"name\":\"loop\"}"),
            ("app/lib/util.ts", module),
        ])
        .unwrap();
        let key = ProjectFingerprintKey::from_bytes([7_u8; 32]);
        let identity = key.location_hash("undeclared-package", "app/lib/util.ts");
        let matches = locate_findings(
            repo.path(),
            &key,
            &[("code_scan.undeclared-package".into(), identity)],
        )
        .unwrap();
        let brief = crate::cli::autofix::brief::brief_artifact("job_0123456789abcdef", 1, &matches);
        assert_eq!(brief.findings.len(), 1, "{brief:?}");
        assert_eq!(brief.findings[0].locations.len(), 2, "{brief:?}");
        let verified = check_brief(repo.path(), &brief).unwrap();
        assert_eq!(verified.len(), 2, "{verified:?}");
        for entry in &verified {
            let line = entry.issue.line.expect("the audit reported a line");
            assert!(
                line >= entry.location.start_line && line <= entry.location.end_line,
                "{entry:?}"
            );
        }
        let mut lines: Vec<u32> = verified.iter().filter_map(|v| v.issue.line).collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![1, 2], "{verified:?}");
    }
}
