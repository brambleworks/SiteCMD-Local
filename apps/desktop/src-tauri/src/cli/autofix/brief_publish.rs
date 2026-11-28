//! The agent path of the publish job: the fix job's artifact supplies check
//! ids, identities and locations, and every word of the issue comes from the
//! binary's own check text, the publish claim and the checkout the publish
//! job itself made.

use std::path::{Component, Path};

use sitecmd_protocol::identity::code_producer_rule_id;
use sitecmd_protocol::stack::DetectedStack;
use sitecmd_protocol::sync::ProjectFingerprintKey;

use super::artifact::{BriefArtifact, Manifest};
use super::brief::code_slug;
use super::exit_check::{CheckedBrief, HandedLines};
use super::github_api::GitHubApi;
use super::publish_job::{PublishJobArgs, PublishOutcome};
use super::secrets::site_fingerprint_key;
use crate::cli::ConnectStop;
use crate::connected_service::{
    ClaimedJob, ConnectedServiceClient, FindingOutcomeReport, ResultReport,
};
use crate::core::audit::{audit_observing_files, CodeIssue};
use crate::core::fix_templates::{build_check::package_json, hosts, HostKind};
use crate::core::fixes;
use sitecmd_protocol::engine_abi::{Brief, BriefTarget, BriefTargetLocation, Done, Task};

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
/// audit reported there. The exact line identifies the occurrence. Published
/// fields contain only occurrence metadata and binary-owned wording.
#[derive(Debug, Clone)]
pub struct VerifiedFinding {
    pub check_id: String,
    pub identity: String,
    pub issue: CodeIssue,
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
/// reported at that exact path and line. Anything else is a refusal,
/// because the artifact crossed an untrusted boundary.
///
/// The brief's exact line selects which reported issue a location means,
/// so a file the audit reports the rule at more than once still resolves.
pub fn verify_brief(
    root: &Path,
    brief: &BriefArtifact,
    key: &ProjectFingerprintKey,
    handed: &mut HandedLines,
) -> Result<Vec<VerifiedFinding>, BriefRejected> {
    let report =
        audit_observing_files(root, |bytes| handed.record_lines(bytes)).map_err(rejected)?;
    let engine = sitecmd_engine_host::load().map_err(|error| rejected(error.to_string()))?;
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
            // Exact lines distinguish repeated occurrences of one rule in a file.
            let issue = reported
                .into_iter()
                .find(|issue| {
                    issue.line == Some(location.start_line)
                        && location.start_line == location.end_line
                })
                .ok_or_else(|| {
                    rejected(format!(
                        "{at}: the reported line does not match the brief's line"
                    ))
                })?;
            if key.location_hash(slug, &issue.relative_path).as_str() != finding.identity {
                return Err(rejected(format!(
                    "{at}: the location does not match the claimed identity"
                )));
            }
            verified.push(VerifiedFinding {
                check_id: finding.check_id.clone(),
                identity: finding.identity.clone(),
                issue: crate::core::audit::published_issue(issue, engine.info())
                    .map_err(|error| rejected(error.into()))?,
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

/// Render the hosted issue for the agent named in the claim using locations
/// confirmed by [`verify_brief`], and retain the renderer input for the exit check.
pub fn render_issue(
    claimed: &ClaimedJob,
    verified: &[VerifiedFinding],
    stack: Option<serde_json::Value>,
) -> Result<(Brief, BriefTarget), String> {
    const INVALID_BRIEF: &str = "The engine returned an invalid autofix brief.";
    const MISSING_LOCATION: &str = "The autofix brief is missing a verified location.";
    let first = verified.first().ok_or(MISSING_LOCATION)?;
    let target = BriefTarget {
        agent: claimed.agent.clone(),
        attempt: claimed.attempt,
        check_id: first.check_id.clone(),
        description: first.issue.description.clone(),
        detected_stack: stack,
        likely_fix: first.issue.likely_fix.clone(),
        locations: verified
            .iter()
            .map(|finding| {
                Ok(BriefTargetLocation {
                    path: finding.issue.relative_path.clone(),
                    line: finding.issue.line.ok_or(MISSING_LOCATION)?,
                })
            })
            .collect::<Result<_, &str>>()?,
        severity: first.issue.severity,
        site_url: claimed.site_url.clone(),
        title: first.issue.title.clone(),
        why_now: first.issue.why_now.clone(),
    };
    match fixes::request(
        Task::Brief {
            target: target.clone(),
        },
        None,
    )? {
        Done::Brief(brief) => Ok((brief, target)),
        _ => Err(INVALID_BRIEF.into()),
    }
}

/// Confirm the brief against this checkout, render the issue, open it with a
/// per-operation issue token, hand the token back, and report. A brief the
/// checkout does not confirm is a reported refusal, not a failure that would
/// leave the job waiting.
pub(super) async fn publish_brief(
    args: &PublishJobArgs,
    root: &Path,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    job_client: &ConnectedServiceClient,
) -> Result<(u8, PublishOutcome), ConnectStop> {
    let brief = manifest.brief.as_ref().ok_or("manifest carries no brief")?;
    // A failure code carries no finding outcomes: Connect reads each
    // finding's fate only from a decline or a published result.
    let declined = |code: &str, message: String, revoked: bool| PublishOutcome {
        message,
        result: ResultReport {
            attempt: claimed.attempt,
            findings: Vec::new(),
            issue_number: None,
            outcome_code: code.parse().expect("fixed outcome code"),
            pull_request: None,
            token_revoked: revoked,
        },
    };
    let key = match site_fingerprint_key(&args.export, &args.passphrase_env) {
        Ok(key) => key,
        Err(error) => {
            let remedy = "Pass SITECMD_CONNECTION_EXPORT and SITECMD_CONNECTION_PASSPHRASE to the publish workflow.";
            return Ok((
                1,
                declined("brief_rejected", format!("{error}. {remedy}"), true),
            ));
        }
    };
    let mut handed = HandedLines::default();
    let verified = match verify_brief(root, brief, &key, &mut handed) {
        Ok(verified) => verified,
        Err(rejected) => return Ok((1, declined("brief_rejected", rejected.reason, true))),
    };
    let checked =
        render_issue(claimed, &verified, checkout_stack(root)).and_then(|(brief, target)| {
            CheckedBrief::hosted(brief, &handed, &target).map_err(|refusal| refusal.to_string())
        });
    let brief = match checked {
        Ok(brief) => brief,
        Err(reason) => return Ok((1, declined("brief_rejected", reason, true))),
    };
    let minted = job_client
        .issue_token(&claimed.job_id)
        .await
        .map_err(|error| ConnectStop::refused_as(&error, "issue token").unrecorded(""))?;
    let api = GitHubApi::new();
    let created = api
        .create_issue(&minted.token, &claimed.repository, &brief)
        .await;
    let revoked = api.revoke_installation_token(&minted.token).await;
    match created {
        Ok(number) => Ok((
            0,
            PublishOutcome {
                message: format!("opened issue #{number}"),
                result: ResultReport {
                    attempt: claimed.attempt,
                    findings: manifest
                        .findings
                        .iter()
                        .filter_map(|f| {
                            FindingOutcomeReport::new(
                                &f.check_id,
                                &f.identity,
                                if verified
                                    .iter()
                                    .any(|v| v.check_id == f.check_id && v.identity == f.identity)
                                {
                                    "issue_opened"
                                } else {
                                    "unsupported"
                                },
                            )
                        })
                        .collect(),
                    issue_number: Some(number),
                    outcome_code: "issue_opened".parse().expect("fixed outcome code"),
                    pull_request: None,
                    token_revoked: revoked,
                },
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

    const SOURCE: &str = "Fixture checkout line that must not enter a published issue.";

    fn fixture_key() -> ProjectFingerprintKey {
        ProjectFingerprintKey::from_bytes([7_u8; 32])
    }

    fn fixture() -> (tempfile::TempDir, BriefArtifact, String) {
        let (repo, head) = init_test_repo(&[
            ("package.json", "{\"name\":\"loop\"}"),
            (
                "app/api/signin/fixture-findings.txt",
                &format!("\n{SOURCE}\n"),
            ),
        ])
        .unwrap();
        let key = fixture_key();
        let identity = key.location_hash("standin.rule", "app/api/signin/fixture-findings.txt");
        let matches = locate_findings(
            repo.path(),
            &key,
            &[("code_scan.standin.rule".into(), identity.clone())],
        )
        .unwrap();
        let brief = crate::cli::autofix::brief::brief_artifact("job_0123456789abcdef", 1, &matches);
        (repo, brief, head)
    }

    #[test]
    fn brief_refuses_a_different_file_for_the_claimed_identity() {
        let (repo, mut brief, _) = fixture();
        let other = "app/api/other/fixture-findings.txt";
        std::fs::create_dir_all(repo.path().join("app/api/other")).unwrap();
        std::fs::write(repo.path().join(other), format!("\n{SOURCE}\n")).unwrap();
        brief.findings[0].locations[0].path = other.into();

        let refusal = verify_brief(
            repo.path(),
            &brief,
            &fixture_key(),
            &mut HandedLines::default(),
        )
        .unwrap_err();
        assert!(
            refusal
                .reason
                .contains("does not match the claimed identity"),
            "{refusal:?}"
        );
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
                check_id: "code_scan.standin.rule".into(),
                class: "agent-easy".into(),
                fallback_class: None,
                identity: identity.into(),
            }],
            job_id: "job_0123456789abcdef".into(),
            job_token: "t".into(),
            opt_in_fixers: vec![],
            purpose: "publish".into(),
            repository: "example-org/example-site".into(),
            site_url: "https://loop.example.com".into(),
        }
    }

    #[test]
    fn accepts_a_brief_the_checkout_confirms_and_renders_the_issue() {
        // A rendered issue can disclose the source line or point to the wrong location.
        let (repo, brief, head) = fixture();
        let mut handed = HandedLines::default();
        let verified = verify_brief(repo.path(), &brief, &fixture_key(), &mut handed).unwrap();
        assert_eq!(verified.len(), 1);
        let line = verified[0].issue.line.unwrap();
        let (Brief { title, body }, target) = render_issue(
            &claimed(&head, &brief.findings[0].identity),
            &verified,
            checkout_stack(repo.path()),
        )
        .unwrap();
        let Done::Brief(expected) = fixes::request(
            Task::Brief {
                target: target.clone(),
            },
            None,
        )
        .unwrap() else {
            panic!("missing module brief");
        };
        assert_eq!(title, expected.title);
        assert_eq!(body, expected.body);
        assert_eq!(target.agent, "claude");
        assert_eq!(target.check_id, "code_scan.standin.rule");
        assert_eq!(
            target.locations,
            [BriefTargetLocation {
                path: "app/api/signin/fixture-findings.txt".into(),
                line,
            }]
        );
        assert!(
            body.contains(&format!("`app/api/signin/fixture-findings.txt:{line}`")),
            "{body}"
        );
        assert!(
            !body.contains("`app/api/signin/fixture-findings.txt:1`"),
            "{body}"
        );
        assert!(!body.contains(SOURCE));
        assert!(!body.contains("## Previous attempt"));
        assert!(!body.contains("request_verification"));
        assert!(CheckedBrief::hosted(
            Brief {
                title: title.clone(),
                body
            },
            &handed,
            &target
        )
        .is_ok());
        let quoted = Brief {
            title,
            body: SOURCE.into(),
        };
        assert!(matches!(
            CheckedBrief::hosted(quoted, &handed, &target),
            Err(super::super::exit_check::ExitRefusal::HandedLine)
        ));
    }

    #[test]
    fn rejects_a_rule_that_the_checkout_does_not_report() {
        // A brief can refer to a rule absent from the fresh audit.
        let (repo, mut brief, _) = fixture();
        brief.findings[0].check_id = "code_scan.unknown-fixture-rule".into();
        let rejected = verify_brief(
            repo.path(),
            &brief,
            &fixture_key(),
            &mut HandedLines::default(),
        )
        .unwrap_err();
        assert!(rejected.reason.contains("finding"), "{}", rejected.reason);
    }

    #[test]
    fn rejects_legacy_source_fields_and_a_finding_removed_from_the_checkout() {
        // A stale brief can carry old findings or untrusted source fields.
        let (repo, brief, _) = fixture();
        let mut legacy = serde_json::to_value(&brief).unwrap();
        legacy["findings"][0]["locations"][0]["excerpt"] = "customer source".into();
        assert!(serde_json::from_value::<BriefArtifact>(legacy).is_err());
        std::fs::write(
            repo.path().join("app/api/signin/fixture-findings.txt"),
            "\n",
        )
        .unwrap();
        assert!(verify_brief(
            repo.path(),
            &brief,
            &fixture_key(),
            &mut HandedLines::default()
        )
        .is_err());
    }

    #[test]
    fn rejects_a_path_outside_the_tree_and_a_line_the_audit_did_not_report() {
        // A brief can point outside the checkout or at an unverified line.
        let (repo, mut brief, _) = fixture();
        brief.findings[0].locations[0].path = "../etc/passwd".into();
        assert!(verify_brief(
            repo.path(),
            &brief,
            &fixture_key(),
            &mut HandedLines::default()
        )
        .unwrap_err()
        .reason
        .contains("outside"));
        let (repo2, mut brief2, _) = fixture();
        brief2.findings[0].locations[0].start_line = 1;
        brief2.findings[0].locations[0].end_line = 1;
        assert!(verify_brief(
            repo2.path(),
            &brief2,
            &fixture_key(),
            &mut HandedLines::default()
        )
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
    fn verifies_each_location_in_a_synthetic_repeat_finding() {
        // A shared finding identity can leave only the first location verified.
        let source = "First fixture finding\nSecond fixture finding\n";
        let (repo, _) = init_test_repo(&[
            ("package.json", "{\"name\":\"loop\"}"),
            ("app/lib/fixture-findings.txt", source),
        ])
        .unwrap();
        let key = fixture_key();
        let identity = key.location_hash("standin.rule", "app/lib/fixture-findings.txt");
        let matches = locate_findings(
            repo.path(),
            &key,
            &[("code_scan.standin.rule".into(), identity)],
        )
        .unwrap();
        let brief = crate::cli::autofix::brief::brief_artifact("job_0123456789abcdef", 1, &matches);
        assert_eq!(brief.findings.len(), 1, "{brief:?}");
        assert_eq!(brief.findings[0].locations.len(), 2, "{brief:?}");
        let verified = verify_brief(
            repo.path(),
            &brief,
            &fixture_key(),
            &mut HandedLines::default(),
        )
        .unwrap();
        assert_eq!(verified.len(), 2, "{verified:?}");
        // Each verified finding is the one the brief's location at that
        // position selected, so its reported line is inside that range.
        for (entry, location) in verified.iter().zip(&brief.findings[0].locations) {
            let line = entry.issue.line.expect("the audit reported a line");
            assert!(
                line >= location.start_line && line <= location.end_line,
                "{entry:?} {location:?}"
            );
        }
        let mut lines: Vec<u32> = verified.iter().filter_map(|v| v.issue.line).collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![1, 2], "{verified:?}");
    }
}
