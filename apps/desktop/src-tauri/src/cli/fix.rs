//! sitecmd fix command
//!
//! Reads the last scan result from `.sitecmd/last-scan.json` and outputs
//! fix text for failing issues: the module's AI-ready prompt for local
//! findings, ranked by severity, and Connect's fix guide for hosted
//! findings, ranked by severity.

use sitecmd_protocol::engine_abi::FixTextTarget;

use crate::cli::impact::{self, Applicability};
use crate::core::fixes::one_fix_text;
use crate::core::scan_types::ScanResult;
use crate::core::scan_types::{Category, CheckResult};

use super::hosted::report::{clean, Artifact, Finding, FixGuide};

const NO_GUIDE: &str = "SiteCMD doesn't have fix text for this check yet.";
const GUIDE_NOT_FETCHED: &str = "Run `sitecmd scan` again to fetch the fix text for this check.";
const DEVELOPER_STEPS: &str = "The details";
pub(super) const REFRESH_CACHE: &str = "Run `sitecmd scan` to refresh the cache.";

enum FixScan {
    Hosted(Box<Artifact>),
    Local(Box<ScanResult>),
}

enum FindingData<'a> {
    Local(&'a CheckResult),
    Hosted(&'a Finding),
}

struct FixIssue<'a> {
    data: FindingData<'a>,
    id: &'a str,
    category: Option<Category>,
    applicability: Applicability,
}

impl FixIssue<'_> {
    fn prompt(&self, url: &str, stack: Option<&serde_json::Value>) -> Result<String, String> {
        self.prompt_with(url, stack, one_fix_text)
    }

    fn prompt_with(
        &self,
        url: &str,
        stack: Option<&serde_json::Value>,
        module: impl FnOnce(FixTextTarget) -> Result<String, String>,
    ) -> Result<String, String> {
        match self.data {
            FindingData::Local(issue) => module(FixTextTarget::Web {
                issue: Box::new(issue.clone()),
                url: url.into(),
                detected_stack: stack.cloned(),
            }),
            FindingData::Hosted(issue) => Ok(hosted_text(issue)),
        }
    }
}

fn hosted_text(issue: &Finding) -> String {
    let body = match &issue.fix_guide {
        None => GUIDE_NOT_FETCHED.into(),
        Some(None) => NO_GUIDE.into(),
        Some(Some(guide)) => guide_text(guide),
    };
    format!("{} - {}\n\n{body}", issue.check_id, clean(&issue.title))
}

/// The guide's lead, owner steps, then developer steps, as the dashboard orders them.
fn guide_text(guide: &FixGuide) -> String {
    let mut blocks: Vec<String> = guide.lead.iter().map(|lead| terminal(lead)).collect();
    let developer = !guide.plain_only && !guide.steps.is_empty();
    if !guide.plain.is_empty() {
        blocks.push(numbered(&guide.plain));
        if developer {
            blocks.push(DEVELOPER_STEPS.into());
        }
    }
    if developer {
        blocks.push(numbered(&guide.steps));
    }
    if blocks.is_empty() {
        return NO_GUIDE.into();
    }
    blocks.join("\n\n")
}

fn numbered(steps: &[String]) -> String {
    let lines: Vec<_> = steps
        .iter()
        .enumerate()
        .map(|(index, step)| format!("{}. {}", index + 1, terminal(step)))
        .collect();
    lines.join("\n")
}

// Connect's text reaches the terminal, so line breaks and tabs are its only control characters.
fn terminal(text: &str) -> String {
    text.chars()
        .filter(|ch| matches!(ch, '\n' | '\t') || !ch.is_control())
        .collect()
}

impl FixScan {
    fn parse(contents: &str) -> Result<Self, String> {
        match serde_json::from_str(contents) {
            Ok(hosted) => Ok(Self::Hosted(hosted)),
            Err(hosted_error) => serde_json::from_str(contents).map(Self::Local).map_err(|local_error| {
                format!("Failed to parse last-scan.json. Hosted scan: {hosted_error}. Local scan: {local_error}. {REFRESH_CACHE}")
            }),
        }
    }

    fn issues(&self) -> Vec<FixIssue<'_>> {
        match self {
            Self::Local(scan) => impact::rank_issues(&scan.issues, scan.detected_stack.as_ref())
                .into_iter()
                .map(|row| FixIssue {
                    data: FindingData::Local(row.issue),
                    id: &row.issue.check_id,
                    category: row.issue.category,
                    applicability: row.applicability,
                })
                .collect(),
            Self::Hosted(artifact) => {
                let mut issues: Vec<_> = artifact.hosted.issues.iter().collect();
                issues.sort_by_key(|issue| issue.severity.sort_rank());
                issues
                    .into_iter()
                    .map(|issue| FixIssue {
                        data: FindingData::Hosted(issue),
                        id: &issue.check_id,
                        category: issue.category,
                        applicability: impact::classify_applicability(&issue.check_id, None),
                    })
                    .collect()
            }
        }
    }

    fn context(&self) -> (u32, &str, Option<&serde_json::Value>) {
        match self {
            Self::Local(scan) => (scan.overall_score, &scan.url, scan.detected_stack.as_ref()),
            Self::Hosted(artifact) => (artifact.hosted.score(), artifact.hosted.url.as_str(), None),
        }
    }
}

pub struct FixArgs {
    pub all: bool,
    pub id: Option<String>,
    pub type_filter: Option<String>,
    pub category: Option<Category>,
}

fn filtered<'a, 'b>(
    ranked: &'b [FixIssue<'a>],
    applicability: Option<&Applicability>,
    category: Option<Category>,
) -> Vec<&'b FixIssue<'a>> {
    ranked
        .iter()
        .filter(|ranked| {
            applicability.is_none_or(|value| ranked.applicability == *value)
                && category.is_none_or(|value| ranked.category == Some(value))
        })
        .collect()
}

fn read_scan(sitecmd_dir: &std::path::Path) -> Result<FixScan, String> {
    let contents = super::read_last_scan(sitecmd_dir)?
        .ok_or_else(|| "No scan data. Run `sitecmd scan` first.".to_string())?;

    FixScan::parse(&contents)
}

/// Run the fix subcommand.
///
/// Reads `.sitecmd/last-scan.json`, ranks issues by impact, applies any
/// filters, and prints fix text to stdout.
pub async fn run(args: FixArgs) -> Result<(), String> {
    let sitecmd_dir = crate::cli::find_config_dir()
        .ok_or_else(|| "No .sitecmd/ directory found. Run `sitecmd init` first.".to_string())?;

    let scan = read_scan(&sitecmd_dir)?;

    let ranked = scan.issues();
    let (score, url, detected_stack) = scan.context();

    if ranked.is_empty() {
        println!("No issues found. Score: {score}/100.");
        return Ok(());
    }

    if let Some(ref check_id) = args.id {
        let found = ranked.iter().find(|r| r.id == check_id);

        let ri = found.ok_or_else(|| {
            format!(
                "Issue '{}' not found in failing checks. Run `sitecmd scan` to see current issues.",
                check_id
            )
        })?;

        let prompt = ri.prompt(url, detected_stack)?;
        println!("{}", prompt);
        println!("\n---\nFix applied? Run `sitecmd scan --diff` to verify.");
        return Ok(());
    }

    let type_filter: Option<Applicability> = match args.type_filter.as_deref() {
        Some("code") => Some(Applicability::Code),
        Some("config") => Some(Applicability::Config),
        Some("content") => Some(Applicability::Content),
        Some(other) => {
            return Err(format!(
                "Unknown --type '{}'. Valid values: code, config, content.",
                other
            ));
        }
        None => None,
    };

    let filtered = filtered(&ranked, type_filter.as_ref(), args.category);

    if filtered.is_empty() {
        println!("No issues match the given filters. Score: {}/100.", score);
        return Ok(());
    }

    let divider = "=".repeat(72);

    if args.all {
        // Print ALL matching prompts separated by dividers
        for (i, ri) in filtered.iter().enumerate() {
            if i > 0 {
                println!("\n{}\n", divider);
            }
            let prompt = ri.prompt(url, detected_stack)?;
            println!("{}", prompt);
        }
    } else {
        let top = &filtered[0];
        let prompt = top.prompt(url, detected_stack)?;
        println!("{}", prompt);

        let remaining = filtered.len() - 1;
        if remaining > 0 {
            eprintln!(
                "{} more issue{} available. Use `sitecmd fix --all` to see all.",
                remaining,
                if remaining == 1 { "" } else { "s" }
            );
        }
    }

    println!("\n---\nFix applied? Run `sitecmd scan --diff` to verify.");

    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub struct FixScanHarness(FixScan);

#[cfg(any(test, feature = "test-support"))]
impl FixScanHarness {
    pub fn parse(contents: &str) -> Result<Self, String> {
        FixScan::parse(contents).map(Self)
    }

    pub fn first_prompt_with(
        &self,
        module: impl FnOnce(FixTextTarget) -> Result<String, String>,
    ) -> Result<String, String> {
        let (_, url, stack) = self.0.context();
        self.0.issues()[0].prompt_with(url, stack, module)
    }

    pub fn first_prompt(&self) -> Result<String, String> {
        let (_, url, stack) = self.0.context();
        self.0.issues()[0].prompt(url, stack)
    }
}

#[cfg(test)]
mod tests {
    use super::{run, FixArgs};

    #[cfg(unix)]
    #[test]
    fn fix_refuses_a_linked_scan_cache() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = dir.path().join("fixture.json");
        std::fs::write(&fixture, "{}").unwrap();
        std::os::unix::fs::symlink(fixture, dir.path().join("last-scan.json")).unwrap();
        let Err(error) = super::read_scan(dir.path()) else {
            panic!("accepted a linked scan cache");
        };
        assert!(error.contains("refused unsafe"), "{error}");
    }

    #[test]
    fn incompatible_cache_explains_how_to_refresh_it() {
        // An old cache fails to parse without saying how to replace it.
        let error = match super::FixScan::parse(&serde_json::json!({
            "url": "https://example.com", "mode": "live", "scanType": "health", "overallScore": 90,
            "categories": [{"category": "compliance", "score": 90, "issuesTotal": 1,
                "issuesCritical": 0, "issuesHigh": 1, "issuesMedium": 0, "issuesLow": 0, "issuesPassed": 0}],
            "issues": [], "durationMs": 1, "timestamp": "2026-11-14T00:00:00Z"
        }).to_string()) {
            Ok(_) => panic!("an old category must not parse"),
            Err(error) => error,
        };
        assert!(error.contains("unknown variant"));
        assert!(error.contains("last-scan.json"));
        assert!(error.contains("Run `sitecmd scan`"));
    }

    #[test]
    fn fix_category_keeps_only_that_category() {
        // fix --category matches by name fragment instead of the category key.
        let scan = super::FixScan::parse(&serde_json::json!({
            "url": "https://example.com", "mode": "live", "scanType": "health", "overallScore": 90,
            "categories": [], "durationMs": 1, "timestamp": "2026-11-14T00:00:00Z",
            "issues": [
                {"checkId": "security.dns.spf", "category": "email", "title": "SPF",
                    "description": "", "status": "fail", "severity": "high"},
                {"checkId": "security.csp", "category": "security", "title": "CSP",
                    "description": "", "status": "fail", "severity": "high"}
            ]
        }).to_string())
        .unwrap();
        let ranked = scan.issues();
        let email = Some(crate::core::scan_types::Category::Email);
        let selected = super::filtered(&ranked, None, email);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "security.dns.spf");
        let applicability = selected[0].applicability.clone();
        let excluded_applicability = match applicability {
            crate::cli::impact::Applicability::Code => crate::cli::impact::Applicability::Config,
            _ => crate::cli::impact::Applicability::Code,
        };
        assert_eq!(
            super::filtered(&ranked, Some(&applicability), email).len(),
            1
        );
        assert!(super::filtered(&ranked, Some(&excluded_applicability), email).is_empty());
        assert_eq!(super::filtered(&ranked, None, None).len(), 2);
    }

    #[test]
    fn prints_fix_text_for_a_synthetic_local_finding() {
        // The local fix command can discard the module's text or send the wrong finding context.
        let scan = super::FixScan::parse(r#"{
            "url":"http://localhost:8080/","mode":"predeploy","scanType":"health",
            "overallScore":100,"categories":[],"detectedStack":{"framework":"Fixture"},
            "issues":[{"checkId":"standin.rule","category":"reliability","status":"fail","severity":"low",
                "title":"Sample finding","description":"Fixture"}],
            "durationMs":0,"timestamp":"2026-01-01T00:00:00Z"
        }"#).unwrap();
        let (_, url, stack) = scan.context();
        let ranked = scan.issues();
        let text = ranked[0]
            .prompt_with(url, stack, |target| {
                let super::FixTextTarget::Web {
                    issue,
                    url,
                    detected_stack,
                } = target
                else {
                    panic!("expected a local finding");
                };
                assert_eq!(issue.check_id, "standin.rule");
                assert_eq!(url, "http://localhost:8080/");
                assert_eq!(detected_stack.unwrap()["framework"], "Fixture");
                Ok("Fixture fix text".into())
            })
            .unwrap();
        assert_eq!(text, "Fixture fix text");
        assert_eq!(
            ranked[0].prompt(url, stack).unwrap(),
            "Synthetic module guidance for Sample finding"
        );
    }

    #[test]
    fn guide_text_drops_terminal_controls_and_empty_sections() {
        // Bug: Connect's text can drive the terminal, or an owner-only guide prints a stray heading.
        let guide = |plain_only, plain: &[&str], steps: &[&str]| super::FixGuide {
            plain_only,
            lead: None,
            plain: plain.iter().map(|step| step.to_string()).collect(),
            steps: steps.iter().map(|step| step.to_string()).collect(),
        };
        assert_eq!(
            super::guide_text(&guide(true, &["Ask your host.\u{1b}[2J"], &[])),
            "1. Ask your host.[2J"
        );
        assert_eq!(
            super::guide_text(&guide(false, &[], &["```\nline\tone\r\n```"])),
            "1. ```\nline\tone\n```"
        );
        assert_eq!(super::guide_text(&guide(false, &[], &[])), super::NO_GUIDE);
        // An owner-only guide that also carries developer steps printed those steps.
        assert_eq!(
            super::guide_text(&guide(true, &["Ask your host."], &["Edit the config."])),
            "1. Ask your host."
        );
    }

    #[tokio::test]
    async fn fix_command_is_not_tier_gated() {
        let original = std::env::var_os("SITECMD_DB_PATH");
        let temp = tempfile::tempdir().expect("temp dir");
        let db_path = temp.path().join("missing-sitecmd.db");
        std::env::set_var("SITECMD_DB_PATH", &db_path);

        let result = run(FixArgs {
            all: false,
            id: None,
            type_filter: None,
            category: None,
        })
        .await;

        if let Some(value) = original {
            std::env::set_var("SITECMD_DB_PATH", value);
        } else {
            std::env::remove_var("SITECMD_DB_PATH");
        }

        let error = result.expect_err("no scan artifacts exist in the temp dir");
        assert!(
            !error.contains("paid plan"),
            "the fix command must not be tier-gated: {error}"
        );
    }
}
