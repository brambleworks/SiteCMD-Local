//! Recreate template edits from the trusted claim, never from artifact source.

use sitecmd_protocol::engine_abi::{Done, FixTarget, FixUnavailable, FixerInfo, Patch, Task};

use super::apply::check_write_set;
use super::artifact::Manifest;
use super::exit_check::HandedLines;
use crate::connected_service::ClaimedJob;
use crate::core::{fixes, project_listing::ProjectListing};

pub(crate) fn catalog() -> Result<Vec<FixerInfo>, String> {
    match fixes::request(Task::FixCatalog {}, None)? {
        Done::FixCatalog(fixers) => Ok(fixers),
        _ => Err("The engine returned an invalid template catalog.".into()),
    }
}

pub(super) enum TemplateFix {
    Patches(Vec<Patch>),
    Unavailable(FixUnavailable),
}

pub(super) fn plan_finding(
    project: &ProjectListing,
    target: FixTarget,
    fixer: &FixerInfo,
) -> Result<TemplateFix, String> {
    plan_with_reads(project, target, fixer, |_, _| {})
}

fn plan_with_reads(
    project: &ProjectListing,
    target: FixTarget,
    fixer: &FixerInfo,
    handed_file: impl FnMut(&sitecmd_protocol::engine_abi::RelPath, &[u8]),
) -> Result<TemplateFix, String> {
    if let Some(path) = fixer
        .write_set
        .iter()
        .find(|path| project.contains_symlink(path))
    {
        return Err(crate::core::fix_templates::symlink_refusal(path.as_str()));
    }
    match fixes::request_with_file(Task::FixPlan { target }, Some(project), handed_file)? {
        Done::FixPlan(plan) => {
            const EMPTY_PLAN: &str = "The engine returned an empty template plan.";
            if plan.patches.is_empty() {
                return Err(EMPTY_PLAN.into());
            }
            check_write_set(&plan.patches, |path| fixer.write_set.contains(path))?;
            Ok(TemplateFix::Patches(plan.patches))
        }
        Done::FixUnavailable(refusal) => Ok(TemplateFix::Unavailable(refusal)),
        _ => Err("The engine returned an invalid template response.".into()),
    }
}

pub(super) fn regenerate(
    project: &ProjectListing,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    catalog: &[FixerInfo],
    handed: &mut HandedLines,
) -> Result<Vec<Patch>, String> {
    let mut patches = Vec::new();
    let mut paths = Vec::new();
    for finding in &claimed.findings {
        if !manifest.findings.iter().any(|entry| {
            entry.check_id == finding.check_id
                && entry.identity == finding.identity
                && entry.outcome.as_deref() == Some("applied")
        }) {
            continue;
        }
        let fixer = catalog
            .iter()
            .find(|fixer| fixer.check_id == finding.check_id)
            .ok_or("no template fixer")?;
        let target = FixTarget {
            check_id: finding.check_id.clone(),
            identity: finding.identity.clone(),
        };
        match plan_with_reads(project, target, fixer, |path, bytes| {
            handed.record(path, bytes)
        })? {
            TemplateFix::Patches(entries) => patches.extend(entries),
            TemplateFix::Unavailable(reason) => {
                return Err(match reason {
                    FixUnavailable::NoTemplate => "no template fixer",
                    FixUnavailable::NoHost => "no recognized host configuration",
                    FixUnavailable::AlreadySatisfied { .. } => "template already sets it",
                    FixUnavailable::Unsupported { .. } => "template prerequisites are not met",
                }
                .into());
            }
        }
        paths.extend(fixer.write_set.iter().map(|path| path.as_str().to_owned()));
    }
    paths.sort();
    paths.dedup();
    let mut expected = manifest.write_set.clone();
    expected.sort();
    expected.dedup();
    if paths.is_empty() || paths != expected {
        return Err("template plan does not match the publish checkout's write set".into());
    }
    Ok(patches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_artifact_with_a_tampered_write_set() {
        // A supplied write set can authorize changes outside the module patch.
        let (root, base_sha) =
            crate::cli::autofix::repo::init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
        let claimed: ClaimedJob = serde_json::from_value(serde_json::json!({
            "agent": "claude", "attempt": 1, "base_sha": base_sha,
            "default_branch": "main", "expires_at": "x", "job_id": "job_0123456789abcdef",
            "job_token": "test", "purpose": "publish", "repository": "example/site", "site_url": "https://example.com",
            "findings": [{ "category": "security", "check_id": "standin.rule", "class": "template", "identity": "/" }]
        })).unwrap();
        let mut manifest = Manifest {
            schema_version: super::super::artifact::ARTIFACT_SCHEMA_VERSION,
            job_id: claimed.job_id.clone(),
            attempt: 1,
            base_sha: claimed.base_sha.clone(),
            outcome_code: None,
            write_set: vec!["vercel.json".into()],
            findings: vec![super::super::artifact::ManifestFinding {
                check_id: claimed.findings[0].check_id.clone(),
                identity: "/".into(),
                outcome: Some("applied".into()),
            }],
            brief: None,
        };
        let project = crate::core::project_listing::list_project(root.path()).unwrap();
        let catalog = catalog().unwrap();
        let patches = regenerate(
            &project,
            &claimed,
            &manifest,
            &catalog,
            &mut HandedLines::default(),
        )
        .unwrap();
        assert_eq!(patches.len(), 1);
        assert!(patches[0].content.contains("\"example\":true"));
        manifest.write_set = vec![".github/workflows/deploy.yml".into()];
        assert!(regenerate(
            &project,
            &claimed,
            &manifest,
            &catalog,
            &mut HandedLines::default()
        )
        .is_err());
        assert_eq!(
            std::fs::read_to_string(root.path().join("vercel.json")).unwrap(),
            "{}\n"
        );
    }
}
