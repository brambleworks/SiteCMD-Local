//! What crosses from the untrusted fix job to the trusted publish job:
//! `manifest.json` and `patch.diff` inside the workflow artifact
//! `sitecmd-job-<job id>`. Data only, never executed, and carrying no prose
//! for an agent.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const ARTIFACT_SCHEMA_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_PATCH_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefArtifactLocation {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefFinding {
    pub check_id: String,
    pub identity: String,
    pub locations: Vec<BriefArtifactLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefArtifact {
    pub job_id: String,
    pub attempt: u32,
    pub findings: Vec<BriefFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFinding {
    pub check_id: String,
    pub identity: String,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u16,
    pub job_id: String,
    pub attempt: u32,
    pub base_sha: String,
    pub outcome_code: Option<String>,
    pub summary: String,
    pub write_set: Vec<String>,
    pub findings: Vec<ManifestFinding>,
    pub brief: Option<BriefArtifact>,
}

pub fn write_artifact(dir: &Path, manifest: &Manifest, patch: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let encoded = serde_json::to_string_pretty(manifest)
        .map_err(|error| format!("manifest could not be encoded: {error}"))?;
    std::fs::write(dir.join("manifest.json"), encoded)
        .map_err(|error| format!("manifest.json could not be written: {error}"))?;
    std::fs::write(dir.join("patch.diff"), patch)
        .map_err(|error| format!("patch.diff could not be written: {error}"))?;
    Ok(())
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<String, String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("{label} could not be read: {error}"))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("{label} is not a bounded regular file"));
    }
    std::fs::read_to_string(path).map_err(|error| format!("{label} could not be read: {error}"))
}

pub fn read_artifact(dir: &Path) -> Result<(Manifest, String), String> {
    let manifest_text = read_bounded(&dir.join("manifest.json"), MAX_MANIFEST_BYTES, "manifest")?;
    let manifest: Manifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("manifest is not valid: {error}"))?;
    if manifest.schema_version != ARTIFACT_SCHEMA_VERSION {
        return Err(format!(
            "manifest schema {} is not {ARTIFACT_SCHEMA_VERSION}",
            manifest.schema_version
        ));
    }
    let patch = read_bounded(&dir.join("patch.diff"), MAX_PATCH_BYTES, "patch")?;
    Ok((manifest, patch))
}

pub fn has_something_to_publish(manifest: &Manifest, patch: &str) -> bool {
    !patch.trim().is_empty()
        || manifest
            .brief
            .as_ref()
            .is_some_and(|brief| brief.findings.iter().any(|f| !f.locations.is_empty()))
}

pub fn write_outputs(path: &Path, publish: bool) -> Result<(), String> {
    std::fs::write(path, format!("publish={publish}\n"))
        .map_err(|error| format!("{} could not be written: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            attempt: 1,
            base_sha: "0".repeat(40),
            brief: None,
            findings: vec![ManifestFinding {
                check_id: "security.headers.x_content_type_options".into(),
                identity: "/".into(),
                outcome: Some("applied".into()),
            }],
            job_id: "job_0123456789abcdef".into(),
            outcome_code: None,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            summary: "planned".into(),
            write_set: vec!["vercel.json".into()],
        }
    }

    #[test]
    fn round_trips_manifest_and_patch() {
        let temp = tempfile::tempdir().unwrap();
        write_artifact(
            temp.path(),
            &manifest(),
            "diff --git a/vercel.json b/vercel.json\n",
        )
        .unwrap();
        let (read, patch) = read_artifact(temp.path()).unwrap();
        assert_eq!(read, manifest());
        assert_eq!(patch, "diff --git a/vercel.json b/vercel.json\n");
        assert!(temp.path().join("manifest.json").is_file());
        assert!(temp.path().join("patch.diff").is_file());
    }

    #[test]
    fn something_to_publish_means_a_patch_or_a_brief_with_locations() {
        assert!(!has_something_to_publish(&manifest(), ""));
        assert!(has_something_to_publish(&manifest(), "diff"));
        let mut with_brief = manifest();
        with_brief.brief = Some(BriefArtifact {
            attempt: 1,
            findings: vec![BriefFinding {
                check_id: "code_scan.open-redirect".into(),
                identity: "f".repeat(64),
                locations: vec![BriefArtifactLocation {
                    end_line: 3,
                    excerpt: "x".into(),
                    path: "app/route.ts".into(),
                    start_line: 3,
                }],
            }],
            job_id: "job_0123456789abcdef".into(),
        });
        assert!(has_something_to_publish(&with_brief, ""));
        with_brief.brief.as_mut().unwrap().findings[0]
            .locations
            .clear();
        assert!(!has_something_to_publish(&with_brief, ""));
    }

    #[test]
    fn refuses_unknown_fields_and_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("manifest.json"), r#"{"schema_version":1,"job_id":"job_0123456789abcdef","attempt":1,"base_sha":"0","outcome_code":null,"summary":"","write_set":[],"findings":[],"brief":null,"extra":1}"#).unwrap();
        std::fs::write(temp.path().join("patch.diff"), "").unwrap();
        assert!(read_artifact(temp.path()).unwrap_err().contains("manifest"));
        std::fs::write(
            temp.path().join("manifest.json"),
            serde_json::to_string(&manifest()).unwrap(),
        )
        .unwrap();
        std::fs::write(
            temp.path().join("patch.diff"),
            vec![b'x'; 8 * 1024 * 1024 + 1],
        )
        .unwrap();
        assert!(read_artifact(temp.path()).unwrap_err().contains("patch"));
    }

    #[test]
    fn writes_the_outputs_file_the_action_appends() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("outputs.txt");
        write_outputs(&path, true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "publish=true\n");
    }
}
