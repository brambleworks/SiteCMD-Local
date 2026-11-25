//! Fix requests and responses shared by the module and host.

use serde::{Deserialize, Serialize};

use crate::code_scan::CodeIssue;
use crate::vocab::{CheckResult, Severity};

use super::types::RelPath;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixTarget {
    pub check_id: String,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub path: RelPath,
    pub base_sha256: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixPlan {
    pub patches: Vec<Patch>,
}

impl Patch {
    pub fn hash_base(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixerInfo {
    pub check_id: String,
    pub title: String,
    pub write_set: Vec<RelPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FixUnavailable {
    NoTemplate,
    NoHost,
    AlreadySatisfied { path: RelPath },
    Unsupported { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FixTextTarget {
    Web {
        issue: Box<CheckResult>,
        url: String,
        detected_stack: Option<serde_json::Value>,
    },
    Hosted {
        category: String,
        title: String,
        severity: Severity,
        url: String,
    },
    Code {
        issue: Box<CodeIssue>,
        framework: String,
    },
}

/// Verified finding metadata used to render a GitHub issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefTarget {
    pub agent: String,
    pub attempt: u32,
    pub check_id: String,
    pub description: String,
    pub detected_stack: Option<serde_json::Value>,
    pub likely_fix: Option<String>,
    pub locations: Vec<BriefTargetLocation>,
    pub severity: Severity,
    pub site_url: String,
    pub title: String,
    pub why_now: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefTargetLocation {
    pub path: String,
    pub line: u32,
}
