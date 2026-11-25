//! Versioned metadata fingerprints shared by reports, suppressions, and fix guards.

use super::CodeIssue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const PREFIX: &str = "sitecmd/v3:sha256:";
pub const SARIF_KEY: &str = "sitecmd/v3";

pub fn fingerprint(rule: &str, path: &str, ordinal: usize) -> String {
    let material = format!(
        "sitecmd-code-ordinal-v3\0{rule}\0{}\0{ordinal}",
        path.replace('\\', "/")
    );
    format!(
        "{PREFIX}{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

/// Return one ordinal per input finding, sorting each rule and path group by line.
/// Line-less findings sort last and ties retain input order without reading source.
pub fn ordinals(issues: &[CodeIssue]) -> Vec<usize> {
    let mut indices: Vec<_> = (0..issues.len()).collect();
    indices.sort_by_key(|&index| issues[index].line.unwrap_or(u32::MAX));
    let mut counts = HashMap::new();
    let mut result = vec![0; issues.len()];
    for index in indices {
        let issue = &issues[index];
        let count = counts
            .entry((
                issue.check_id.as_str(),
                issue.relative_path.replace('\\', "/"),
            ))
            .or_insert(0);
        *count += 1;
        result[index] = *count;
    }
    result
}
