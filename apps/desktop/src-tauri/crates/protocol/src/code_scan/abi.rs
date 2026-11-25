use crate::engine_abi::{AuditIssue, FileLocation, PathError, RelPath};

use super::CodeIssue;
use crate::identity::code_producer_rule_id;

impl TryFrom<CodeIssue> for AuditIssue {
    type Error = PathError;

    fn try_from(issue: CodeIssue) -> Result<Self, Self::Error> {
        let path = FileLocation::Listed(RelPath::parse(&issue.relative_path)?);
        Ok(audit_issue_at(issue, path))
    }
}

pub fn audit_issue_at(mut issue: CodeIssue, path: FileLocation) -> AuditIssue {
    let rule_id = code_producer_rule_id(&issue.id).to_owned();
    let id_path_offset = match path {
        FileLocation::Offer { .. } => omit_issue_path(&mut issue.id, &issue.relative_path),
        FileLocation::Listed(_) => None,
    };
    AuditIssue {
        rule_id,
        id_path_offset,
        path,
        id: issue.id,
        check_id: issue.check_id,
        category: issue.category,
        severity: issue.severity,
        title: issue.title,
        description: issue.description,
        line: issue.line,
        evidence: issue.evidence,
        why_now: issue.why_now,
        likely_fix: issue.likely_fix,
        confidence: issue.confidence,
        confidence_reason: issue.confidence_reason,
        verify_hint: issue.verify_hint,
        fix_prompt: None,
    }
}

fn omit_issue_path(id: &mut String, path: &str) -> Option<u32> {
    let first_separator = id.find(':')?;
    let suffix = &id[first_separator + 1..];
    let found = suffix
        .match_indices(path)
        .find_map(|(offset, _)| {
            let after = offset + path.len();
            ((offset == 0 || suffix.as_bytes()[offset - 1] == b':')
                && (after == suffix.len() || suffix.as_bytes()[after] == b':'))
                .then_some(first_separator + 1 + offset)
        })
        .or_else(|| suffix.find(path).map(|offset| first_separator + 1 + offset))?;
    id.replace_range(found..found + path.len(), "");
    u32::try_from(found).ok()
}

#[cfg(test)]
mod tests {
    use super::omit_issue_path;

    #[test]
    fn offered_issue_ids_omit_paths_regardless_of_separators() {
        for path in ["src/sign-in.ts", "src/sign:in.ts"] {
            for (prefix, suffix) in [("rule:kind:", ":42"), ("rule:[", "]:42")] {
                let full = format!("{prefix}{path}{suffix}");
                let mut id = full.clone();
                assert_eq!(omit_issue_path(&mut id, path), Some(prefix.len() as u32));
                assert_eq!(id, format!("{prefix}{suffix}"));
                id.insert_str(prefix.len(), path);
                assert_eq!(id, full);
            }
        }
    }
}
