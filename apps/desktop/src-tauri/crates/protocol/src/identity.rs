//! Delimiter-aware Code Scan identity helpers shared by scoring surfaces.

/// Producer rule from a Code Scan occurrence ID (`<rule>:<path>` -> `<rule>`).
pub fn code_producer_rule_id(issue_id: &str) -> &str {
    issue_id.split(':').next().unwrap_or(issue_id)
}

/// Rejects legacy location-bearing Code identities after the migration boundary.
pub fn validate_canonical_check_id(check_id: &str) -> Result<(), String> {
    if check_id.trim().is_empty() {
        return Err("canonical check_id must not be empty".to_string());
    }
    if let Some(rule) = check_id.strip_prefix("code_scan.") {
        if rule.is_empty() {
            return Err("canonical Code check_id must include a rule".to_string());
        }
        if rule.contains(':') {
            return Err(format!(
                "path-bearing Code check_id '{check_id}' is not canonical; pass the rule-level check_id and a structured occurrence target"
            ));
        }
    }
    Ok(())
}

/// Rule ID from a unified `code_scan.<rule>` check ID.
pub fn code_rule_id(check_id: &str) -> Option<&str> {
    let rest = check_id.strip_prefix("code_scan.")?;
    Some(rest.split(':').next().unwrap_or(rest))
}
