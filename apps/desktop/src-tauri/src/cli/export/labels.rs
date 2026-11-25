use crate::core::scan_types::Category;

pub(super) fn stack_summary_string(stack: Option<&serde_json::Value>) -> String {
    if let Some(s) = stack {
        if let Some(summary) = s.get("summary").and_then(|v| v.as_str()) {
            return summary.to_string();
        }
    }
    "Unknown".to_string()
}

pub(super) fn category_label(cat: &Category) -> &'static str {
    cat.key()
}

pub(super) fn category_display_name(cat: &Category) -> &'static str {
    cat.label()
}

/// Generate a concise verify command for a given check ID.
pub fn verify_hint(check_id: &str, url: &str) -> String {
    // Security headers - curl to inspect response headers
    if check_id.contains("security_header")
        || check_id.starts_with("security.headers.")
        || check_id.contains("headers.")
    {
        // Derive the header name from the check id segment after the last '.'
        let header_name = check_id
            .rsplit('.')
            .next()
            .unwrap_or("x-header")
            .replace('_', "-");
        return format!("curl -sI {} | grep -i {}", url, header_name);
    }

    if check_id.contains("https") && !check_id.contains("hsts") {
        let bare = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        return format!("curl -sI http://{} | head -1", bare);
    }

    "sitecmd scan --diff".to_string()
}
