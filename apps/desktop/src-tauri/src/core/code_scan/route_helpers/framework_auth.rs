use super::*;

#[derive(Debug, Default, Clone)]

pub(in crate::core::code_scan) struct NextMiddlewareProtection {
    pub(in crate::core::code_scan) global: bool,
    pub(in crate::core::code_scan) prefixes: Vec<String>,
}

impl NextMiddlewareProtection {
    fn covers(&self, route_path: &str) -> bool {
        self.global
            || self
                .prefixes
                .iter()
                .any(|prefix| route_path.starts_with(prefix))
    }
}

/// Findings that assert an unauthenticated caller can reach the route. A
/// resolved framework gate in front of the route contradicts both.
const AUTH_GATED_ISSUE_PREFIXES: &[&str] = &["sensitive-auth:", "public-endpoint-rate-limit:"];

/// The finding that asserts no role, ownership, or capability decision was
/// made. A guarding layout that reads the role contradicts it.
const AUTHZ_GATED_ISSUE_PREFIX: &str = "sensitive-authz:";

pub(in crate::core::code_scan) fn apply_framework_auth_overrides(
    framework: Option<&str>,
    files: &[SourceFile],
    issues: &mut Vec<CodeIssue>,
) {
    let middleware_protection = if framework == Some("Next.js") {
        collect_next_middleware_protection(files)
    } else {
        NextMiddlewareProtection::default()
    };
    let layout_protection = collect_layout_auth_protection(files);
    let has_middleware_protection =
        middleware_protection.global || !middleware_protection.prefixes.is_empty();
    if !has_middleware_protection && layout_protection.is_empty() {
        return;
    }

    issues.retain(|issue| {
        let relative_path = issue.relative_path.replace('\\', "/");
        if issue.id.starts_with(AUTHZ_GATED_ISSUE_PREFIX) {
            return !layout_protection.decides_authorization(&relative_path);
        }
        if !AUTH_GATED_ISSUE_PREFIXES
            .iter()
            .any(|prefix| issue.id.starts_with(prefix))
        {
            return true;
        }
        if layout_protection.authenticates(&relative_path) {
            return false;
        }
        if !has_middleware_protection {
            return true;
        }
        let Some(route_path) = route_path_from_relative_path(&issue.relative_path) else {
            return true;
        };
        !middleware_protection.covers(&route_path)
    });
}

/// Directory prefixes whose descendants a Remix / React Router layout route
/// already gates, split by what the layout decides.
#[derive(Debug, Default, Clone)]
pub(in crate::core::code_scan) struct LayoutGuardProtection {
    authenticated: Vec<String>,
    authorized: Vec<String>,
}

impl LayoutGuardProtection {
    fn is_empty(&self) -> bool {
        self.authenticated.is_empty()
    }

    fn authenticates(&self, relative_path: &str) -> bool {
        Self::covers(&self.authenticated, relative_path)
    }

    fn decides_authorization(&self, relative_path: &str) -> bool {
        Self::covers(&self.authorized, relative_path)
    }

    fn covers(prefixes: &[String], relative_path: &str) -> bool {
        prefixes
            .iter()
            .any(|prefix| relative_path.starts_with(prefix.as_str()))
    }
}

/// A `_layout` file that reads the session and redirects when it is absent
/// protects every route nested beneath it, including the nested `admin+` style
/// segments that carry no in-file auth of their own. When that same layout also
/// reads the caller's role, it owns the authorization decision as well.
pub(in crate::core::code_scan) fn collect_layout_auth_protection(
    files: &[SourceFile],
) -> LayoutGuardProtection {
    let mut protection = LayoutGuardProtection::default();
    for file in files {
        let normalized = file.relative_path.replace('\\', "/");
        let Some((directory, file_name)) = normalized.rsplit_once('/') else {
            continue;
        };
        let is_layout_route = ["_layout.tsx", "_layout.jsx", "_layout.ts", "_layout.js"]
            .iter()
            .any(|candidate| file_name.eq_ignore_ascii_case(candidate));
        if !is_layout_route {
            continue;
        }
        if !layout_redirects_unauthenticated(&file.content) {
            continue;
        }
        let prefix = format!("{directory}/");
        if !protection.authenticated.contains(&prefix) {
            protection.authenticated.push(prefix.clone());
        }
        if has_any(&file.content, &AUTHZ_PATTERNS) && !protection.authorized.contains(&prefix) {
            protection.authorized.push(prefix);
        }
    }
    protection
}

/// Whether a layout route resolves the caller's identity and redirects when it
/// is missing. Both halves are required: reading a session without acting on it
/// is not a gate.
fn layout_redirects_unauthenticated(content: &str) -> bool {
    let identifies_caller =
        has_any(content, &AUTH_PATTERNS) || has_any(content, &SESSION_LOOKUP_PATTERNS);
    identifies_caller && content.to_ascii_lowercase().contains("redirect(")
}

pub(in crate::core::code_scan) fn collect_next_middleware_protection(
    files: &[SourceFile],
) -> NextMiddlewareProtection {
    let mut protection = NextMiddlewareProtection::default();

    for file in files {
        if !is_next_middleware_file(&file.relative_path) {
            continue;
        }
        let lower = file.content.to_ascii_lowercase();
        if !(has_any(&file.content, &AUTH_PATTERNS)
            || has_inline_secret_guard(&lower)
            || lower.contains("withauth")
            || lower.contains("clerkmiddleware"))
        {
            continue;
        }

        let matcher_section = lower
            .find("matcher")
            .map(|index| &file.content[index..])
            .unwrap_or(&file.content);
        let mut found_prefix = false;
        for pattern in NEXT_MIDDLEWARE_MATCHER_PATTERNS.iter() {
            for capture in pattern.captures_iter(matcher_section) {
                let Some(raw_matcher) = capture.get(1).map(|value| value.as_str()) else {
                    continue;
                };
                let Some(prefix) = normalize_middleware_matcher(raw_matcher) else {
                    continue;
                };
                found_prefix = true;
                if !protection.prefixes.contains(&prefix) {
                    protection.prefixes.push(prefix);
                }
            }
        }

        if !found_prefix {
            protection.global = true;
        }
    }

    protection
}

pub(in crate::core::code_scan) fn is_next_middleware_file(relative_path: &str) -> bool {
    let normalized = relative_path.replace('\\', "/").to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "middleware.ts" | "middleware.js" | "src/middleware.ts" | "src/middleware.js"
    )
}

pub(in crate::core::code_scan) fn normalize_middleware_matcher(
    raw_matcher: &str,
) -> Option<String> {
    if !raw_matcher.starts_with('/') {
        return None;
    }

    let mut normalized = raw_matcher.to_string();
    if let Some(prefix) = normalized.split(':').next() {
        normalized = prefix.to_string();
    }
    normalized = normalized.replace("(.*)", "");
    normalized = normalized.replace('*', "");
    normalized = normalized.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(in crate::core::code_scan) fn route_path_from_relative_path(
    relative_path: &str,
) -> Option<String> {
    let normalized = relative_path.replace('\\', "/");
    let trimmed = normalized.strip_prefix("src/").unwrap_or(&normalized);

    if let Some(rest) = trimmed.strip_prefix("app/") {
        for suffix in ["/route.ts", "/route.js", "/route.tsx", "/route.jsx"] {
            if let Some(route) = rest.strip_suffix(suffix) {
                return Some(normalize_route_path(route));
            }
        }
    }

    if let Some(rest) = trimmed.strip_prefix("pages/") {
        for suffix in [".ts", ".js", ".tsx", ".jsx"] {
            if let Some(route) = rest.strip_suffix(suffix) {
                return Some(normalize_route_path(route));
            }
        }
    }

    None
}

pub(in crate::core::code_scan) fn normalize_route_path(route: &str) -> String {
    let mut parts = Vec::new();
    for segment in route.split('/') {
        if segment.is_empty() || (segment.starts_with('(') && segment.ends_with(')')) {
            continue;
        }
        parts.push(segment);
    }
    format!("/{}", parts.join("/"))
}
