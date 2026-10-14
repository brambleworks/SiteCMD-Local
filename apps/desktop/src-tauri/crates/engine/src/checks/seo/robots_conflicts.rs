//! Contradictory page-level robots directives within one crawler scope.

use super::parsing::extract_attr_value;
use crate::checks::seo::robots_tag;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use crate::header_lines::HeaderLines;
use std::collections::{BTreeMap, BTreeSet};

pub struct MetaRobotsConflictCheck;

const GENERAL_ROBOTS_SCOPE: &str = "all-crawlers";

fn add_polarity_directives(
    by_scope: &mut BTreeMap<String, BTreeSet<String>>,
    scope: &str,
    content: &str,
) {
    let directives = by_scope.entry(scope.to_string()).or_default();
    for token in content
        .split(|character: char| character == ',' || character.is_ascii_whitespace())
        .map(|token| token.trim().trim_matches(':').to_ascii_lowercase())
    {
        match token.as_str() {
            "index" | "noindex" | "follow" | "nofollow" => {
                directives.insert(token);
            }
            "none" => {
                directives.insert("noindex".into());
                directives.insert("nofollow".into());
            }
            "all" => {
                directives.insert("index".into());
                directives.insert("follow".into());
            }
            _ => {}
        }
    }
}

fn normalized_robots_scope(raw: &str) -> Option<String> {
    let scope = robots_tag::crawler_name(raw)?;
    Some(if matches!(scope.as_str(), "*" | "robots") {
        GENERAL_ROBOTS_SCOPE.into()
    } else {
        scope
    })
}

fn robots_scope_label(scope: &str) -> String {
    match scope {
        GENERAL_ROBOTS_SCOPE => "General crawler".into(),
        "googlebot" => "Googlebot".into(),
        "googlebot-news" => "Googlebot-News".into(),
        "bingbot" => "Bingbot".into(),
        other => other.to_string(),
    }
}

/// The directives each crawler scope declares, and how many declarations
/// declared them.
#[derive(Clone, Default)]
struct Declared {
    by_scope: BTreeMap<String, BTreeSet<String>>,
    meta_tags: usize,
    header_values: usize,
}

/// The page's robots meta tags.
fn meta_declarations(body: &str) -> Declared {
    let mut declared = Declared::default();
    let scannable = crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(body, " ");
    let lower = scannable.to_ascii_lowercase();
    for tag in crate::checks::html_attrs::tag_slices(&scannable, &lower, "meta") {
        let Some(name) = extract_attr_value(tag, "name").map(|name| name.to_ascii_lowercase())
        else {
            continue;
        };
        let scope = match name.as_str() {
            "robots" => GENERAL_ROBOTS_SCOPE,
            "googlebot" | "googlebot-news" | "bingbot" => name.as_str(),
            _ => continue,
        };
        if let Some(content) = extract_attr_value(tag, "content") {
            declared.meta_tags += 1;
            add_polarity_directives(&mut declared.by_scope, scope, &content);
        }
    }
    declared
}

/// The meta tags' declarations with these X-Robots-Tag lines added.
fn with_header_lines(meta: &Declared, x_robots_tag: &[String]) -> Declared {
    let mut declared = meta.clone();
    declared.header_values = x_robots_tag.len();
    for header_value in x_robots_tag {
        let mut current_scope = GENERAL_ROBOTS_SCOPE.to_string();
        for clause in header_value
            .split(',')
            .map(str::trim)
            .filter(|clause| !clause.is_empty())
        {
            if let Some((prefix, content)) = clause.split_once(':') {
                let Some(scope) = normalized_robots_scope(prefix) else {
                    continue;
                };
                current_scope = scope;
                add_polarity_directives(&mut declared.by_scope, &current_scope, content);
            } else {
                add_polarity_directives(&mut declared.by_scope, &current_scope, clause);
            }
        }
    }
    declared
}

/// Each scope's contradictions, in scope order.
fn conflicts(declared: &Declared) -> Vec<String> {
    let mut conflicts = Vec::new();
    for (scope, directives) in &declared.by_scope {
        let label = robots_scope_label(scope);
        if directives.contains("index") && directives.contains("noindex") {
            conflicts.push(format!(
                "{label} scope declares index and noindex; noindex is the restrictive outcome"
            ));
        }
        if directives.contains("follow") && directives.contains("nofollow") {
            conflicts.push(format!(
                "{label} scope declares follow and nofollow; nofollow is the restrictive outcome"
            ));
        }
    }
    conflicts
}

impl Check for MetaRobotsConflictCheck {
    fn id(&self) -> &str {
        "seo.meta_conflicts"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        Self::evaluate(ctx, HeaderLines::Separate)
    }
}

impl MetaRobotsConflictCheck {
    /// The verdict, with the page's header lines as the runtime handed them
    /// over. In any split of a joined value a clause after a name lands in
    /// that name's scope, as read as it arrived, or in every crawler's, as
    /// read one line per clause, so a split conflicts only where one of those
    /// two readings does: the value passes when both pass. It fails when the
    /// clauses whose scope every split gives conflict on their own. Anything
    /// else declines, including a value every split of which conflicts only
    /// through a clause after a name.
    pub fn evaluate(ctx: &PageContext, lines: HeaderLines) -> Vec<CheckResult> {
        let meta = meta_declarations(&ctx.body);
        let readings = robots_tag::readings(&ctx.response_headers, lines);
        let as_arrived = with_header_lines(&meta, &readings.as_arrived);
        let (Some(per_clause), Some(fixed)) = (&readings.per_clause, &readings.fixed) else {
            return vec![graded(&as_arrived)];
        };
        let fixed = with_header_lines(&meta, fixed);
        vec![if conflicts(&as_arrived).is_empty()
            && conflicts(&with_header_lines(&meta, per_clause)).is_empty()
        {
            graded(&as_arrived)
        } else if !conflicts(&fixed).is_empty() {
            graded(&fixed)
        } else {
            scope_not_established()
        }]
    }
}

fn graded(declared: &Declared) -> CheckResult {
    let conflicts = conflicts(declared);
    let declaration_count = declared.meta_tags + declared.header_values;
    CheckResult {
        check_id: "seo.meta_conflicts".into(),
        category: ScanCategory::Seo,
        title: if conflicts.is_empty() {
            "Page-level robots directive consistency".into()
        } else {
            "Contradictory page-level robots directives".into()
        },
        description: if conflicts.is_empty() {
            if declaration_count == 0 {
                "No supported page-level robots meta tags or X-Robots-Tag header values were observed. This check does not inspect robots.txt and does not establish that the URL is crawlable, indexable, canonical, or selected for indexing.".into()
            } else {
                format!(
                    "No contradictory index/noindex or follow/nofollow pair was observed within the same crawler scope across {} parsed page-level declaration{}. Supporting crawlers can combine applicable declarations; this check does not validate unknown directives, robots.txt, or each consumer's current processing behavior.",
                    declaration_count,
                    if declaration_count == 1 { "" } else { "s" },
                )
            }
        } else {
            format!(
                "Observed contradictory directives within the same crawler scope: {}. Supporting search engines generally apply the most restrictive applicable directive, so the outcome is restrictive rather than undefined; the declarations still obscure authoring intent.",
                conflicts.join("; "),
            )
        },
        status: if conflicts.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        // The restrictive directive wins, so this is authoring ambiguity rather than undefined behavior.
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: if !conflicts.is_empty() {
            Some(
                "For each affected crawler scope, decide the intended index and link-following policy, then remove the opposite directive from the responsible HTML meta tag or X-Robots-Tag header. Multiple declarations are allowed, so consolidate only when it improves ownership and prevents the contradiction. Re-fetch the production response and inspect the relevant search-console URL after deployment."
                    .into(),
            )
        } else {
            None
        },
        raw_data: Some(serde_json::json!({
            "directives_by_scope": declared.by_scope,
            "meta_tag_count": declared.meta_tags,
            "header_value_count": declared.header_values,
            "conflicts": conflicts,
            "robots_txt_inspected": false,
        })),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: if conflicts.is_empty() {
            None
        } else {
            Some("Contradictory declarations can leave a restrictive indexing or link-following outcome in effect while making the intended policy difficult to audit and maintain. The behavior is consumer-specific but is not assumed to be undefined.".into())
        },
    }
}

/// The row for a joined X-Robots-Tag value whose clauses do not establish a verdict.
fn scope_not_established() -> CheckResult {
    CheckResult {
        check_id: "seo.meta_conflicts".into(),
        category: ScanCategory::Seo,
        title: "Robots directive scope not established".into(),
        description: "This response's X-Robots-Tag lines reached SiteCMD combined into one value, and whether a directive after a crawler name shares a scope with its opposite turns on where one of those lines ended. SiteCMD grades neither reading.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({
            "reason": "crawler_scope_not_established",
            "robots_txt_inspected": false,
        })),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

#[cfg(test)]
#[path = "robots_conflicts_tests.rs"]
mod tests;
