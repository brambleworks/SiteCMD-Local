//! Page-level and crawler-scoped indexing directives.

use super::extract_attr_value;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use std::collections::BTreeSet;

pub struct NoindexCheck;

/// Match robots directives, including `none`, without widening UA-scoped headers.
fn robots_directive_present(value: &str, directive: &str) -> bool {
    value
        .split(|character: char| character == ',' || character.is_ascii_whitespace())
        .map(|token| token.trim().trim_matches(':'))
        .any(|token| {
            token.eq_ignore_ascii_case(directive)
                || (token.eq_ignore_ascii_case("none")
                    && matches!(directive, "noindex" | "nofollow"))
        })
}

#[derive(Default)]
struct RobotsDirectiveState {
    general_noindex: bool,
    general_nofollow: bool,
    scoped_noindex_agents: BTreeSet<String>,
    scoped_nofollow_agents: BTreeSet<String>,
    noindex_sources: BTreeSet<String>,
}

impl RobotsDirectiveState {
    fn has_noindex(&self) -> bool {
        self.general_noindex || !self.scoped_noindex_agents.is_empty()
    }

    fn has_nofollow(&self) -> bool {
        self.general_nofollow || !self.scoped_nofollow_agents.is_empty()
    }
}

fn apply_robots_directives(
    state: &mut RobotsDirectiveState,
    scope: Option<&str>,
    directives: &str,
    source: &str,
) {
    let has_noindex = robots_directive_present(directives, "noindex");
    let has_nofollow = robots_directive_present(directives, "nofollow");
    if !has_noindex && !has_nofollow {
        return;
    }
    let normalized_scope = scope
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_ascii_lowercase)
        .filter(|scope| {
            scope.len() <= 64
                && scope
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
        });
    let is_general = normalized_scope
        .as_deref()
        .is_none_or(|scope| matches!(scope, "*" | "robots"));
    if is_general {
        state.general_noindex |= has_noindex;
        state.general_nofollow |= has_nofollow;
    } else if let Some(agent) = normalized_scope {
        if has_noindex {
            state.scoped_noindex_agents.insert(agent.clone());
        }
        if has_nofollow {
            state.scoped_nofollow_agents.insert(agent);
        }
    }
    if has_noindex {
        state.noindex_sources.insert(source.to_string());
    }
}

fn collect_meta_robots_directives(body: &str, state: &mut RobotsDirectiveState) {
    let scannable = crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(body, " ");
    let lower = scannable.to_ascii_lowercase();
    for tag in crate::checks::html_attrs::tag_slices(&scannable, &lower, "meta") {
        let Some(name) = extract_attr_value(tag, "name").map(|name| name.to_ascii_lowercase())
        else {
            continue;
        };
        let scope = match name.as_str() {
            "robots" => None,
            // These are documented crawler-specific meta names. Narrow names
            // remain scoped; they do not imply a general page-wide directive.
            "googlebot" | "googlebot-news" | "bingbot" => Some(name.as_str()),
            _ => continue,
        };
        let Some(content) = extract_attr_value(tag, "content") else {
            continue;
        };
        let source = format!("html_meta:{name}");
        apply_robots_directives(state, scope, &content, &source);
    }
}

fn is_valued_robots_directive(name: &str) -> bool {
    matches!(
        name,
        "max-snippet" | "max-image-preview" | "max-video-preview" | "unavailable_after"
    )
}

fn collect_header_robots_directives(headers: &http::HeaderMap, state: &mut RobotsDirectiveState) {
    for value in headers
        .get_all("x-robots-tag")
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        let mut current_scope: Option<String> = None;
        for clause in value
            .split(',')
            .map(str::trim)
            .filter(|clause| !clause.is_empty())
        {
            if let Some((prefix, directives)) = clause.split_once(':') {
                let prefix = prefix.trim().to_ascii_lowercase();
                if is_valued_robots_directive(&prefix) {
                    continue;
                }
                current_scope = Some(prefix);
                let source = format!(
                    "x_robots_tag:{}",
                    current_scope.as_deref().unwrap_or("unscoped")
                );
                apply_robots_directives(state, current_scope.as_deref(), directives, &source);
            } else {
                let source = format!(
                    "x_robots_tag:{}",
                    current_scope.as_deref().unwrap_or("unscoped")
                );
                apply_robots_directives(state, current_scope.as_deref(), clause, &source);
            }
        }
    }
}

fn crawler_label(agent: &str) -> String {
    match agent {
        "googlebot" => "Googlebot".into(),
        "googlebot-news" => "Googlebot-News".into(),
        "bingbot" => "Bingbot".into(),
        other => other.to_string(),
    }
}

impl Check for NoindexCheck {
    fn id(&self) -> &str {
        "seo.noindex"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let mut directives = RobotsDirectiveState::default();
        collect_meta_robots_directives(&ctx.body, &mut directives);
        collect_header_robots_directives(&ctx.response_headers, &mut directives);
        let is_blocked = directives.has_noindex();
        let has_nofollow = directives.has_nofollow();
        let google_scoped = directives.scoped_noindex_agents.contains("googlebot");
        let scoped_labels = directives
            .scoped_noindex_agents
            .iter()
            .map(|agent| crawler_label(agent))
            .collect::<Vec<_>>();
        let only_googlebot = !directives.general_noindex
            && directives.scoped_noindex_agents.len() == 1
            && google_scoped;
        let is_primary_entry = matches!(ctx.url.path(), "" | "/");

        vec![CheckResult {
            check_id: "seo.noindex".into(),
            category: ScanCategory::Seo,
            title: if directives.general_noindex {
                "Page is marked noindex".into()
            } else if only_googlebot {
                "Googlebot-specific noindex directive".into()
            } else if is_blocked {
                "Crawler-specific noindex directive".into()
            } else {
                "Noindex / nofollow audit".into()
            },
            description: if directives.general_noindex {
                "A robots meta tag or X-Robots-Tag instructs supporting search crawlers not to index this page after they can crawl and process the directive. That can be correct for account, duplicate, staging, or private-workflow pages; confirm whether this URL is intended to appear in search.".into()
            } else if only_googlebot {
                "A crawler-specific robots meta tag or X-Robots-Tag addresses Googlebot with noindex. It asks Google Search not to index this page after Googlebot can crawl and process the directive; it does not state a rule for every other crawler. Confirm whether Google Search visibility is intended for this URL.".into()
            } else if is_blocked {
                format!(
                    "A noindex directive is scoped to {} only; it does not mark the page noindex for every crawler. Confirm whether exclusion from {} is intentional. SiteCMD observed the directive syntax but did not verify how each named crawler currently processes it.",
                    scoped_labels.join(", "),
                    scoped_labels.join(", "),
                )
            } else if has_nofollow {
                "A nofollow directive asks supporting crawlers not to follow links from this page. Crawler interpretation can vary, and the directive does not determine whether this page itself is indexed."
                    .into()
            } else {
                "No page-level noindex or nofollow directive was observed. This removes one possible indexing restriction but does not guarantee that the URL is crawlable, canonical, eligible, or selected for indexing.".into()
            },
            status: if is_blocked {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            severity: if is_blocked
                && is_primary_entry
                && (directives.general_noindex || google_scoped)
            {
                Severity::High
            } else if is_blocked && (directives.general_noindex || google_scoped) {
                Severity::Medium
            } else {
                Severity::Low
            },
            fix_prompt: None,
            manual_fix: if is_blocked {
                Some("First confirm which named crawlers, if any, should index this URL. If the observed exclusion is unintended, remove noindex only from the applicable robots meta tag or X-Robots-Tag scope, keep the URL crawlable so that crawler can see the change, then inspect and request recrawling in the relevant search-console tool. Keep intentional exclusions and do not broaden a crawler-specific rule merely to clear this finding.".into())
            } else {
                None
            },
            raw_data: Some(serde_json::json!({
                "noindex": is_blocked,
                "nofollow": has_nofollow,
                "general_noindex": directives.general_noindex,
                "general_nofollow": directives.general_nofollow,
                "scoped_noindex_agents": directives.scoped_noindex_agents,
                "scoped_nofollow_agents": directives.scoped_nofollow_agents,
                "noindex_sources": directives.noindex_sources,
            })),
            confidence: if is_blocked {
                crate::checks::IssueConfidence::NeedsReview
            } else {
                crate::checks::IssueConfidence::High
            },
            confidence_reason: is_blocked.then(|| "The noindex directive is directly observed, but whether excluding this specific URL is a defect depends on the page's intended search visibility.".into()),
            why_it_matters: if is_blocked {
                Some(if directives.general_noindex {
                    "For a page intended to acquire search traffic, a processed general noindex directive removes it from supporting search engines' results. It is harmless and often desirable on pages that should stay out of search.".into()
                } else {
                    format!("For a page intended to appear through {}, a processed scoped noindex directive can exclude it from that crawler's search surface. It does not establish exclusion from other search systems.", scoped_labels.join(", "))
                })
            } else {
                None
            },
        }]
    }
}
