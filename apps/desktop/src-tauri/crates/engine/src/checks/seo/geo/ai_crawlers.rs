//! Grades root-wide robots.txt blocks for known AI crawlers. Discovery and
//! fetch blocks need review; training-only blocks are policy.

use crate::checks::seo::robots::{robots_groups, RobotsGroup};
use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

#[derive(Clone, Copy)]
struct CrawlerPolicy<'a> {
    token: &'a str,
    label: &'a str,
    purpose: &'a str,
    affects_discovery_or_fetch: bool,
}

fn root_blocked_for_agent(groups: &[RobotsGroup], token: &str) -> bool {
    let token = token.to_ascii_lowercase();
    let specific: Vec<_> = groups
        .iter()
        .filter(|group| group.agents.iter().any(|agent| agent == &token))
        .collect();
    let selected: Vec<_> = if specific.is_empty() {
        groups
            .iter()
            .filter(|group| group.agents.iter().any(|agent| agent == "*"))
            .collect()
    } else {
        specific
    };
    selected.iter().any(|group| group.root_disallow)
        && !selected.iter().any(|group| group.has_allow_rule)
}

/// Grade the `seo.ai_crawler_blocking` outcome from a fetched robots.txt
/// body. Returns a passing row when no recognized crawler is blocked at the
/// root, and no row when the block is the primary robots check's root-wide
/// wildcard finding.
pub fn evaluate_ai_crawler_blocking(body: &str) -> Vec<CheckResult> {
    // Purpose labels are intentionally separated: vendor documentation
    // distinguishes search indexing, user-triggered retrieval, model
    // development, and general web crawling. Blocking one does not imply
    // the effects of another.
    let ai_crawlers = [
        CrawlerPolicy {
            token: "OAI-SearchBot",
            label: "OpenAI search indexing",
            purpose: "discovery",
            affects_discovery_or_fetch: true,
        },
        CrawlerPolicy {
            token: "ChatGPT-User",
            label: "ChatGPT user-triggered fetch",
            purpose: "user_fetch",
            affects_discovery_or_fetch: true,
        },
        CrawlerPolicy {
            token: "GPTBot",
            label: "OpenAI model-training crawler",
            purpose: "model_training",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "Claude-SearchBot",
            label: "Anthropic search indexing",
            purpose: "discovery",
            affects_discovery_or_fetch: true,
        },
        CrawlerPolicy {
            token: "Claude-User",
            label: "Claude user-triggered fetch",
            purpose: "user_fetch",
            affects_discovery_or_fetch: true,
        },
        CrawlerPolicy {
            token: "ClaudeBot",
            label: "Anthropic model-development crawler",
            purpose: "model_training",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "Anthropic-AI",
            label: "Anthropic legacy model crawler token",
            purpose: "model_training",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "Google-Extended",
            label: "Google Gemini training/grounding control",
            purpose: "model_training_or_grounding",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "Bytespider",
            label: "ByteDance crawler",
            purpose: "model_or_platform_crawling",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "CCBot",
            label: "Common Crawl",
            purpose: "general_web_crawl",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "PerplexityBot",
            label: "Perplexity search indexing",
            purpose: "discovery",
            affects_discovery_or_fetch: true,
        },
        CrawlerPolicy {
            token: "Applebot-Extended",
            label: "Apple generative-AI data-use control",
            purpose: "model_training",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "Meta-ExternalAgent",
            label: "Meta AI training crawler",
            purpose: "model_training",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "FacebookBot",
            label: "Meta legacy speech/language crawler",
            purpose: "model_or_platform_crawling",
            affects_discovery_or_fetch: false,
        },
        CrawlerPolicy {
            token: "cohere-ai",
            label: "Cohere crawler",
            purpose: "model_or_platform_crawling",
            affects_discovery_or_fetch: false,
        },
    ];

    // Consecutive agents share a rule block; only root disallows block them.
    let groups = robots_groups(body);
    // The primary robots check owns a root-wide wildcard block. Avoid a
    // second issue that merely re-labels the same rule for AI products.
    if groups
        .iter()
        .any(|group| group.blocks_root && group.agents.iter().any(|agent| agent == "*"))
    {
        return vec![];
    }

    let blocked: Vec<_> = ai_crawlers
        .iter()
        .copied()
        .filter(|crawler| root_blocked_for_agent(&groups, crawler.token))
        .collect();
    if blocked.is_empty() {
        return vec![CheckResult {
            check_id: "seo.ai_crawler_blocking".into(),
            category: ScanCategory::Seo,
            title: "AI discovery or fetch crawler policy".into(),
            description: "robots.txt has no root-wide rule blocking any AI discovery, fetch, or model crawler token SiteCMD recognizes. Path-scoped rules, CDN or WAF behavior, and tokens SiteCMD does not recognize were not evaluated.".into(),
            status: CheckStatus::Pass,
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }];
    }

    let affected: Vec<_> = blocked
        .iter()
        .filter(|crawler| crawler.affects_discovery_or_fetch)
        .collect();
    let policy_only: Vec<_> = blocked
        .iter()
        .filter(|crawler| !crawler.affects_discovery_or_fetch)
        .collect();
    let affected_labels = affected
        .iter()
        .map(|crawler| crawler.label)
        .collect::<Vec<_>>()
        .join(", ");
    let policy_labels = policy_only
        .iter()
        .map(|crawler| crawler.label)
        .collect::<Vec<_>>()
        .join(", ");
    let has_discovery_effect = !affected.is_empty();

    let description = if has_discovery_effect {
        format!(
            "robots.txt has root-wide, no-exception rules for these discovery/fetch crawler tokens: {}.{} This can be a deliberate content policy. According to the respective vendor documentation, blocking the named discovery or user-fetch token may reduce that product's ability to index or retrieve page content; it does not prove total exclusion, and CDN/WAF behavior was not tested.{}",
            affected_labels,
            if policy_labels.is_empty() { "".to_string() } else { format!(" It also blocks model/training or general-crawl tokens: {}.", policy_labels) },
            if policy_labels.is_empty() { "" } else { " Training/data-use controls are separate from search visibility." }
        )
    } else {
        format!(
            "robots.txt has root-wide, no-exception rules for these model/training or general-crawl tokens: {}. This is a deliberate policy signal, not an SEO failure by itself. For example, Google documents that Google-Extended has no effect on Google Search inclusion or ranking.",
            policy_labels
        )
    };

    vec![CheckResult {
        check_id: "seo.ai_crawler_blocking".into(),
        category: ScanCategory::Seo,
        // Factual title: blocking AI crawlers is often a deliberate
        // anti-training posture, not a defect.
        title: if has_discovery_effect {
            "AI discovery or fetch crawler policy".into()
        } else {
            "AI model crawler policy".into()
        },
        description,
        status: if has_discovery_effect {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        },
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: if has_discovery_effect {
            Some("Review each exact user-agent token against the vendor's current official crawler documentation and your content/training policy. Allow only the discovery or user-fetch products you intentionally support, keep model-training/data-use tokens blocked when desired, and preserve path-specific restrictions. Then test robots selection plus CDN/WAF access for verified vendor traffic; changing robots.txt does not bypass an edge block or guarantee inclusion.".into())
        } else {
            None
        },
        raw_data: Some(serde_json::json!({
            "blocked_crawlers": blocked.iter().map(|crawler| serde_json::json!({
                "user_agent": crawler.token,
                "label": crawler.label,
                "purpose": crawler.purpose,
                "may_affect_discovery_or_user_fetch": crawler.affects_discovery_or_fetch,
            })).collect::<Vec<_>>(),
            "root_wide_no_allow_exception": true,
            "cdn_or_waf_tested": false,
        })),
        confidence: if has_discovery_effect {
            IssueConfidence::NeedsReview
        } else {
            IssueConfidence::High
        },
        confidence_reason: if has_discovery_effect {
            Some("The robots policy is directly observed, but product behavior can change and SiteCMD did not verify vendor IPs, edge access, indexing state, or the site's intentional policy.".into())
        } else {
            None
        },
        why_it_matters: if has_discovery_effect {
            Some("A product-specific discovery or retrieval crawler generally needs page access to index or fetch full content, while model-training controls serve a different policy goal. The operator must choose that tradeoff deliberately.".into())
        } else {
            None
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_agent_group_blocks_every_listed_crawler() {
        // Consecutive User-agent lines share one rule block; both bots in
        // the group must be reported, not just the last one parsed.
        let robots =
            "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n";
        let results = evaluate_ai_crawler_blocking(robots);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Pass);
        assert_eq!(results[0].severity, Severity::Low);
        assert!(results[0]
            .description
            .contains("OpenAI model-training crawler"));
        assert!(results[0]
            .description
            .contains("Anthropic model-development crawler"));
    }

    #[test]
    fn blocking_a_discovery_crawler_warns_low_without_count_thresholds() {
        let robots = "User-agent: GPTBot\nUser-agent: ClaudeBot\nUser-agent: CCBot\nUser-agent: PerplexityBot\nDisallow: /\n";
        let results = evaluate_ai_crawler_blocking(robots);
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert_eq!(results[0].severity, Severity::Low);
        assert_eq!(results[0].title, "AI discovery or fetch crawler policy");
        assert!(
            results[0].description.contains("deliberate")
                && results[0].description.contains("discovery/fetch"),
            "description must acknowledge the intentional posture: {}",
            results[0].description
        );
    }

    #[test]
    fn meta_externalagent_is_recognized() {
        let robots = "User-agent: meta-externalagent\nDisallow: /\n";
        let results = evaluate_ai_crawler_blocking(robots);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].description.contains("Meta AI training"),
            "{}",
            results[0].description
        );
    }

    #[test]
    fn partial_disallow_is_not_a_block() {
        // Only a root Disallow counts; a path-scoped rule must not be
        // reported as blocking the crawler.
        let robots = "User-agent: GPTBot\nDisallow: /private/\n";
        let results = evaluate_ai_crawler_blocking(robots);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Pass);
    }

    #[test]
    fn training_only_blocks_are_reported_as_policy_not_an_issue() {
        let robots = "User-agent: GPTBot\nUser-agent: Google-Extended\nDisallow: /\n";
        let results = evaluate_ai_crawler_blocking(robots);
        assert_eq!(results[0].status, CheckStatus::Pass);
        assert!(results[0].manual_fix.is_none());
        assert!(results[0].description.contains("model/training"));
    }

    #[test]
    fn wildcard_site_block_is_left_to_primary_robots_check() {
        let robots = "User-agent: *\nDisallow: /\n";
        assert!(evaluate_ai_crawler_blocking(robots).is_empty());
    }
}
