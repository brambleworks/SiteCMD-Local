//! Inspect response caching policy and validators.
//! Missing explicit policy and deliberate `no-store` responses require contextual review.

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct CacheHeadersCheck;

impl Check for CacheHeadersCheck {
    fn id(&self) -> &str {
        "performance.cache"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Performance
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let cache_control =
            crate::header_lines::field_value(&ctx.response_headers, "cache-control");

        let has_etag = ctx.response_headers.contains_key("etag");
        let has_last_modified = ctx.response_headers.contains_key("last-modified");

        // `no-cache` permits storage with revalidation; only `no-store` forbids
        // caching entirely.
        let is_no_store = cache_control
            .as_ref()
            .map(|cc| cc.to_ascii_lowercase().contains("no-store"))
            .unwrap_or(false);
        // ETag and Last-Modified are validators, not freshness/storage
        // policies. Either can make a conditional request cheap, but neither
        // says whether reuse is appropriate or how long a response is fresh.
        let has_explicit_policy = cache_control.is_some();
        let has_validator = has_etag || has_last_modified;

        vec![CheckResult {
            check_id: "performance.cache".into(),
            category: ScanCategory::Performance,
            title: if has_explicit_policy && !is_no_store {
                "Explicit cache policy detected".into()
            } else if is_no_store {
                "Cache-Control set to no-store".into()
            } else if has_validator {
                "No explicit caching policy set".into()
            } else {
                "No explicit caching policy or validator detected".into()
            },
            description: if is_no_store {
                "Cache-Control is set to no-store, which tells caches not to retain this HTML response. That can be correct for sensitive or highly personalized content; it trades away reuse and conditional revalidation for that protection."
                    .into()
            } else if has_explicit_policy {
                format!(
                    "An explicit Cache-Control policy is present. {}{}{}",
                    cache_control
                        .as_ref()
                        .map(|cc| format!("Cache-Control: {}. ", cc))
                        .unwrap_or_default(),
                    if has_etag { "ETag present. " } else { "" },
                    if has_last_modified {
                        "Last-Modified present."
                    } else {
                        ""
                    }
                )
            } else if has_validator {
                let validators = match (has_etag, has_last_modified) {
                    (true, true) => "ETag and Last-Modified validators are present",
                    (true, false) => "An ETag validator is present",
                    (false, true) => "A Last-Modified validator is present",
                    (false, false) => unreachable!(),
                };
                format!("{}. They can support conditional requests that revalidate the response, but there is no explicit Cache-Control freshness or storage policy. This scan does not establish whether caching this page is safe or intended.", validators)
            } else {
                "No Cache-Control, ETag, or Last-Modified header was found on this HTML response. Without an explicit reuse policy or validator, later visits may transfer the response body again. This scan does not establish whether reuse is safe or intended."
                    .into()
            },
            status: if has_explicit_policy && !is_no_store {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Medium,
            fix_prompt: None,
            manual_fix: if has_explicit_policy && !is_no_store {
                None
            } else if is_no_store {
                Some("Keep `no-store` when this HTML contains sensitive or user-specific data that must not be retained. Otherwise classify its personalization, deployment cadence, and acceptable staleness, then choose a private or public Cache-Control policy at the response-owning layer and add an ETag when conditional revalidation is useful. Test anonymous and authenticated responses through the real CDN or proxy.".into())
            } else {
                Some("Classify this HTML response by whether it is public or personalized, how it is invalidated, and how much staleness the product accepts. Use `private` for user-specific content; use public or shared-cache directives only for content safe to serve across users. Choose TTL and stale behavior from the deployment model rather than copying universal numbers, add a validator when useful, and verify anonymous plus authenticated cache status through the deployed edge.".into())
            },
            raw_data: Some(
                serde_json::json!({"cache_control": cache_control, "etag": has_etag, "last_modified": has_last_modified}),
            ),
            confidence: if has_explicit_policy && !is_no_store {
                crate::checks::IssueConfidence::High
            } else {
                crate::checks::IssueConfidence::NeedsReview
            },
            confidence_reason: if has_explicit_policy && !is_no_store {
                None
            } else {
                Some("Header state is directly observed, but the response's sensitivity, personalization, and intended cache behavior require review.".into())
            },
            why_it_matters: if has_explicit_policy && !is_no_store {
                None
            } else if is_no_store {
                Some("`no-store` prevents reuse of this response. That is an intentional privacy/security control for some pages and an avoidable repeat-transfer cost for others.".into())
            } else if has_validator {
                Some("Validators can reduce transferred bytes after revalidation, while an explicit policy makes intended storage and freshness behavior clearer. Whether this page should be cached is context-dependent.".into())
            } else {
                Some("Without a validator or explicit policy, repeat requests may transfer more HTML bytes. Sensitive or personalized pages may intentionally avoid reuse, so this remains a review item.".into())
            },
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_headers(headers: &[(&str, &str)]) -> PageContext {
        let mut map = http::header::HeaderMap::new();
        for (name, value) in headers {
            map.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        PageContext {
            evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: map,
            status_code: 200,
            body: String::new(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: Some("HTTP/2.0".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn no_caching_headers_warn_for_contextual_review() {
        let results = CacheHeadersCheck.run(&ctx_with_headers(&[]));
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert_eq!(results[0].severity, Severity::Medium);
        assert!(results[0].title.contains("No explicit caching policy"));
        assert_eq!(
            results[0].confidence,
            crate::checks::IssueConfidence::NeedsReview
        );
        assert!(results[0]
            .description
            .contains("does not establish whether reuse is safe"));
        assert!(results[0]
            .manual_fix
            .as_deref()
            .is_some_and(|fix| fix.contains("Classify") && fix.contains("personalized")));
    }

    #[test]
    fn no_cache_directive_passes() {
        let results = CacheHeadersCheck.run(&ctx_with_headers(&[(
            "cache-control",
            "no-cache, must-revalidate",
        )]));
        assert_eq!(results[0].status, CheckStatus::Pass);
    }

    #[test]
    fn no_store_directive_warns() {
        let results = CacheHeadersCheck.run(&ctx_with_headers(&[("cache-control", "no-store")]));
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert!(results[0].title.contains("no-store"));
        assert_eq!(
            results[0].confidence,
            crate::checks::IssueConfidence::NeedsReview
        );
        assert!(results[0]
            .manual_fix
            .as_deref()
            .is_some_and(|fix| fix.contains("Keep `no-store`") && fix.contains("sensitive")));
    }

    #[test]
    fn etag_alone_is_a_validator_not_an_explicit_freshness_policy() {
        let results = CacheHeadersCheck.run(&ctx_with_headers(&[("etag", "\"abc123\"")]));
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert!(results[0].description.contains("ETag validator"));
        assert!(results[0].description.contains("no explicit Cache-Control"));
    }

    #[test]
    fn last_modified_alone_warns_with_revalidation_aware_copy() {
        let results = CacheHeadersCheck.run(&ctx_with_headers(&[(
            "last-modified",
            "Tue, 30 Jun 2026 12:00:00 GMT",
        )]));
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert!(results[0].title.contains("No explicit caching policy"));
        assert!(
            results[0].description.contains("revalidate")
                && !results[0]
                    .description
                    .contains("re-download the entire page"),
            "copy must not claim full re-downloads when Last-Modified exists: {}",
            results[0].description
        );
    }

    /// With no validators at all, the check must still avoid claiming every
    /// browser/proxy will transfer the full body on every visit.
    #[test]
    fn no_headers_at_all_uses_conditional_transfer_copy() {
        let results = CacheHeadersCheck.run(&ctx_with_headers(&[]));
        assert!(!results[0].description.contains("will re-download"));
        assert!(results[0].description.contains("may transfer"));
    }
}
