//! PageSpeed Insights API v5 client.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Parsed PageSpeed Insights result.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct PageSpeedReport {
    pub url: String,
    pub strategy: String,       // "mobile" or "desktop"
    pub performance_score: u32, // 0-100
    pub lcp_ms: Option<f64>,
    pub cls: Option<f64>,
    pub tbt_ms: Option<f64>, // Lighthouse Total Blocking Time lab diagnostic
    pub fcp_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub si_ms: Option<f64>, // Speed Index
    pub opportunities: Vec<Opportunity>,
    // Real-user field data from CrUX via PSI loadingExperience keys.
    pub field_lcp_ms: Option<f64>,
    pub field_cls: Option<f64>,
    pub field_inp_ms: Option<f64>,
    /// "url" | "origin" | None - indicates which CrUX dataset was used.
    pub field_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct Opportunity {
    pub id: String,
    pub title: String,
    pub description: String,
    pub savings_ms: Option<f64>,
}

/// CWV rating thresholds per Google.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CwvRating {
    Good,
    NeedsImprovement,
    Poor,
}

impl CwvRating {
    #[tracing::instrument(fields(ms))]
    pub fn for_lcp(ms: f64) -> Self {
        if ms <= 2500.0 {
            Self::Good
        } else if ms <= 4000.0 {
            Self::NeedsImprovement
        } else {
            Self::Poor
        }
    }
    #[tracing::instrument(fields(value))]
    pub fn for_cls(value: f64) -> Self {
        if value <= 0.1 {
            Self::Good
        } else if value <= 0.25 {
            Self::NeedsImprovement
        } else {
            Self::Poor
        }
    }
    #[tracing::instrument(fields(ms))]
    pub fn for_tbt(ms: f64) -> Self {
        // TBT thresholds (lab proxy for INP)
        if ms <= 200.0 {
            Self::Good
        } else if ms <= 600.0 {
            Self::NeedsImprovement
        } else {
            Self::Poor
        }
    }
    #[tracing::instrument(fields(ms))]
    pub fn for_fcp(ms: f64) -> Self {
        if ms <= 1800.0 {
            Self::Good
        } else if ms <= 3000.0 {
            Self::NeedsImprovement
        } else {
            Self::Poor
        }
    }
}

/// Fetch PageSpeed Insights report for a URL.
///
/// `strategy`: "mobile" or "desktop". Defaults to "mobile" if empty.
#[tracing::instrument(skip(url, api_key), fields(strategy = %strategy))]
pub async fn fetch_pagespeed_report(
    url: &str,
    strategy: &str,
    api_key: Option<&str>,
) -> Result<PageSpeedReport, String> {
    crate::network_policy::validate_url(url, crate::network_policy::UrlPolicy::Scan).await?;
    let strategy = if strategy.is_empty() {
        "mobile"
    } else {
        strategy
    };
    let api_url = format!(
        "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={}&category=performance&strategy={}",
        urlencoding::encode(url),
        strategy,
    );

    let client = crate::http_client::client();
    // Keep the API key out of formatted URLs and strip request URLs from errors
    // before logging because reqwest includes query strings by default.
    let mut request = client
        .get(&api_url)
        .timeout(crate::constants::PSI_REQUEST_TIMEOUT); // PSI can be slow
    if let Some(key) = api_key.filter(|key| !key.is_empty()) {
        request = request.query(&[("key", key)]);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| format!("PageSpeed API request failed: {}", e.without_url()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = crate::http_client::read_text_limited(
            resp,
            crate::constants::INTEGRATION_ERROR_BODY_MAX_BYTES,
            crate::constants::BODY_READ_TIMEOUT,
        )
        .await
        .unwrap_or_default();
        return Err(format_pagespeed_http_error(status, &body));
    }

    let json: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::PAGESPEED_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Failed to parse PageSpeed response: {}", e))?;

    parse_psi_response(&json, url, strategy)
}

pub fn is_pagespeed_rate_limit_error(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    normalized.contains("429")
        || normalized.contains("too many requests")
        || normalized.contains("resource_exhausted")
        || normalized.contains("rate_limit_exceeded")
        || normalized.contains("ratelimitexceeded")
        || normalized.contains("quota exceeded")
}

fn format_pagespeed_http_error(status: reqwest::StatusCode, body: &str) -> String {
    let detail = summarize_pagespeed_error_body(status, body);
    if detail.is_empty() {
        format!("PageSpeed API returned {}", status)
    } else {
        format!("PageSpeed API returned {}: {}", status, detail)
    }
}

fn summarize_pagespeed_error_body(status: reqwest::StatusCode, body: &str) -> String {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || is_pagespeed_rate_limit_error(body) {
        return "rate limit exhausted".to_string();
    }

    pagespeed_json_error_detail(body).unwrap_or_else(|| truncate_error_detail(body))
}

fn pagespeed_json_error_detail(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = json.get("error").unwrap_or(&json);

    let status = error.get("status").and_then(serde_json::Value::as_str);
    let reason = error
        .get("details")
        .and_then(serde_json::Value::as_array)
        .and_then(|details| {
            details
                .iter()
                .find_map(|detail| detail.get("reason").and_then(serde_json::Value::as_str))
        })
        .or_else(|| {
            error
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .and_then(|errors| {
                    errors
                        .iter()
                        .find_map(|detail| detail.get("reason").and_then(serde_json::Value::as_str))
                })
        });
    let message = error.get("message").and_then(serde_json::Value::as_str);

    let mut parts = Vec::new();
    if let Some(status) = status {
        parts.push(status);
    }
    if let Some(reason) = reason {
        parts.push(reason);
    }
    if let Some(message) = message {
        parts.push(message);
    }

    let detail = parts.join(": ");
    if detail.is_empty() {
        None
    } else {
        Some(truncate_error_detail(&detail))
    }
}

fn truncate_error_detail(detail: &str) -> String {
    const MAX_ERROR_DETAIL_CHARS: usize = 240;

    let compact = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= MAX_ERROR_DETAIL_CHARS {
        return compact;
    }

    let truncated = compact
        .chars()
        .take(MAX_ERROR_DETAIL_CHARS)
        .collect::<String>();
    format!("{truncated}...")
}

#[tracing::instrument(skip(json, url), fields(strategy = %strategy))]
pub(crate) fn parse_psi_response(
    json: &serde_json::Value,
    url: &str,
    strategy: &str,
) -> Result<PageSpeedReport, String> {
    let lighthouse = json
        .get("lighthouseResult")
        .ok_or("Missing lighthouseResult in PSI response")?;

    // Performance score (0.0 – 1.0 → 0 – 100)
    let perf_score = lighthouse
        .pointer("/categories/performance/score")
        .and_then(|v| v.as_f64())
        .map(|s| (s * 100.0).round() as u32)
        .unwrap_or(0);

    let audits = lighthouse.get("audits").unwrap_or(&serde_json::Value::Null);

    let lcp_ms = audit_numeric(audits, "largest-contentful-paint");
    let cls = audit_numeric(audits, "cumulative-layout-shift");
    let tbt_ms = audit_numeric(audits, "total-blocking-time");
    let fcp_ms = audit_numeric(audits, "first-contentful-paint");
    let ttfb_ms = audit_numeric(audits, "server-response-time");
    let si_ms = audit_numeric(audits, "speed-index");

    // Parse opportunities (audits with "overallSavingsMs")
    let mut opportunities = Vec::new();
    if let Some(audits_obj) = audits.as_object() {
        for (_key, audit) in audits_obj {
            let savings = audit
                .pointer("/details/overallSavingsMs")
                .and_then(|v| v.as_f64());
            if let Some(savings_ms) = savings {
                if savings_ms > 0.0 {
                    opportunities.push(Opportunity {
                        id: audit
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        title: audit
                            .get("title")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: audit
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        savings_ms: Some(savings_ms),
                    });
                }
            }
        }
    }

    opportunities.sort_by(|a, b| {
        b.savings_ms
            .unwrap_or(0.0)
            .partial_cmp(&a.savings_ms.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Prefer URL-level field data; fall back to origin-level.
    let (field_lcp_ms, field_cls, field_inp_ms, field_source) = {
        let url_exp = json.get("loadingExperience");
        let origin_exp = json.get("originLoadingExperience");
        let (experience, source_label) = match (url_exp, origin_exp) {
            (Some(v), _) if v.pointer("/metrics").is_some() => (Some(v), "url"),
            (_, Some(v)) if v.pointer("/metrics").is_some() => (Some(v), "origin"),
            _ => (None, ""),
        };
        match experience {
            Some(exp) => {
                let lcp = exp
                    .pointer("/metrics/LARGEST_CONTENTFUL_PAINT_MS/percentile")
                    .and_then(|v| v.as_f64());
                // CrUX returns CLS multiplied by 100 (percentile is an integer).
                let cls_field = exp
                    .pointer("/metrics/CUMULATIVE_LAYOUT_SHIFT_SCORE/percentile")
                    .and_then(|v| v.as_f64())
                    .map(|v| v / 100.0);
                let inp = exp
                    .pointer("/metrics/INTERACTION_TO_NEXT_PAINT/percentile")
                    .and_then(|v| v.as_f64());
                let src = if lcp.is_some() || cls_field.is_some() || inp.is_some() {
                    Some(source_label.to_string())
                } else {
                    None
                };
                (lcp, cls_field, inp, src)
            }
            None => (None, None, None, None),
        }
    };

    Ok(PageSpeedReport {
        url: url.to_string(),
        strategy: strategy.to_string(),
        performance_score: perf_score,
        lcp_ms,
        cls,
        tbt_ms,
        fcp_ms,
        ttfb_ms,
        si_ms,
        opportunities,
        field_lcp_ms,
        field_cls,
        field_inp_ms,
        field_source,
    })
}

#[tracing::instrument(skip(audits), fields(id = %id))]
pub(crate) fn audit_numeric(audits: &serde_json::Value, id: &str) -> Option<f64> {
    audits.get(id)?.get("numericValue")?.as_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn security_regression_pagespeed_rejects_private_network_targets() {
        let error = fetch_pagespeed_report("http://192.168.1.10", "mobile", None)
            .await
            .expect_err("private network target should be rejected before PSI API call");

        assert!(error.contains("private/internal IP address"));
    }

    #[test]
    fn cwv_rating_lcp_uses_25s_and_4s_thresholds() {
        // Google Web Vitals: <=2.5s good, <=4s needs improvement, > poor.
        assert_eq!(CwvRating::for_lcp(0.0), CwvRating::Good);
        assert_eq!(CwvRating::for_lcp(2500.0), CwvRating::Good);
        assert_eq!(CwvRating::for_lcp(2500.1), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_lcp(4000.0), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_lcp(4000.1), CwvRating::Poor);
    }

    #[test]
    fn cwv_rating_cls_uses_01_and_025_thresholds() {
        assert_eq!(CwvRating::for_cls(0.0), CwvRating::Good);
        assert_eq!(CwvRating::for_cls(0.1), CwvRating::Good);
        assert_eq!(CwvRating::for_cls(0.11), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_cls(0.25), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_cls(0.26), CwvRating::Poor);
    }

    #[test]
    fn cwv_rating_tbt_uses_200ms_and_600ms_thresholds() {
        assert_eq!(CwvRating::for_tbt(0.0), CwvRating::Good);
        assert_eq!(CwvRating::for_tbt(200.0), CwvRating::Good);
        assert_eq!(CwvRating::for_tbt(200.1), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_tbt(600.0), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_tbt(601.0), CwvRating::Poor);
    }

    #[test]
    fn cwv_rating_fcp_uses_18s_and_3s_thresholds() {
        assert_eq!(CwvRating::for_fcp(0.0), CwvRating::Good);
        assert_eq!(CwvRating::for_fcp(1800.0), CwvRating::Good);
        assert_eq!(CwvRating::for_fcp(1801.0), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_fcp(3000.0), CwvRating::NeedsImprovement);
        assert_eq!(CwvRating::for_fcp(3001.0), CwvRating::Poor);
    }

    #[test]
    fn audit_numeric_extracts_metric_from_audit_object() {
        let audits = serde_json::json!({
            "largest-contentful-paint": {"numericValue": 2400.0}
        });
        assert_eq!(
            audit_numeric(&audits, "largest-contentful-paint"),
            Some(2400.0)
        );
    }

    #[test]
    fn audit_numeric_returns_none_when_audit_missing() {
        let audits = serde_json::json!({});
        assert!(audit_numeric(&audits, "missing-audit").is_none());
    }

    #[test]
    fn audit_numeric_returns_none_when_numeric_value_missing() {
        let audits = serde_json::json!({"audit-id": {"score": 0.95}});
        assert!(audit_numeric(&audits, "audit-id").is_none());
    }

    #[test]
    fn audit_numeric_returns_none_when_numeric_value_not_a_number() {
        let audits = serde_json::json!({"audit-id": {"numericValue": "not a number"}});
        assert!(audit_numeric(&audits, "audit-id").is_none());
    }

    #[test]
    fn pagespeed_quota_errors_are_summarized_without_raw_response_body() {
        let body = serde_json::json!({
            "error": {
                "code": 429,
                "message": "Quota exceeded for quota metric and project_number:1234567890",
                "status": "RESOURCE_EXHAUSTED",
                "details": [{ "reason": "RATE_LIMIT_EXCEEDED" }]
            }
        })
        .to_string();

        let error = format_pagespeed_http_error(reqwest::StatusCode::TOO_MANY_REQUESTS, &body);

        assert_eq!(
            error,
            "PageSpeed API returned 429 Too Many Requests: rate limit exhausted"
        );
        assert!(is_pagespeed_rate_limit_error(&error));
        assert!(!error.contains("project_number"));
    }

    #[test]
    fn pagespeed_non_quota_errors_keep_concise_json_detail() {
        let body = serde_json::json!({
            "error": {
                "message": "The supplied URL is invalid.",
                "status": "INVALID_ARGUMENT",
                "errors": [{ "reason": "badRequest" }]
            }
        })
        .to_string();

        let error = format_pagespeed_http_error(reqwest::StatusCode::BAD_REQUEST, &body);

        assert_eq!(
            error,
            "PageSpeed API returned 400 Bad Request: INVALID_ARGUMENT: badRequest: The supplied URL is invalid."
        );
    }

    fn full_psi_body() -> serde_json::Value {
        serde_json::json!({
            "lighthouseResult": {
                "categories": {"performance": {"score": 0.85}},
                "audits": {
                    "largest-contentful-paint": {"id": "lcp", "title": "LCP", "description": "x", "numericValue": 2200.0},
                    "cumulative-layout-shift": {"id": "cls", "title": "CLS", "description": "x", "numericValue": 0.05},
                    "total-blocking-time": {"id": "tbt", "title": "TBT", "description": "x", "numericValue": 150.0},
                    "first-contentful-paint": {"id": "fcp", "title": "FCP", "description": "x", "numericValue": 1500.0},
                    "server-response-time": {"id": "ttfb", "title": "TTFB", "description": "x", "numericValue": 250.0},
                    "speed-index": {"id": "si", "title": "SI", "description": "x", "numericValue": 3000.0},
                    "uses-text-compression": {
                        "id": "uses-text-compression",
                        "title": "Enable text compression",
                        "description": "Compress text-based resources",
                        "details": {"overallSavingsMs": 800.0}
                    },
                    "uses-rel-preconnect": {
                        "id": "uses-rel-preconnect",
                        "title": "Preconnect to required origins",
                        "description": "Origin connect time",
                        "details": {"overallSavingsMs": 200.0}
                    }
                }
            }
        })
    }

    #[test]
    fn parse_psi_response_extracts_full_payload() {
        let report =
            parse_psi_response(&full_psi_body(), "https://example.com", "mobile").expect("parse");
        assert_eq!(report.url, "https://example.com");
        assert_eq!(report.strategy, "mobile");
        assert_eq!(report.performance_score, 85, "0.85 * 100 → 85");
        assert_eq!(report.lcp_ms, Some(2200.0));
        assert_eq!(report.cls, Some(0.05));
        assert_eq!(report.tbt_ms, Some(150.0));
        assert_eq!(report.fcp_ms, Some(1500.0));
        assert_eq!(report.ttfb_ms, Some(250.0));
        assert_eq!(report.si_ms, Some(3000.0));
    }

    #[test]
    fn parse_psi_response_sorts_opportunities_by_savings_descending() {
        let report =
            parse_psi_response(&full_psi_body(), "https://example.com", "mobile").expect("parse");
        assert_eq!(report.opportunities.len(), 2);
        assert_eq!(report.opportunities[0].id, "uses-text-compression");
        assert_eq!(report.opportunities[0].savings_ms, Some(800.0));
        assert_eq!(report.opportunities[1].id, "uses-rel-preconnect");
        assert_eq!(report.opportunities[1].savings_ms, Some(200.0));
    }

    #[test]
    fn parse_psi_response_excludes_audits_without_savings() {
        let report =
            parse_psi_response(&full_psi_body(), "https://example.com", "mobile").expect("parse");
        let ids: Vec<&str> = report.opportunities.iter().map(|o| o.id.as_str()).collect();
        assert!(!ids.contains(&"largest-contentful-paint"));
        assert!(!ids.contains(&"cls"));
    }

    #[test]
    fn parse_psi_response_excludes_audits_with_zero_savings() {
        // overallSavingsMs of 0 means the page already passes - don't show
        // it as an opportunity.
        let body = serde_json::json!({
            "lighthouseResult": {
                "categories": {"performance": {"score": 1.0}},
                "audits": {
                    "uses-text-compression": {
                        "id": "uses-text-compression",
                        "details": {"overallSavingsMs": 0.0}
                    }
                }
            }
        });
        let report = parse_psi_response(&body, "https://example.com", "mobile").expect("parse");
        assert!(report.opportunities.is_empty());
    }

    #[test]
    fn parse_psi_response_returns_err_when_lighthouse_result_missing() {
        let body = serde_json::json!({
            "error": {"code": 500, "message": "Internal error"}
        });
        let result = parse_psi_response(&body, "https://example.com", "mobile");
        assert!(result.is_err());
    }

    #[test]
    fn parse_psi_response_defaults_score_to_zero_when_missing() {
        let body = serde_json::json!({
            "lighthouseResult": {"audits": {}}
        });
        let report = parse_psi_response(&body, "https://example.com", "mobile").expect("parse");
        assert_eq!(report.performance_score, 0);
        assert!(report.lcp_ms.is_none());
        assert!(report.opportunities.is_empty());
    }

    #[test]
    fn parse_psi_response_rounds_score_correctly() {
        // 0.876 → 88, 0.5 → 50.
        let body_876 = serde_json::json!({
            "lighthouseResult": {
                "categories": {"performance": {"score": 0.876}},
                "audits": {}
            }
        });
        let report = parse_psi_response(&body_876, "https://example.com", "mobile").expect("parse");
        assert_eq!(report.performance_score, 88);
    }

    #[test]
    fn parse_psi_response_handles_missing_audits_object() {
        let body = serde_json::json!({
            "lighthouseResult": {"categories": {"performance": {"score": 0.5}}}
        });
        let report = parse_psi_response(&body, "https://example.com", "mobile").expect("parse");
        assert_eq!(report.performance_score, 50);
        // All metric fields default to None, opportunities empty.
        assert!(report.lcp_ms.is_none());
        assert!(report.opportunities.is_empty());
    }

    #[test]
    fn parse_psi_response_carries_url_and_strategy_through() {
        let report = parse_psi_response(
            &full_psi_body(),
            "https://other.example.com/page",
            "desktop",
        )
        .expect("parse");
        assert_eq!(report.url, "https://other.example.com/page");
        assert_eq!(report.strategy, "desktop");
    }

    #[test]
    fn parse_extracts_field_data_when_loading_experience_present() {
        let json = serde_json::json!({
            "lighthouseResult": {
                "categories": { "performance": { "score": 0.9 } },
                "audits": {}
            },
            "loadingExperience": {
                "metrics": {
                    "LARGEST_CONTENTFUL_PAINT_MS": { "percentile": 2400 },
                    "CUMULATIVE_LAYOUT_SHIFT_SCORE": { "percentile": 8 },
                    "INTERACTION_TO_NEXT_PAINT": { "percentile": 180 }
                }
            }
        });
        let report = parse_psi_response(&json, "https://example.com", "mobile").unwrap();
        assert_eq!(report.field_lcp_ms, Some(2400.0));
        assert!(
            (report.field_cls.unwrap() - 0.08).abs() < 1e-6,
            "CLS should be 0.08 after /100 normalization"
        );
        assert_eq!(report.field_inp_ms, Some(180.0));
        assert_eq!(report.field_source.as_deref(), Some("url"));
    }

    #[test]
    fn parse_falls_back_to_origin_experience_when_url_missing() {
        let json = serde_json::json!({
            "lighthouseResult": {
                "categories": { "performance": { "score": 0.9 } },
                "audits": {}
            },
            "originLoadingExperience": {
                "metrics": {
                    "LARGEST_CONTENTFUL_PAINT_MS": { "percentile": 3100 }
                }
            }
        });
        let report = parse_psi_response(&json, "https://example.com", "mobile").unwrap();
        assert_eq!(report.field_lcp_ms, Some(3100.0));
        assert_eq!(report.field_source.as_deref(), Some("origin"));
    }

    #[test]
    fn parse_returns_none_field_data_when_no_experience() {
        let json = serde_json::json!({
            "lighthouseResult": {
                "categories": { "performance": { "score": 0.9 } },
                "audits": {}
            }
        });
        let report = parse_psi_response(&json, "https://example.com", "mobile").unwrap();
        assert!(report.field_lcp_ms.is_none());
        assert!(report.field_source.is_none());
    }
}
