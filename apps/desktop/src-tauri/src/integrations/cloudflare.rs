//! Cloudflare analytics API client.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudflareData {
    pub requests_total: u64,
    pub requests_cached: u64,
    pub cache_hit_rate: f64,
    pub bandwidth_total: u64,
    pub bandwidth_cached: u64,
    pub threats_blocked: u64,
    pub page_views: u64,
    pub unique_visitors: u64,
}

/// Map a UI period string ("day", "7d", "30d", "6mo", "12mo") to a number of
/// days. Unknown values fall back to 30 so the dashboard still renders.
#[tracing::instrument(fields(period = %period))]
pub(crate) fn period_to_days(period: &str) -> u64 {
    match period {
        "day" => 1,
        "7d" => 7,
        "30d" => 30,
        "6mo" => 180,
        "12mo" => 365,
        _ => 30,
    }
}

/// Compute cache-hit rate as a percentage, guarding against div-by-zero.
#[tracing::instrument(fields(total, cached))]
pub(crate) fn cache_hit_rate(total: u64, cached: u64) -> f64 {
    if total > 0 {
        (cached as f64 / total as f64) * 100.0
    } else {
        0.0
    }
}

/// Compute the GraphQL `since` date by subtracting `days` from `today`. Pure
/// (no clock) so tests are deterministic. If the subtraction would underflow
/// (`days` larger than the date), returns `today`.
#[tracing::instrument(skip(today), fields(days))]
pub(crate) fn since_date(today: chrono::NaiveDate, days: u64) -> String {
    today
        .checked_sub_days(chrono::Days::new(days))
        .unwrap_or(today)
        .to_string()
}

/// Parse the GraphQL response body into `CloudflareData`. Pure JSON-shape
/// extraction with safe defaults for missing fields. Tested directly.
#[tracing::instrument(skip(json))]
pub(crate) fn parse_graphql_response(json: &serde_json::Value) -> CloudflareData {
    let data = &json["data"]["viewer"]["zones"][0]["httpRequests1dGroups"][0];
    let sum = &data["sum"];
    let uniq = &data["uniq"];

    let requests_total = sum["requests"].as_u64().unwrap_or(0);
    let requests_cached = sum["cachedRequests"].as_u64().unwrap_or(0);

    CloudflareData {
        requests_total,
        requests_cached,
        cache_hit_rate: cache_hit_rate(requests_total, requests_cached),
        bandwidth_total: sum["bytes"].as_u64().unwrap_or(0),
        bandwidth_cached: sum["cachedBytes"].as_u64().unwrap_or(0),
        threats_blocked: sum["threats"].as_u64().unwrap_or(0),
        page_views: sum["pageViews"].as_u64().unwrap_or(0),
        unique_visitors: uniq["uniques"].as_u64().unwrap_or(0),
    }
}

/// Parse the REST analytics-dashboard response. Pure; tested directly.
#[tracing::instrument(skip(json))]
pub(crate) fn parse_rest_response(json: &serde_json::Value) -> CloudflareData {
    let totals = &json["result"]["totals"];
    let requests_total = totals["requests"]["all"].as_u64().unwrap_or(0);
    let requests_cached = totals["requests"]["cached"].as_u64().unwrap_or(0);

    CloudflareData {
        requests_total,
        requests_cached,
        cache_hit_rate: cache_hit_rate(requests_total, requests_cached),
        bandwidth_total: totals["bandwidth"]["all"].as_u64().unwrap_or(0),
        bandwidth_cached: totals["bandwidth"]["cached"].as_u64().unwrap_or(0),
        threats_blocked: totals["threats"]["all"].as_u64().unwrap_or(0),
        page_views: totals["pageviews"]["all"].as_u64().unwrap_or(0),
        unique_visitors: totals["uniques"]["all"].as_u64().unwrap_or(0),
    }
}

pub(crate) fn normalize_cloudflare_zone_ref(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = url::Url::parse(trimmed) {
        return parsed
            .host_str()
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase());
    }

    let with_scheme = format!("https://{}", trimmed.trim_start_matches("//"));
    if let Ok(parsed) = url::Url::parse(&with_scheme) {
        if let Some(host) = parsed.host_str() {
            return Some(host.trim_end_matches('.').to_ascii_lowercase());
        }
    }

    Some(trimmed.trim_end_matches('.').to_ascii_lowercase())
}

pub fn looks_like_cloudflare_zone_id(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 32 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn cloudflare_error_messages(json: &serde_json::Value) -> Vec<String> {
    json["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .filter_map(|error| error["message"].as_str())
                .filter(|message| !message.trim().is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_zone_lookup_response(
    json: &serde_json::Value,
    zone_name: &str,
) -> Result<String, String> {
    let errors = cloudflare_error_messages(json);
    if !errors.is_empty() {
        return Err(format!(
            "Cloudflare zone lookup failed: {}",
            errors.join("; ")
        ));
    }

    if json["success"].as_bool() == Some(false) {
        return Err("Cloudflare zone lookup failed.".to_string());
    }

    json["result"]
        .as_array()
        .and_then(|zones| zones.first())
        .and_then(|zone| zone["id"].as_str())
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "Cloudflare zone '{}' was not found. Paste the Zone ID, or use a token with Zone:Read so SiteCMD can resolve the domain.",
                zone_name
            )
        })
}

async fn resolve_zone_id(api_key: &str, zone_ref: &str) -> Result<String, String> {
    let zone_ref =
        normalize_cloudflare_zone_ref(zone_ref).ok_or("No Cloudflare zone configured")?;
    if looks_like_cloudflare_zone_id(&zone_ref) {
        return Ok(zone_ref);
    }

    let zone_name = zone_ref
        .strip_prefix("www.")
        .unwrap_or(zone_ref.as_str())
        .to_string();
    let encoded_name: String = url::form_urlencoded::byte_serialize(zone_name.as_bytes()).collect();
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones?name={}&status=active&per_page=1",
        encoded_name
    );
    let resp = crate::http_client::client()
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .timeout(crate::constants::API_TIMEOUT_SHORT)
        .send()
        .await
        .map_err(|e| format!("Cloudflare zone lookup error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Cloudflare zone lookup returned {}. Paste the Zone ID, or add Zone:Read permission to the token.",
            resp.status()
        ));
    }

    let json: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::CLOUDFLARE_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Cloudflare zone lookup parse error: {}", e))?;
    parse_zone_lookup_response(&json, &zone_name)
}

fn graphql_response_has_zone(json: &serde_json::Value) -> bool {
    json["data"]["viewer"]["zones"]
        .as_array()
        .map(|zones| !zones.is_empty())
        .unwrap_or(false)
}

#[tracing::instrument(skip(api_key), fields(zone_id = %zone_id))]
pub async fn fetch_stats(api_key: &str, zone_id: &str) -> Result<CloudflareData, String> {
    fetch_stats_with_period(api_key, zone_id, "30d").await
}

#[tracing::instrument(skip(api_key), fields(zone_ref = %zone_id, period = %period))]
pub async fn fetch_stats_with_period(
    api_key: &str,
    zone_id: &str,
    period: &str,
) -> Result<CloudflareData, String> {
    let days = period_to_days(period);
    let client = crate::http_client::client();
    let since = since_date(chrono::Utc::now().date_naive(), days);
    let resolved_zone_id = resolve_zone_id(api_key, zone_id).await?;

    let query = serde_json::json!({
        "query": r#"query {
            viewer {
                zones(filter: {zoneTag: $zoneTag}) {
                    httpRequests1dGroups(limit: 1, filter: {date_geq: $since}) {
                        sum {
                            requests
                            cachedRequests
                            bytes
                            cachedBytes
                            threats
                            pageViews
                        }
                        uniq {
                            uniques
                        }
                    }
                }
            }
        }"#,
        "variables": {
            "zoneTag": resolved_zone_id,
            "since": since,
        }
    });

    let resp = client
        .post("https://api.cloudflare.com/client/v4/graphql")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&query)
        .timeout(crate::constants::API_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Cloudflare API error: {}", e))?;

    if !resp.status().is_success() {
        // Fallback to REST API for basic zone info
        return fetch_stats_rest(api_key, &resolved_zone_id).await;
    }

    let json: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::CLOUDFLARE_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Parse error: {}", e))?;

    if !cloudflare_error_messages(&json).is_empty() || !graphql_response_has_zone(&json) {
        return fetch_stats_rest(api_key, &resolved_zone_id).await;
    }

    Ok(parse_graphql_response(&json))
}

async fn fetch_stats_rest(api_key: &str, zone_id: &str) -> Result<CloudflareData, String> {
    let client = crate::http_client::client();
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/analytics/dashboard?since=-43200",
        zone_id
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .timeout(crate::constants::API_TIMEOUT_SHORT)
        .send()
        .await
        .map_err(|e| format!("Cloudflare REST error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Cloudflare API returned {}", resp.status()));
    }

    let json: serde_json::Value = crate::http_client::read_json_limited(
        resp,
        crate::constants::CLOUDFLARE_API_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("Parse error: {}", e))?;

    Ok(parse_rest_response(&json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn period_to_days_recognises_known_periods() {
        assert_eq!(period_to_days("day"), 1);
        assert_eq!(period_to_days("7d"), 7);
        assert_eq!(period_to_days("30d"), 30);
        assert_eq!(period_to_days("6mo"), 180);
        assert_eq!(period_to_days("12mo"), 365);
    }

    #[test]
    fn period_to_days_falls_back_to_30() {
        // Unknown / typo inputs default to 30 days so the dashboard still
        // renders something rather than rejecting the request.
        assert_eq!(period_to_days(""), 30);
        assert_eq!(period_to_days("forever"), 30);
        assert_eq!(period_to_days("1d"), 30); // not in the explicit list
        assert_eq!(period_to_days("DAY"), 30); // case-sensitive
    }

    #[test]
    fn cache_hit_rate_zero_when_no_traffic() {
        // SECURITY/UX: must not panic on division by zero (an empty zone
        // would produce 0 total requests).
        assert_eq!(cache_hit_rate(0, 0), 0.0);
        assert_eq!(cache_hit_rate(0, 5), 0.0);
    }

    #[test]
    fn cache_hit_rate_full_hit() {
        assert_eq!(cache_hit_rate(100, 100), 100.0);
    }

    #[test]
    fn cache_hit_rate_partial() {
        assert_eq!(cache_hit_rate(200, 50), 25.0);
        assert!((cache_hit_rate(3, 1) - 33.333_333_333_333_336).abs() < 1e-9);
    }

    #[test]
    fn since_date_subtracts_days() {
        let today = NaiveDate::from_ymd_opt(2026, 4, 19).unwrap();
        assert_eq!(since_date(today, 0), "2026-04-19");
        assert_eq!(since_date(today, 1), "2026-04-18");
        assert_eq!(since_date(today, 30), "2026-03-20");
        assert_eq!(since_date(today, 365), "2025-04-19");
    }

    #[test]
    fn since_date_falls_back_to_today_on_underflow() {
        // Subtracting more days than have passed since 0001-01-01 underflows
        // and would panic without the unwrap_or - verify the fallback.
        let today = NaiveDate::from_ymd_opt(2026, 4, 19).unwrap();
        let result = since_date(today, u64::MAX);
        assert_eq!(result, "2026-04-19");
    }

    #[test]
    fn normalize_cloudflare_zone_ref_accepts_domain_or_url() {
        assert_eq!(
            normalize_cloudflare_zone_ref(" HTTPS://WWW.Example.COM/ "),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            normalize_cloudflare_zone_ref("example.com."),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_cloudflare_zone_ref(""), None);
    }

    #[test]
    fn looks_like_cloudflare_zone_id_requires_32_hex_chars() {
        assert!(looks_like_cloudflare_zone_id(
            "0123456789abcdef0123456789ABCDEF"
        ));
        assert!(!looks_like_cloudflare_zone_id("example.com"));
        assert!(!looks_like_cloudflare_zone_id("0123456789abcdef"));
        assert!(!looks_like_cloudflare_zone_id(
            "0123456789abcdef0123456789abcdeg"
        ));
    }

    #[test]
    fn parse_zone_lookup_response_extracts_zone_id() {
        let body = serde_json::json!({
            "success": true,
            "result": [{ "id": "0123456789abcdef0123456789abcdef", "name": "example.com" }]
        });

        assert_eq!(
            parse_zone_lookup_response(&body, "example.com").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_zone_lookup_response_reports_missing_zone() {
        let body = serde_json::json!({ "success": true, "result": [] });
        let error = parse_zone_lookup_response(&body, "example.com").unwrap_err();
        assert!(error.contains("example.com"));
        assert!(error.contains("Zone ID"));
    }

    fn graphql_full_body() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "viewer": {
                    "zones": [{
                        "httpRequests1dGroups": [{
                            "sum": {
                                "requests": 1000u64,
                                "cachedRequests": 750u64,
                                "bytes": 5_000_000u64,
                                "cachedBytes": 3_000_000u64,
                                "threats": 12u64,
                                "pageViews": 800u64
                            },
                            "uniq": { "uniques": 500u64 }
                        }]
                    }]
                }
            }
        })
    }

    #[test]
    fn parse_graphql_response_extracts_full_payload() {
        let data = parse_graphql_response(&graphql_full_body());
        assert_eq!(data.requests_total, 1000);
        assert_eq!(data.requests_cached, 750);
        assert!((data.cache_hit_rate - 75.0).abs() < 1e-9);
        assert_eq!(data.bandwidth_total, 5_000_000);
        assert_eq!(data.bandwidth_cached, 3_000_000);
        assert_eq!(data.threats_blocked, 12);
        assert_eq!(data.page_views, 800);
        assert_eq!(data.unique_visitors, 500);
    }

    #[test]
    fn parse_graphql_response_defaults_missing_fields_to_zero() {
        // Empty zone or partial response - every field must default to 0
        // rather than panic. Catches Cloudflare API shape changes.
        let data = parse_graphql_response(&serde_json::json!({}));
        assert_eq!(data.requests_total, 0);
        assert_eq!(data.requests_cached, 0);
        assert_eq!(data.cache_hit_rate, 0.0);
        assert_eq!(data.bandwidth_total, 0);
        assert_eq!(data.threats_blocked, 0);
        assert_eq!(data.page_views, 0);
        assert_eq!(data.unique_visitors, 0);
    }

    #[test]
    fn parse_graphql_response_handles_partial_data() {
        // Some zones return sum but no uniques - uniques must fall back to 0.
        let body = serde_json::json!({
            "data": { "viewer": { "zones": [{
                "httpRequests1dGroups": [{
                    "sum": { "requests": 50u64, "cachedRequests": 25u64 }
                }]
            }]}}
        });
        let data = parse_graphql_response(&body);
        assert_eq!(data.requests_total, 50);
        assert_eq!(data.requests_cached, 25);
        assert_eq!(data.cache_hit_rate, 50.0);
        assert_eq!(data.unique_visitors, 0);
        assert_eq!(data.threats_blocked, 0);
    }

    #[test]
    fn parse_rest_response_extracts_full_payload() {
        let body = serde_json::json!({
            "result": {
                "totals": {
                    "requests": { "all": 2000u64, "cached": 1500u64 },
                    "bandwidth": { "all": 10_000_000u64, "cached": 7_500_000u64 },
                    "threats": { "all": 5u64 },
                    "pageviews": { "all": 1500u64 },
                    "uniques": { "all": 900u64 }
                }
            }
        });
        let data = parse_rest_response(&body);
        assert_eq!(data.requests_total, 2000);
        assert_eq!(data.requests_cached, 1500);
        assert!((data.cache_hit_rate - 75.0).abs() < 1e-9);
        assert_eq!(data.bandwidth_total, 10_000_000);
        assert_eq!(data.bandwidth_cached, 7_500_000);
        assert_eq!(data.threats_blocked, 5);
        assert_eq!(data.page_views, 1500);
        assert_eq!(data.unique_visitors, 900);
    }

    #[test]
    fn parse_rest_response_defaults_to_zeros_on_empty_body() {
        let data = parse_rest_response(&serde_json::json!({}));
        assert_eq!(data.requests_total, 0);
        assert_eq!(data.cache_hit_rate, 0.0);
        assert_eq!(data.bandwidth_total, 0);
        assert_eq!(data.threats_blocked, 0);
        assert_eq!(data.page_views, 0);
        assert_eq!(data.unique_visitors, 0);
    }

    #[test]
    fn parse_rest_response_uses_lowercase_pageviews_key() {
        let body = serde_json::json!({
            "result": { "totals": { "pageviews": { "all": 42u64 } } }
        });
        let data = parse_rest_response(&body);
        assert_eq!(data.page_views, 42);
    }
}
