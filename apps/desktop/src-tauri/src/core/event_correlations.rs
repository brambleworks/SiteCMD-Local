//! Detects likely relationships between operational events and scan history.

use crate::db::{
    CausalLinkObservationInput, Database, EventSeverity, EventType, ScanSummary, SiteEvent,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct Correlation {
    pub source_event_id: i64,
    pub target_event_id: Option<i64>,
    pub correlation_type: String, // deploy_to_regression, scan_to_traffic, uptime_to_traffic
    pub confidence: String,       // high, medium, low
    pub description: String,
    pub source_timestamp: String,
    pub target_timestamp: Option<String>,
}

/// Render an event timestamp for the `Correlation` wire format.
fn ms_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Find deploy, uptime, analytics, and scan-history correlations.
#[tracing::instrument(skip(events, scans))]
pub fn find_correlations(events: &[SiteEvent], scans: &[ScanSummary]) -> Vec<Correlation> {
    let mut correlations: Vec<Correlation> = Vec::new();

    // Events carry epoch ms directly; scans still parse RFC 3339 text below.
    let parsed_events: Vec<(&SiteEvent, chrono::DateTime<chrono::Utc>)> = events
        .iter()
        .filter_map(|e| chrono::DateTime::from_timestamp_millis(e.occurred_at_ms).map(|dt| (e, dt)))
        .collect();

    let parsed_scans: Vec<(&ScanSummary, chrono::DateTime<chrono::Utc>)> = scans
        .iter()
        .filter_map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s.timestamp)
                .ok()
                .map(|dt| (s, dt.with_timezone(&chrono::Utc)))
        })
        .collect();

    let deploy_events: Vec<_> = parsed_events
        .iter()
        .filter(|(e, _)| e.event_type == EventType::Deploy)
        .collect();

    // Pair only consecutive scans of the same environment so merged timelines
    // cannot fabricate cross-environment score changes.
    let mut scans_by_url: HashMap<&str, Vec<(&ScanSummary, chrono::DateTime<chrono::Utc>)>> =
        HashMap::new();
    for (scan, ts) in &parsed_scans {
        scans_by_url
            .entry(scan.url.as_str())
            .or_default()
            .push((*scan, *ts));
    }

    // Build consecutive same-site scan pairs to detect regressions.
    let mut scan_pairs: Vec<(&ScanSummary, &ScanSummary, chrono::DateTime<chrono::Utc>)> =
        Vec::new();
    for group in scans_by_url.values() {
        for window in group.windows(2) {
            let (newer, newer_ts) = &window[0];
            let (older, _older_ts) = &window[1];
            if (older.overall_score as i32 - newer.overall_score as i32) > 5 {
                scan_pairs.push((newer, older, *newer_ts));
            }
        }
    }
    // Deterministic newest-first order. HashMap group order is arbitrary, so
    // tie-break equal timestamps on the regressed scan id to keep output stable.
    scan_pairs.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.id.cmp(&b.0.id)));

    for (deploy_event, deploy_ts) in &deploy_events {
        for (regressed_scan, prev_scan, scan_ts) in &scan_pairs {
            let gap = *scan_ts - *deploy_ts;
            if gap >= chrono::Duration::zero() && gap <= chrono::Duration::hours(24) {
                let score_drop =
                    prev_scan.overall_score as i32 - regressed_scan.overall_score as i32;
                let confidence = if gap <= chrono::Duration::hours(2) && score_drop > 10 {
                    "high"
                } else if gap <= chrono::Duration::hours(6) {
                    "medium"
                } else {
                    "low"
                };

                correlations.push(Correlation {
                    source_event_id: deploy_event.id,
                    target_event_id: None,
                    correlation_type: "deploy_to_regression".into(),
                    confidence: confidence.into(),
                    description: format!(
                        "Deploy \"{}\" may have caused a {} point score drop ({} → {})",
                        deploy_event.title.chars().take(50).collect::<String>(),
                        score_drop,
                        prev_scan.overall_score,
                        regressed_scan.overall_score
                    ),
                    source_timestamp: ms_to_rfc3339(deploy_event.occurred_at_ms),
                    target_timestamp: Some(regressed_scan.timestamp.clone()),
                });
                break;
            }
        }
    }

    let mut improved_scan_pairs: Vec<(&ScanSummary, &ScanSummary, chrono::DateTime<chrono::Utc>)> =
        Vec::new();
    for group in scans_by_url.values() {
        for window in group.windows(2) {
            let (newer, newer_ts) = &window[0];
            let (older, _older_ts) = &window[1];
            if (newer.overall_score as i32 - older.overall_score as i32) > 5 {
                improved_scan_pairs.push((newer, older, *newer_ts));
            }
        }
    }
    improved_scan_pairs.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.id.cmp(&b.0.id)));

    for (deploy_event, deploy_ts) in &deploy_events {
        for (improved_scan, prev_scan, scan_ts) in &improved_scan_pairs {
            let gap = *scan_ts - *deploy_ts;
            if gap >= chrono::Duration::zero() && gap <= chrono::Duration::hours(24) {
                let score_up = improved_scan.overall_score as i32 - prev_scan.overall_score as i32;
                let confidence = if gap <= chrono::Duration::hours(2) && score_up > 10 {
                    "high"
                } else if gap <= chrono::Duration::hours(6) {
                    "medium"
                } else {
                    "low"
                };
                correlations.push(Correlation {
                    source_event_id: deploy_event.id,
                    target_event_id: None,
                    correlation_type: "deploy_to_resolution".into(),
                    confidence: confidence.into(),
                    description: format!(
                        "Deploy \"{}\" likely resolved a {} point score improvement ({} -> {})",
                        deploy_event.title.chars().take(50).collect::<String>(),
                        score_up,
                        prev_scan.overall_score,
                        improved_scan.overall_score
                    ),
                    source_timestamp: ms_to_rfc3339(deploy_event.occurred_at_ms),
                    target_timestamp: Some(improved_scan.timestamp.clone()),
                });
                break;
            }
        }
    }

    let downtime_events: Vec<_> = parsed_events
        .iter()
        .filter(|(e, _)| e.event_type == EventType::Uptime && e.severity == EventSeverity::Critical)
        .collect();

    let traffic_events: Vec<_> = parsed_events
        .iter()
        .filter(|(e, _)| {
            e.event_type == EventType::Analytics && e.title.to_lowercase().contains("drop")
        })
        .collect();

    for (downtime, down_ts) in &downtime_events {
        for (traffic, traffic_ts) in &traffic_events {
            let gap = (*traffic_ts - *down_ts).num_hours().abs();
            if gap <= 4 {
                correlations.push(Correlation {
                    source_event_id: downtime.id,
                    target_event_id: Some(traffic.id),
                    correlation_type: "uptime_to_traffic".into(),
                    confidence: if gap <= 1 { "high" } else { "medium" }.into(),
                    description: format!(
                        "Downtime event likely caused the traffic drop - {} apart",
                        if gap == 0 {
                            "same hour".to_string()
                        } else {
                            format!("{}h apart", gap)
                        }
                    ),
                    source_timestamp: ms_to_rfc3339(downtime.occurred_at_ms),
                    target_timestamp: Some(ms_to_rfc3339(traffic.occurred_at_ms)),
                });
                break;
            }
        }
    }

    let anomaly_events: Vec<_> = parsed_events
        .iter()
        .filter(|(e, _)| e.event_type == EventType::Analytics)
        .collect();

    for (regressed_scan, prev_scan, scan_ts) in &scan_pairs {
        let score_drop = prev_scan.overall_score as i32 - regressed_scan.overall_score as i32;
        if score_drop < 10 {
            continue;
        }

        for (anomaly, anomaly_ts) in &anomaly_events {
            let gap_hours = (*anomaly_ts - *scan_ts).num_hours().abs();
            if gap_hours <= 48 {
                correlations.push(Correlation {
                    source_event_id: anomaly.id,
                    target_event_id: None,
                    correlation_type: "scan_to_traffic".into(),
                    confidence: if gap_hours <= 12 { "medium" } else { "low" }.into(),
                    description: format!(
                        "Score dropped {} pts ({} → {}) near a traffic anomaly: {}",
                        score_drop,
                        prev_scan.overall_score,
                        regressed_scan.overall_score,
                        anomaly.title.chars().take(60).collect::<String>()
                    ),
                    source_timestamp: regressed_scan.timestamp.clone(),
                    target_timestamp: Some(ms_to_rfc3339(anomaly.occurred_at_ms)),
                });
                break;
            }
        }
    }

    // Deduplicate by source_event_id + correlation_type
    correlations.sort_by(|a, b| {
        a.source_event_id
            .cmp(&b.source_event_id)
            .then(a.correlation_type.cmp(&b.correlation_type))
    });
    correlations.dedup_by(|a, b| {
        a.source_event_id == b.source_event_id && a.correlation_type == b.correlation_type
    });

    correlations
}

/// Get correlations for a project by loading events and scans then running detection.
#[tracing::instrument(skip(db), fields(project_id))]
pub fn get_project_correlations(
    db: &Arc<Database>,
    project_id: i64,
) -> Result<Vec<Correlation>, String> {
    let end = chrono::Utc::now();
    let start = end - chrono::Duration::days(30);
    let events = db.get_events(
        project_id,
        start.timestamp_millis(),
        end.timestamp_millis(),
        None,
        None,
        None,
        None,
    )?;

    let projects = db.get_projects()?;
    let project = projects
        .iter()
        .find(|p| p.id == project_id)
        .ok_or_else(|| "Project not found".to_string())?;

    let mut all_scans: Vec<ScanSummary> = Vec::new();
    for env in &project.environments {
        if let Ok(scans) = db.get_scan_history_for_project(project_id, &env.url, 20) {
            all_scans.extend(scans);
        }
    }

    all_scans.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let correlations = find_correlations(&events, &all_scans);

    if !correlations.is_empty() {
        tracing::info!(
            "Found {} correlation(s) for project {}",
            correlations.len(),
            project_id
        );
    }

    Ok(correlations)
}

/// Record co-resolution observations used for dynamic confidence calibration.
/// Currently invoked only by tests and manual callers.
pub fn record_resolution_observations(
    db: &Database,
    project_id: i64,
    pre_deploy_active: &HashSet<String>,
    post_deploy_active: &HashSet<String>,
    deploy_event_id: Option<i64>,
    observed_at_ms: i64,
) -> Result<(), String> {
    use crate::core::correlation::causal_graph::CAUSAL_LINKS;

    // Resolved = was active before, not active after.
    let resolved: HashSet<String> = pre_deploy_active
        .difference(post_deploy_active)
        .cloned()
        .collect();

    if resolved.is_empty() {
        return Ok(());
    }

    let mut rows: Vec<CausalLinkObservationInput> = Vec::new();
    for link in CAUSAL_LINKS {
        let cause_active_pre = pre_deploy_active.contains(link.cause);
        let cause_resolved = resolved.contains(link.cause);
        let effect_resolved = resolved.contains(link.effect);
        // Both must have been active (co_active) before, and both resolved after.
        if cause_active_pre && cause_resolved && effect_resolved {
            rows.push(CausalLinkObservationInput {
                cause_check_id: link.cause.to_string(),
                effect_check_id: link.effect.to_string(),
                observed_at_ms,
                co_active: 1,   // both were in pre_deploy_active
                co_resolved: 1, // both resolved after
                resolution_event_id: deploy_event_id,
            });
        }
    }

    if rows.is_empty() {
        return Ok(());
    }

    db.insert_causal_link_observations(project_id, rows)
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Record causal pairs that became active in the same scan window.
/// This is not called until scan completion provides both active sets.
pub fn record_regression_observations(
    db: &Database,
    project_id: i64,
    pre_scan_active: &HashSet<String>,
    post_scan_active: &HashSet<String>,
    scan_event_id: Option<i64>,
    observed_at_ms: i64,
) -> Result<(), String> {
    use crate::core::correlation::causal_graph::CAUSAL_LINKS;

    // Newly regressed = active after, not active before.
    let newly_regressed: HashSet<String> = post_scan_active
        .difference(pre_scan_active)
        .cloned()
        .collect();

    if newly_regressed.is_empty() {
        return Ok(());
    }

    let mut rows: Vec<CausalLinkObservationInput> = Vec::new();
    for link in CAUSAL_LINKS {
        let cause_regressed = newly_regressed.contains(link.cause);
        let effect_regressed = newly_regressed.contains(link.effect);
        // Both cause and effect must have newly appeared - co-regression.
        if cause_regressed && effect_regressed {
            rows.push(CausalLinkObservationInput {
                cause_check_id: link.cause.to_string(),
                effect_check_id: link.effect.to_string(),
                observed_at_ms,
                co_active: 1,   // both newly active
                co_resolved: 0, // this is the failure case
                resolution_event_id: scan_event_id,
            });
        }
    }

    if rows.is_empty() {
        return Ok(());
    }

    db.insert_causal_link_observations(project_id, rows)
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
#[path = "event_correlations_parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::EventSource;

    fn make_scan(id: i64, score: u32, ts: &str) -> ScanSummary {
        ScanSummary {
            id,
            url: "https://example.com".into(),
            mode: "full".into(),
            scan_type: crate::core::scanner::ScanType::Health,
            overall_score: score,
            issues_total: 0,
            issues_critical: 0,
            issues_high: 0,
            issues_medium: 0,
            issues_low: 0,
            duration_ms: 0,
            timestamp: ts.into(),
            session_id: None,
            page_url: None,
        }
    }

    fn make_scan_url(id: i64, score: u32, ts: &str, url: &str) -> ScanSummary {
        ScanSummary {
            url: url.into(),
            ..make_scan(id, score, ts)
        }
    }

    fn make_deploy(id: i64, ts: &str) -> SiteEvent {
        SiteEvent {
            id,
            project_id: 1,
            event_type: EventType::Deploy,
            severity: EventSeverity::Info,
            occurred_at_ms: chrono::DateTime::parse_from_rfc3339(ts)
                .expect("valid RFC 3339 test timestamp")
                .timestamp_millis(),
            title: "v1.2.3 deployed".into(),
            summary: "".into(),
            detail: None,
            source: EventSource::Internal,
            source_id: None,
            metadata: None,
            affected_check_ids: None,
        }
    }

    #[test]
    fn cross_environment_scans_do_not_form_deploy_correlations() {
        let t0 = "2024-01-01T12:00:00Z";
        let events = vec![make_deploy(1, t0)];
        // Merged newest-first: prod 95 (T+1h), localhost 40 (T+30m), prod 93 (T-1h).
        let scans = vec![
            make_scan_url(3, 95, "2024-01-01T13:00:00Z", "https://example.com"),
            make_scan_url(2, 40, "2024-01-01T12:30:00Z", "http://localhost:3000"),
            make_scan_url(1, 93, "2024-01-01T11:00:00Z", "https://example.com"),
        ];

        let correlations = find_correlations(&events, &scans);
        assert!(
            !correlations
                .iter()
                .any(|c| c.correlation_type.starts_with("deploy_to")),
            "cross-environment scans must not fabricate deploy correlations; got: {:?}",
            correlations
        );
    }

    #[test]
    fn deploy_to_resolution_emits_correlation() {
        // Deploy at T0. Scans newest-first: T+1h (score 85), T-1h (score 70).
        let t0 = "2024-01-01T12:00:00Z";
        let t_before = "2024-01-01T11:00:00Z";
        let t_after = "2024-01-01T13:00:00Z";

        let events = vec![make_deploy(1, t0)];
        // newest-first scan order
        let scans = vec![make_scan(2, 85, t_after), make_scan(1, 70, t_before)];

        let correlations = find_correlations(&events, &scans);
        assert!(
            correlations
                .iter()
                .any(|c| c.correlation_type == "deploy_to_resolution"),
            "expected a deploy_to_resolution correlation; got: {:?}",
            correlations
        );
    }

    #[test]
    fn deploy_to_resolution_not_emitted_for_regression() {
        // Score dropped - should not produce deploy_to_resolution.
        let t0 = "2024-01-01T12:00:00Z";
        let t_before = "2024-01-01T11:00:00Z";
        let t_after = "2024-01-01T13:00:00Z";

        let events = vec![make_deploy(1, t0)];
        // newest-first: score went DOWN from 85 to 70
        let scans = vec![make_scan(2, 70, t_after), make_scan(1, 85, t_before)];

        let correlations = find_correlations(&events, &scans);
        assert!(
            !correlations
                .iter()
                .any(|c| c.correlation_type == "deploy_to_resolution"),
            "should not emit deploy_to_resolution when score dropped"
        );
    }

    #[test]
    fn record_resolution_observations_writes_rows_for_co_resolved_links() {
        let db = crate::db::test_helpers::temp_db_with_project();
        let project_id: i64 = 1;

        // Both compression and lcp were active before, both resolved after.
        let pre: HashSet<String> = ["performance.compression", "performance.lcp"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let post: HashSet<String> = HashSet::new();

        record_resolution_observations(&db, project_id, &pre, &post, None, 1_000_000)
            .expect("record_resolution_observations should not fail");

        let count = db
            .execute(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM causal_link_observations
                     WHERE project_id = ?1
                       AND cause_check_id = 'performance.compression'
                       AND effect_check_id = 'performance.lcp'",
                    rusqlite::params![project_id],
                    |r| r.get::<_, i64>(0),
                )
            })
            .expect("execute")
            .expect("query");

        assert!(
            count >= 1,
            "expected at least 1 row for (compression, lcp); got {}",
            count
        );
    }

    #[test]
    fn record_resolution_observations_no_op_when_nothing_resolved() {
        let db = crate::db::test_helpers::temp_db();
        let project_id: i64 = 1;

        // lcp stays active in both sets - nothing resolved.
        let pre: HashSet<String> = ["performance.lcp"].iter().map(|s| s.to_string()).collect();
        let post: HashSet<String> = ["performance.lcp"].iter().map(|s| s.to_string()).collect();

        record_resolution_observations(&db, project_id, &pre, &post, None, 1_000_000)
            .expect("should be a no-op");

        let count = db
            .execute(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM causal_link_observations WHERE project_id = ?1",
                    rusqlite::params![project_id],
                    |r| r.get::<_, i64>(0),
                )
            })
            .expect("execute")
            .expect("query");

        assert_eq!(count, 0, "expected zero rows when nothing resolved");
    }

    #[test]
    fn record_regression_observations_writes_rows_for_co_regressed_links() {
        let db = crate::db::test_helpers::temp_db_with_project();
        let project_id: i64 = 1;

        // Both compression and lcp newly appear (pre is empty, post has both).
        // (compression, lcp) is a known CAUSAL_LINK so we expect an observation row.
        let pre: HashSet<String> = HashSet::new();
        let post: HashSet<String> = ["performance.compression", "performance.lcp"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        record_regression_observations(&db, project_id, &pre, &post, None, 2_000_000)
            .expect("record_regression_observations should not fail");

        let count = db
            .execute(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM causal_link_observations
                     WHERE project_id = ?1
                       AND cause_check_id = 'performance.compression'
                       AND effect_check_id = 'performance.lcp'
                       AND co_active = 1
                       AND co_resolved = 0",
                    rusqlite::params![project_id],
                    |r| r.get::<_, i64>(0),
                )
            })
            .expect("execute")
            .expect("query");

        assert!(
            count >= 1,
            "expected at least 1 regression row for (compression, lcp); got {}",
            count
        );
    }

    #[test]
    fn record_regression_observations_no_op_when_nothing_newly_regressed() {
        let db = crate::db::test_helpers::temp_db();
        let project_id: i64 = 1;

        // lcp was already active before - not newly regressed.
        let pre: HashSet<String> = ["performance.lcp"].iter().map(|s| s.to_string()).collect();
        let post: HashSet<String> = ["performance.lcp"].iter().map(|s| s.to_string()).collect();

        record_regression_observations(&db, project_id, &pre, &post, None, 2_000_000)
            .expect("should be a no-op");

        let count = db
            .execute(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM causal_link_observations WHERE project_id = ?1",
                    rusqlite::params![project_id],
                    |r| r.get::<_, i64>(0),
                )
            })
            .expect("execute")
            .expect("query");

        assert_eq!(count, 0, "expected zero rows when nothing newly regressed");
    }
}
