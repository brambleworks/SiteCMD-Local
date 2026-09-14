//! Pre-deploy risk and hypothetical resolution analysis.
//! Changed files intersect active fix locations; hypothetical fixes walk calibrated causal edges.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::checks::Severity;
use crate::core::correlation::{
    causal_graph::{Confidence, CAUSAL_LINKS},
    observations::{dynamic_confidence, ObservationIndex},
};
use crate::core::types_work_items::Evidence;
use crate::db::Database;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct DeployRiskPreview {
    pub direct_risks: Vec<RiskItem>,
    pub downstream_risks: Vec<RiskItem>,
    pub historical_regressions: Vec<HistoricalRegression>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct RiskItem {
    pub check_id: String,
    pub severity: Severity,
    pub title: String,
    pub matched_files: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct HistoricalRegression {
    pub check_id: String,
    pub deploy_timestamp: String,
    pub score_drop: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct WhatIfResult {
    pub also_resolves: Vec<WhatIfEffect>,
    pub confidence_basis: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct WhatIfEffect {
    pub check_id: String,
    pub confidence: Confidence,
    pub via: Vec<String>,
}

/// Preview project-wide direct and downstream risks for changed files.
pub fn preview_deploy_risk(
    db: &Database,
    project_id: i64,
    changed_files: Vec<String>,
) -> Result<DeployRiskPreview, String> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let groups = db.get_work_items_grouped(project_id, None, now_ms)?;

    let mut direct = Vec::new();
    let mut downstream_check_ids: HashSet<String> = HashSet::new();

    for group in &groups {
        let matched: Vec<String> = group
            .fix_locations
            .iter()
            .filter(|fl| {
                changed_files.iter().any(|cf| {
                    cf == &fl.relative_path
                        || cf.ends_with(&fl.relative_path)
                        || (!fl.absolute_path.is_empty() && cf == &fl.absolute_path)
                })
            })
            .map(|fl| fl.relative_path.clone())
            .collect();
        if !matched.is_empty() {
            direct.push(RiskItem {
                check_id: group.check_id.clone(),
                severity: group.severity,
                title: group.title.clone(),
                matched_files: matched,
                confidence: Confidence::High,
            });
            for eff in &group.downstream_effects {
                downstream_check_ids.insert(eff.clone());
            }
        }
    }

    let direct_check_ids: HashSet<String> = direct.iter().map(|r| r.check_id.clone()).collect();

    let downstream: Vec<RiskItem> = groups
        .iter()
        .filter(|g| downstream_check_ids.contains(&g.check_id))
        .filter(|g| !direct_check_ids.contains(&g.check_id))
        .map(|g| RiskItem {
            check_id: g.check_id.clone(),
            severity: g.severity,
            title: g.title.clone(),
            matched_files: Vec::new(),
            confidence: Confidence::Medium,
        })
        .collect();

    // Historical regressions are not yet available from this query path.
    let historical_regressions = Vec::new();
    let _ = (db, project_id); // Reserved for historical regression queries.

    Ok(DeployRiskPreview {
        direct_risks: direct,
        downstream_risks: downstream,
        historical_regressions,
    })
}

/// Predict downstream resolutions from hypothetical resolved check IDs.
pub fn whatif_resolve(
    db: &Database,
    project_id: i64,
    hypothetical_resolved: Vec<String>,
) -> Result<WhatIfResult, String> {
    let active_check_ids: HashSet<String> = db
        .get_active_check_ids(project_id)
        .map_err(|e| e.to_string())?;
    let observations = ObservationIndex::load(db, project_id)?;

    let mut effects: HashMap<String, (Confidence, Vec<String>)> = HashMap::new();

    for resolved in &hypothetical_resolved {
        for link in CAUSAL_LINKS {
            if link.cause == resolved && active_check_ids.contains(link.effect) {
                let (r, a) = observations.for_link(resolved, link.effect);
                let calibrated = dynamic_confidence(link.confidence, r, a);
                effects
                    .entry(link.effect.to_string())
                    .and_modify(|(c, v)| {
                        if calibrated.as_f32() > c.as_f32() {
                            *c = calibrated;
                        }
                        v.push(resolved.clone());
                    })
                    .or_insert_with(|| (calibrated, vec![resolved.clone()]));
            }
        }
    }

    let also_resolves: Vec<WhatIfEffect> = effects
        .into_iter()
        .map(|(check_id, (confidence, via))| WhatIfEffect {
            check_id,
            confidence,
            via,
        })
        .collect();

    // Surface evidence rows that justify the confidence scores. For v3 we
    // include observation counts inline so callers can display the basis.
    let mut confidence_basis: Vec<Evidence> = Vec::new();
    for entry in &also_resolves {
        for via_cause in &entry.via {
            let (r, a) = observations.for_link(via_cause, &entry.check_id);
            if a > 0 {
                confidence_basis.push(Evidence {
                    kind: "Observation".into(),
                    timestamp: None,
                    source: "causal_link_observations".into(),
                    detail: format!(
                        "{} -> {}: co-resolved {} of {} observations",
                        via_cause, entry.check_id, r, a
                    ),
                });
            }
        }
    }

    Ok(WhatIfResult {
        also_resolves,
        confidence_basis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_helpers::temp_db;
    use crate::db::work_items::WorkItemInput;
    use crate::db::work_items::WorkItemMetadata;

    fn seed_work_item(db: &Database, project_id: i64, check_id: &str, source: &str, env_url: &str) {
        let input = WorkItemInput {
            project_id,
            env_url: env_url.into(),
            source: source.into(),
            signal_id: format!("{}:{}:{}", source, check_id, env_url),
            check_id: check_id.into(),
            category: "performance".into(),
            severity: Severity::Medium,
            title: format!("{} issue", check_id),
            description: "test description".into(),
            detail_json: None,
            scan_ref: None,
            page_url: None,
            fix_prompt: None,
            manual_fix: None,
            why_it_matters: None,
            observed_at: 1_000,
            metadata: WorkItemMetadata::default(),
        };
        db.upsert_work_items_diff(source, project_id, env_url, vec![input], 1_000)
            .expect("seed work item");
    }

    #[test]
    fn preview_returns_empty_when_no_overlap() {
        let db = temp_db();
        let project_id = db
            .upsert_project("P", "https://example.com", None)
            .expect("project");
        seed_work_item(
            &db,
            project_id,
            "performance.compression",
            "web_scan",
            "https://example.com",
        );

        // Changed file does not match any fix_location (fix_locations are populated by
        // resolver, but in this raw-work-item test they are empty, so no match).
        let result = preview_deploy_risk(&db, project_id, vec!["unrelated/file.ts".into()])
            .expect("preview");
        assert!(
            result.direct_risks.is_empty(),
            "expected no direct risks when changed files don't match any fix_location"
        );
        assert!(
            result.downstream_risks.is_empty(),
            "expected no downstream risks"
        );
    }

    #[test]
    fn preview_returns_empty_for_project_with_no_active_items() {
        let db = temp_db();
        let project_id = db
            .upsert_project("P2", "https://example.com", None)
            .expect("project");

        let result =
            preview_deploy_risk(&db, project_id, vec!["src/index.ts".into()]).expect("preview");
        assert!(result.direct_risks.is_empty());
        assert!(result.downstream_risks.is_empty());
        assert!(result.historical_regressions.is_empty());
    }

    #[test]
    fn preview_historical_regressions_is_empty_pending_phase9() {
        let db = temp_db();
        let project_id = db
            .upsert_project("P3", "https://example.com", None)
            .expect("project");

        let result = preview_deploy_risk(&db, project_id, vec![]).expect("preview");
        assert!(
            result.historical_regressions.is_empty(),
            "historical_regressions is always empty until phase-9 persistence is added"
        );
    }

    #[test]
    fn whatif_compression_predicts_lcp_resolution() {
        let db = temp_db();
        let project_id = db
            .upsert_project("WhatIf1", "https://example.com", None)
            .expect("project");

        seed_work_item(
            &db,
            project_id,
            "performance.compression",
            "web_scan",
            "https://example.com",
        );
        seed_work_item(
            &db,
            project_id,
            "performance.lcp",
            "psi",
            "https://example.com",
        );

        let result = whatif_resolve(&db, project_id, vec!["performance.compression".into()])
            .expect("whatif");

        assert!(
            result
                .also_resolves
                .iter()
                .any(|e| e.check_id == "performance.lcp"),
            "resolving compression should predict lcp resolution; got: {:?}",
            result.also_resolves
        );
    }

    #[test]
    fn whatif_returns_empty_when_effect_not_active() {
        let db = temp_db();
        let project_id = db
            .upsert_project("WhatIf2", "https://example.com", None)
            .expect("project");

        // Only seed compression, not lcp
        seed_work_item(
            &db,
            project_id,
            "performance.compression",
            "web_scan",
            "https://example.com",
        );

        let result = whatif_resolve(&db, project_id, vec!["performance.compression".into()])
            .expect("whatif");

        assert!(
            !result
                .also_resolves
                .iter()
                .any(|e| e.check_id == "performance.lcp"),
            "lcp should not appear in also_resolves when it is not an active issue"
        );
    }

    #[test]
    fn whatif_returns_empty_for_unknown_check_id() {
        let db = temp_db();
        let project_id = db
            .upsert_project("WhatIf3", "https://example.com", None)
            .expect("project");

        let result =
            whatif_resolve(&db, project_id, vec!["nonexistent.check_id".into()]).expect("whatif");

        assert!(
            result.also_resolves.is_empty(),
            "no causal links for unknown check_id"
        );
    }

    #[test]
    fn whatif_includes_confidence_basis_when_observations_exist() {
        let db = temp_db();
        let project_id = db
            .upsert_project("WhatIf4", "https://example.com", None)
            .expect("project");

        seed_work_item(
            &db,
            project_id,
            "performance.compression",
            "web_scan",
            "https://example.com",
        );
        seed_work_item(
            &db,
            project_id,
            "performance.lcp",
            "psi",
            "https://example.com",
        );

        // Insert observation history for the compression -> lcp link
        db.execute(move |conn| {
            conn.execute(
                "INSERT INTO causal_link_observations
                 (project_id, cause_check_id, effect_check_id, co_resolved, co_active, observed_at)
                 VALUES (?1, 'performance.compression', 'performance.lcp', 8, 10, 1000)",
                rusqlite::params![project_id],
            )
        })
        .expect("execute insert")
        .expect("insert observations");

        let result = whatif_resolve(&db, project_id, vec!["performance.compression".into()])
            .expect("whatif");

        assert!(
            !result.confidence_basis.is_empty(),
            "confidence_basis should contain at least one observation row; got: {:?}",
            result.confidence_basis
        );
        assert!(
            result
                .confidence_basis
                .iter()
                .any(|e| e.source == "causal_link_observations"),
            "evidence source should be causal_link_observations; got: {:?}",
            result.confidence_basis
        );
    }

    /// Perf gate: preview_deploy_risk p95 must stay under 200ms for 100 changed files.
    ///
    /// Run with: `cargo test -p sitecmd-runtime --lib -- --ignored preview_deploy_risk_p95_under_200ms`
    #[test]
    #[ignore = "perf gate; run with --ignored"]
    fn preview_deploy_risk_p95_under_200ms() {
        let db = temp_db();
        let project_id = db
            .upsert_project("PerfBench", "https://example.com", None)
            .expect("project");

        // Seed a handful of active work items so get_work_items_grouped has real rows.
        for check_id in &[
            "performance.compression",
            "performance.lcp",
            "performance.render_blocking",
            "seo.canonical.missing",
            "security.https",
        ] {
            seed_work_item(&db, project_id, check_id, "web_scan", "https://example.com");
        }

        let files: Vec<String> = (0..100).map(|i| format!("src/file{i}.ts")).collect();

        let mut samples = Vec::with_capacity(100);
        for _ in 0..100 {
            let start = std::time::Instant::now();
            let _preview = preview_deploy_risk(&db, project_id, files.clone()).unwrap();
            samples.push(start.elapsed().as_micros() as u64);
        }

        samples.sort_unstable();
        let p95 = samples[(samples.len() * 95) / 100];
        let p95_ms = p95 as f64 / 1000.0;
        println!("preview_deploy_risk p95 = {p95_ms:.2}ms");
        assert!(
            p95_ms < 200.0,
            "preview p95 {p95_ms:.2}ms exceeds 200ms budget"
        );
    }

    #[test]
    fn whatif_multiple_causes_expand_effects() {
        let db = temp_db();
        let project_id = db
            .upsert_project("WhatIf5", "https://example.com", None)
            .expect("project");

        seed_work_item(
            &db,
            project_id,
            "performance.compression",
            "web_scan",
            "https://example.com",
        );
        seed_work_item(
            &db,
            project_id,
            "performance.render_blocking",
            "web_scan",
            "https://example.com",
        );
        seed_work_item(
            &db,
            project_id,
            "performance.lcp",
            "psi",
            "https://example.com",
        );

        let result = whatif_resolve(
            &db,
            project_id,
            vec![
                "performance.compression".into(),
                "performance.render_blocking".into(),
            ],
        )
        .expect("whatif");

        // Both compression and render_blocking have lcp as an effect
        let lcp_entry = result
            .also_resolves
            .iter()
            .find(|e| e.check_id == "performance.lcp");
        assert!(
            lcp_entry.is_some(),
            "lcp should appear in also_resolves; got: {:?}",
            result.also_resolves
        );
        let via = &lcp_entry.unwrap().via;
        assert!(
            !via.is_empty(),
            "via should contain at least one cause; got: {:?}",
            via
        );
    }

    #[test]
    fn whatif_observation_storage_failure_is_not_uncalibrated_confidence() {
        let db = temp_db();
        let project_id = db
            .upsert_project("test", "https://example.com", None)
            .expect("upsert project");
        db.execute(|conn| {
            conn.execute("DROP TABLE causal_link_observations", [])
                .map(|_| ())
        })
        .expect("database worker")
        .expect("drop observation table");

        let error = whatif_resolve(&db, project_id, vec!["performance.compression".to_string()])
            .expect_err("missing calibration evidence must not silently use defaults");

        assert!(error.contains("causal_link_observations"));
    }
}
