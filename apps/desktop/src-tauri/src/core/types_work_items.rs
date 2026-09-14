use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::checks::Severity;
use crate::core::correlation::{Confidence, IntegrationSuggestion, LikelyCause};

// Re-export the engine's lifecycle vocabulary at the desktop's established path.
// SQLite schema-pinning tests remain desktop-side.
pub use sitecmd_engine::{IssueStatus, VerifiedBy};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct FixLocation {
    pub label: String,
    pub reason: String,
    pub relative_path: String,
    pub absolute_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct IssueGroup {
    pub check_id: String,
    pub category: String,
    pub severity: Severity, // max across instances (critical > high > medium > low)
    pub title: String,
    pub description: String,
    pub instances: Vec<IssueInstance>,
    pub sources: Vec<String>, // distinct sources, sorted
    pub status: IssueStatus,
    pub snooze_until: Option<i64>,
    pub block_reason: Option<String>,
    pub impact_score: f64,

    #[serde(default)]
    pub likely_causes: Vec<LikelyCause>,

    #[serde(default)]
    pub suggested_integrations: Vec<IntegrationSuggestion>,

    #[serde(default)]
    pub fix_locations: Vec<FixLocation>,

    #[serde(default)]
    pub transitive_causes: Vec<TransitiveCause>,
    #[serde(default)]
    pub downstream_effects: Vec<String>,
    #[serde(default)]
    pub recent_events: Vec<RecentEventRef>,
    #[serde(default)]
    pub enrichments: Vec<Enrichment>,
    #[serde(default)]
    pub correlation_evidence: Vec<Evidence>,
    #[serde(default)]
    pub affected_pages: Vec<String>,
    #[serde(default)]
    pub cross_env_signal: Option<CrossEnvSignal>,
    #[serde(default)]
    pub cross_project_pattern: Option<CrossProjectPattern>,
    #[serde(default)]
    pub display_confidence: Option<Confidence>,
    #[serde(default)]
    pub observation_count: i64,
    #[serde(default)]
    pub anomaly_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct IssueInstance {
    pub id: i64,
    pub source: String,
    pub signal_id: String,
    /// Exact producer check ID before canonical issue-group mapping. New Web
    /// Scan rows always set it; legacy and non-Web sources may leave it absent.
    #[serde(default)]
    pub producer_check_id: Option<String>,
    pub url: Option<String>,      // legacy, from extract_from_signal_id
    pub page_url: Option<String>, // from work_items.page_url
    pub severity: Severity,
    pub title: String,
    pub description: String,
    /// Exact source category for this occurrence. Optional on the wire for
    /// compatibility with clients generated before per-instance issue content
    /// was promoted, but populated for every persisted work item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub check_status: Option<crate::checks::CheckStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub fix_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub manual_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub why_it_matters: Option<String>,
    pub detail_json: Option<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    // Promoted work_items columns. Behavior-driving metadata, not
    // entitlement-gated content: these survive the Free-tier detail_json
    // redaction (path/line already reach Free via signal_id).
    #[serde(default)]
    pub confidence: Option<crate::checks::IssueConfidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub confidence_reason: Option<String>,
    #[serde(default)]
    pub domain: Option<crate::core::code_scan::CodeScanDomain>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub producer_fix_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub producer_category: Option<crate::checks::ScanCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct PageSummary {
    pub page_url: String,
    pub label: String,
    pub issue_count: i64,
    pub max_severity: Severity,
    pub sources: Vec<String>,
}

// Portable scorer output schema re-exported for IPC and desktop consumers.
pub use sitecmd_engine::scoring::calculator::{ScoreBreakdown, ScoreSnapshot};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct TransitiveCause {
    pub check_id: String,
    pub path: Vec<String>,
    pub confidence: Confidence,
    pub depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct RecentEventRef {
    pub event_id: i64,
    pub event_type: String,
    pub occurred_at_ms: i64,
    pub title: String,
    pub correlation_confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum Enrichment {
    FieldLcp {
        p75_ms: u32,
        url: String,
        source: String,
    },
    FieldCls {
        value: f32,
        url: String,
        source: String,
    },
    FieldInp {
        p75_ms: u32,
        url: String,
        source: String,
    },
    SearchImpressionsDrop {
        from: u32,
        to: u32,
        days: u32,
        source: String,
    },
    RecentCrawlErrors {
        count: u32,
        days: u32,
        source: String,
    },
    RecentDowntime {
        window_start: String,
        window_end: String,
        source: String,
    },
    CertExpiresIn {
        days: i64,
        source: String,
    },
    CertChain {
        issues: Vec<String>,
        source: String,
    },
    TtfbHistory {
        p75_ms: u32,
        days: u32,
        source: String,
    },
    BotTrafficPct {
        value: f32,
        source: String,
    },
    CacheHitRate {
        value: f32,
        source: String,
    },
    RecentFiveXxSpike {
        rate: f32,
        started_at: String,
        source: String,
    },
    RecentOriginErrors {
        count: u32,
        days: u32,
        source: String,
    },
    TopFallingPage {
        url: String,
        pct_drop: f32,
        source: String,
    },
    TopFallingFunnel {
        name: String,
        pct_drop: f32,
        source: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct Evidence {
    pub kind: String,
    pub timestamp: Option<String>,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct CrossEnvSignal {
    pub staging_observed_at: String,
    pub days_before_prod: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct CrossProjectPattern {
    pub project_count: i64,
    pub last_seen_at: String,
}

#[cfg(test)]
mod issue_status_tests {
    use super::IssueStatus;

    /// Schema and enum lifecycle vocabularies must match exactly.
    #[test]
    fn issue_status_vocabulary_matches_schema_check_constraint() {
        let snapshot = include_str!("../db/schema_snapshot.sql");
        let check_line = snapshot
            .lines()
            .find(|line| line.contains("status TEXT NOT NULL CHECK(status IN ("))
            .expect("project_issue_states status CHECK constraint in schema snapshot");
        let allowed: std::collections::BTreeSet<&str> = check_line
            .split_once("IN (")
            .expect("CHECK IN list")
            .1
            .split(')')
            .next()
            .expect("CHECK list body")
            .split(',')
            .map(|value| value.trim().trim_matches('\''))
            .collect();
        let variants: std::collections::BTreeSet<&str> =
            IssueStatus::ALL.into_iter().map(|s| s.as_str()).collect();
        assert_eq!(
            variants, allowed,
            "IssueStatus variants and the project_issue_states CHECK constraint disagree"
        );
    }

    /// Pin verification provenance vocabulary to the schema constraint.
    #[test]
    fn verified_by_vocabulary_matches_schema_check_constraint() {
        let snapshot = include_str!("../db/schema_snapshot.sql");
        let check_line = snapshot
            .lines()
            .find(|line| line.contains("verified_by IN ("))
            .expect("project_issue_states verified_by CHECK constraint in schema snapshot");
        let allowed: std::collections::BTreeSet<&str> = check_line
            .split_once("verified_by IN (")
            .expect("CHECK IN list")
            .1
            .split(')')
            .next()
            .expect("CHECK list body")
            .split(',')
            .map(|value| value.trim().trim_matches('\''))
            .collect();
        let variants: std::collections::BTreeSet<&str> = super::VerifiedBy::ALL
            .into_iter()
            .map(|by| by.as_str())
            .collect();
        assert_eq!(
            variants, allowed,
            "VerifiedBy variants and the project_issue_states CHECK constraint disagree"
        );
    }

    /// The invariant the reconcilers depend on: exactly one provenance means
    /// the issue was actually observed to be gone. If a second one ever
    /// qualifies, re-observation has a new regression path to consider.
    #[test]
    fn only_a_scan_proves_absence() {
        let proving: Vec<&str> = super::VerifiedBy::ALL
            .into_iter()
            .filter(|by| by.proves_absence())
            .map(|by| by.as_str())
            .collect();
        assert_eq!(proving, vec!["local_scan"]);
        assert!(!super::VerifiedBy::UserClaim.proves_absence());
    }

    #[test]
    fn issue_status_round_trips_through_display_fromstr_and_serde() {
        for status in IssueStatus::ALL {
            let display = status.to_string();
            assert_eq!(display.parse::<IssueStatus>(), Ok(status));
            let json = serde_json::to_string(&status).expect("serialize");
            assert_eq!(json, format!("\"{}\"", status.as_str()));
            let back: IssueStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, status);
        }
        assert!("wontfix".parse::<IssueStatus>().is_err());
    }

    /// Keep the frontend issue-status manifest synchronized with Rust.
    #[test]
    fn issue_status_json_is_in_sync_with_frontend_copy() {
        let statuses: Vec<&str> = IssueStatus::ALL.into_iter().map(|s| s.as_str()).collect();
        let inactive: Vec<&str> = IssueStatus::ALL
            .into_iter()
            .filter(|s| s.is_inactive_for_scoring())
            .map(|s| s.as_str())
            .collect();
        let manifest = serde_json::json!({
            "_generated": "GENERATED by issue_status_json_is_in_sync_with_frontend_copy in \
        apps/desktop/src-tauri/src/core/types_work_items.rs. Do not edit by hand: change the \
        IssueStatus enum, run cargo test, commit the diff.",
            "statuses": statuses,
            "inactive_for_scoring": inactive,
        });
        let expected = serde_json::to_string_pretty(&manifest).expect("serialize manifest") + "\n";

        let manifest_dir = std::path::PathBuf::from(env!("SITECMD_SOURCE_ROOT"));
        let target = manifest_dir
            .parent()
            .expect("desktop app root")
            .join("src")
            .join("generated")
            .join("issue_status.json");
        let actual = std::fs::read_to_string(&target).unwrap_or_default();
        if actual != expected {
            std::fs::create_dir_all(target.parent().expect("generated dir"))
                .expect("create generated dir");
            std::fs::write(&target, &expected).expect("write issue_status.json");
            panic!(
                "stale issue_status.json regenerated at {}; re-run cargo test and commit the diff",
                target.display()
            );
        }
    }
}
