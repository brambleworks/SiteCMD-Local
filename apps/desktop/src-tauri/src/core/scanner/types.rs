use crate::checks::{CheckResult, ScanCategory};
use crate::scoring::calculator;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Progress callback type - replaces Tauri's AppHandle for emitting scan progress.
/// Desktop app wraps `AppHandle::emit`, CLI wraps stderr output.
pub type ProgressFn = dyn Fn(&ScanProgress) + Send + Sync;

/// Web Scan category filter serialized into `scans.scan_type` and `web_focus`.
/// This differs from the `web | code` subsystem discriminator used by events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum ScanType {
    #[default]
    Health,
    Security,
    Accessibility,
    Polish,
}

impl ScanType {
    pub const ALL: [ScanType; 4] = [
        ScanType::Health,
        ScanType::Security,
        ScanType::Accessibility,
        ScanType::Polish,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ScanType::Health => "health",
            ScanType::Security => "security",
            ScanType::Accessibility => "accessibility",
            ScanType::Polish => "polish",
        }
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ScanType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ScanType::ALL
            .into_iter()
            .find(|scan_type| scan_type.as_str() == value)
            .ok_or_else(|| format!("unknown ScanType: {}", value))
    }
}

/// Schedulable Web Scan focuses plus the separate Code Scan engine.
/// Serialized into `scan_schedules.scan_type` and IPC payloads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum ScheduledScanType {
    #[default]
    Health,
    Security,
    Accessibility,
    Polish,
    Code,
    /// Full web scan plus Code Scan when a source folder is linked.
    Full,
}

impl ScheduledScanType {
    pub const ALL: [ScheduledScanType; 6] = [
        ScheduledScanType::Health,
        ScheduledScanType::Security,
        ScheduledScanType::Accessibility,
        ScheduledScanType::Polish,
        ScheduledScanType::Code,
        ScheduledScanType::Full,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ScheduledScanType::Health => "health",
            ScheduledScanType::Security => "security",
            ScheduledScanType::Accessibility => "accessibility",
            ScheduledScanType::Polish => "polish",
            ScheduledScanType::Code => "code",
            ScheduledScanType::Full => "full",
        }
    }

    /// Single web focus, excluding Code and Full composite schedules.
    pub fn web_scan_type(self) -> Option<ScanType> {
        match self {
            ScheduledScanType::Health => Some(ScanType::Health),
            ScheduledScanType::Security => Some(ScanType::Security),
            ScheduledScanType::Accessibility => Some(ScanType::Accessibility),
            ScheduledScanType::Polish => Some(ScanType::Polish),
            ScheduledScanType::Code => None,
            ScheduledScanType::Full => None,
        }
    }

    /// `(web focus, run code)` plan for a scheduled execution.
    pub fn scheduled_run_plan(self) -> (Option<ScanType>, bool) {
        match self {
            ScheduledScanType::Full => (Some(ScanType::Health), true),
            ScheduledScanType::Code => (None, true),
            other => (other.web_scan_type(), false),
        }
    }
}

impl From<ScanType> for ScheduledScanType {
    fn from(value: ScanType) -> Self {
        match value {
            ScanType::Health => ScheduledScanType::Health,
            ScanType::Security => ScheduledScanType::Security,
            ScanType::Accessibility => ScheduledScanType::Accessibility,
            ScanType::Polish => ScheduledScanType::Polish,
        }
    }
}

impl std::fmt::Display for ScheduledScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ScheduledScanType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ScheduledScanType::ALL
            .into_iter()
            .find(|scan_type| scan_type.as_str() == value)
            .ok_or_else(|| format!("unknown ScheduledScanType: {}", value))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ScanResult {
    pub url: String,
    pub mode: String, // "live" | "predeploy"
    pub scan_type: ScanType,
    pub overall_score: u32,
    pub categories: Vec<calculator::CategoryScore>,
    pub issues: Vec<CheckResult>,
    #[ts(type = "unknown")]
    pub detected_stack: Option<serde_json::Value>,
    pub duration_ms: u64,
    pub timestamp: String,
    /// Cross-page analysis input, never persisted or sent to the frontend.
    #[serde(skip)]
    #[ts(skip)]
    pub page_signals: Option<crate::core::page_signals::PageSignals>,
    /// Verified-good evidence consumed only by the persistence path.
    #[serde(skip)]
    #[ts(skip)]
    pub site_facts: Option<sitecmd_engine::profile::Observation>,
}

/// Progress event payload sent to the frontend via Tauri events.
#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub check_id: String,
    pub category: ScanCategory,
    pub status: String, // "running" | "complete" | "skipped"
    pub results_count: usize,
    pub checks_done: usize,
    pub checks_total: usize,
}

/// Multi-page scan progress event.
#[derive(Debug, Clone, Serialize)]
pub struct MultiScanProgress {
    pub page_index: usize,
    pub page_count: usize,
    pub current_url: String,
    pub page_status: String, // "scanning" | "complete" | "error"
    pub session_id: i64,
}

/// Multi-page scan session result.
#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct MultiScanResult {
    pub session_id: i64,
    pub total_pages: usize,
    pub completed_pages: usize,
    pub overall_score: u32,
    pub duration_ms: u64,
    #[serde(default)]
    pub incomplete_detail: Option<String>,
    pub page_results: Vec<PageScanSummary>,
    /// Canonical issue groups activated during this session.
    #[serde(default)]
    pub new_issue_count: Option<usize>,
    /// Canonical issue groups resolved, or `None` without a persisted project.
    #[serde(default)]
    pub resolved_issue_count: Option<usize>,
    /// Site-wide findings from cross-page analysis (duplicate titles, orphan
    /// pages, canonical loops,...). Empty for sessions under two pages.
    #[serde(default)]
    pub site_issues: Vec<CheckResult>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct PageScanSummary {
    pub url: String,
    pub score: u32,
    pub issues_count: usize,
    pub issues_critical: usize,
    pub issues_high: usize,
    pub issues_medium: usize,
    pub issues_low: usize,
    pub duration_ms: u64,
    pub scan_id: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Scan cancelled")]
    Cancelled,
    #[error("Scan error: {0}")]
    ScanFailed(String),
}

impl serde::Serialize for ScanError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct VerifyChecksResult {
    pub effective_url: String,
    pub results: Vec<CheckResult>,
}

#[cfg(test)]
mod scan_type_tests {
    use super::{ScanType, ScheduledScanType};
    use std::collections::BTreeSet;

    fn variant_set<const N: usize>(all: [&'static str; N]) -> BTreeSet<&'static str> {
        all.into_iter().collect()
    }

    fn constraint_values<'a>(snapshot: &'a str, table: &str, marker: &str) -> BTreeSet<&'a str> {
        let definition = snapshot
            .split_once(&format!("CREATE TABLE {table} ("))
            .unwrap_or_else(|| panic!("missing {table} schema"))
            .1
            .split_once("\n);")
            .unwrap_or_else(|| panic!("unterminated {table} schema"))
            .0;
        definition
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing {table}.{marker} constraint"))
            .1
            .split_once('(')
            .expect("CHECK IN list")
            .1
            .split_once(')')
            .expect("CHECK list body")
            .0
            .split(',')
            .map(|value| value.trim().trim_matches('\''))
            .collect()
    }

    /// Keep enum vocabularies synchronized with schema CHECK constraints.
    #[test]
    fn scan_type_vocabularies_match_schema_check_constraints() {
        let snapshot = include_str!("../../db/schema_snapshot.sql");
        let scan_variants = variant_set(ScanType::ALL.map(|s| s.as_str()));
        let scheduled_variants = variant_set(ScheduledScanType::ALL.map(|s| s.as_str()));
        assert_eq!(
            constraint_values(snapshot, "scan_executions", "web_focus IN"),
            scan_variants,
            "ScanType variants and scan_executions.web_focus disagree"
        );
        assert_eq!(
            constraint_values(snapshot, "scan_schedules", "scan_type IN"),
            scheduled_variants,
            "ScheduledScanType variants and the scan_schedules.scan_type CHECK constraint disagree"
        );
    }

    #[test]
    fn scan_types_round_trip_and_reject_unknown_values() {
        for scan_type in ScanType::ALL {
            assert_eq!(scan_type.to_string().parse::<ScanType>(), Ok(scan_type));
            let json = serde_json::to_string(&scan_type).expect("serialize");
            assert_eq!(json, format!("\"{}\"", scan_type.as_str()));
            let back: ScanType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, scan_type);
            // Every web focus is schedulable and maps back to itself.
            assert_eq!(
                ScheduledScanType::from(scan_type).web_scan_type(),
                Some(scan_type)
            );
        }
        for scheduled in ScheduledScanType::ALL {
            assert_eq!(
                scheduled.to_string().parse::<ScheduledScanType>(),
                Ok(scheduled)
            );
            let json = serde_json::to_string(&scheduled).expect("serialize");
            assert_eq!(json, format!("\"{}\"", scheduled.as_str()));
            let back: ScheduledScanType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, scheduled);
        }
        assert_eq!(ScheduledScanType::Code.web_scan_type(), None);
        // Full dispatches web + code together, so it has no single web focus.
        assert_eq!(ScheduledScanType::Full.web_scan_type(), None);
        assert_eq!(
            ScheduledScanType::Full.scheduled_run_plan(),
            (Some(ScanType::Health), true)
        );
        assert_eq!(ScheduledScanType::Code.scheduled_run_plan(), (None, true));
        assert_eq!(
            ScheduledScanType::Health.scheduled_run_plan(),
            (Some(ScanType::Health), false)
        );
        assert_eq!(
            ScheduledScanType::Security.scheduled_run_plan(),
            (Some(ScanType::Security), false)
        );
        assert_eq!(
            serde_json::from_str::<ScheduledScanType>("\"full\"").unwrap(),
            ScheduledScanType::Full
        );

        assert!("full".parse::<ScanType>().is_err());
        assert!("code".parse::<ScanType>().is_err());
        assert!(serde_json::from_str::<ScanType>("\"code\"").is_err());
        assert!(serde_json::from_str::<ScanType>("\"full\"").is_err());
        assert!("web".parse::<ScheduledScanType>().is_err());
        assert_eq!(ScanType::default(), ScanType::Health);
        assert_eq!(ScheduledScanType::default(), ScheduledScanType::Health);
    }

    /// Keep the frontend scan-type manifest synchronized with Rust.
    #[test]
    fn scan_type_json_is_in_sync_with_frontend_copy() {
        let scan_types: Vec<&str> = ScanType::ALL.into_iter().map(|s| s.as_str()).collect();
        let scheduled_scan_types: Vec<&str> = ScheduledScanType::ALL
            .into_iter()
            .map(|s| s.as_str())
            .collect();
        let manifest = serde_json::json!({
            "_generated": "GENERATED by scan_type_json_is_in_sync_with_frontend_copy in \
        apps/desktop/src-tauri/src/core/scanner/types.rs. Do not edit by hand: change the \
        ScanType/ScheduledScanType enums, run cargo test, commit the diff.",
            "scan_types": scan_types,
            "scheduled_scan_types": scheduled_scan_types,
        });
        let expected = serde_json::to_string_pretty(&manifest).expect("serialize manifest") + "\n";

        let manifest_dir = std::path::PathBuf::from(env!("SITECMD_SOURCE_ROOT"));
        let target = manifest_dir
            .parent()
            .expect("desktop app root")
            .join("src")
            .join("generated")
            .join("scan_type.json");
        let actual = std::fs::read_to_string(&target).unwrap_or_default();
        if actual != expected {
            std::fs::create_dir_all(target.parent().expect("generated dir"))
                .expect("create generated dir");
            std::fs::write(&target, &expected).expect("write scan_type.json");
            panic!(
                "stale scan_type.json regenerated at {}; re-run cargo test and commit the diff",
                target.display()
            );
        }
    }
}
