//! Core scanning infrastructure: scanner orchestrator, git integration, project detection,
//! sitemap discovery, localhost detection, event ingestion, cross-source issue correlation.

pub mod analysis_types;
pub mod code_provenance;
pub mod code_scan;
pub mod confidence_policy;
pub mod correlation;
pub mod database_targets;
pub mod desktop_heartbeat;
pub mod detector;
pub mod engine_release;
pub mod event_correlations;
pub mod fix_brief;
pub mod git;
pub mod localhost;
pub mod native_alerts;
pub mod normalized_scan;
pub mod page_signals;
pub mod project;
pub mod regression_blame;
pub(crate) mod safe_fs;
pub mod scan_execution;
pub mod scanner;
pub mod session_analysis;
pub mod severity_policy;
pub mod sitemap;
pub mod types_work_items;
pub mod work_item_projection;
