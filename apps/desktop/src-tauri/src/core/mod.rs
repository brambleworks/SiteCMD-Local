//! Scan integration, project and localhost detection, and issue correlation.

pub mod audit;
pub mod code_provenance;
mod database_snapshot;
pub mod database_targets;
mod engine_facts;
pub mod engine_io;
pub mod engine_release;
mod filesystem;
pub mod fix_templates;
pub(crate) mod fixes;
pub mod git;
pub mod localhost;
pub mod normalized_scan;
pub mod project_listing;
pub(crate) mod safe_fs;
pub mod scan_execution;
mod scan_scope;
pub mod scan_types;
#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(any(test, feature = "test-support"))]
mod postgres_test_support;
