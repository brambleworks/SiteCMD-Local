//! Native scan, persistence, and command runtime shared by desktop and CLI.

pub mod ai;
pub mod api_cache;
pub mod app_identity;
pub mod audit_log;
pub mod catalog;
pub mod checks;
pub mod cli;
pub mod connected_alerts;
pub mod connected_baseline;
pub mod connected_ci;
pub mod connected_credentials;
pub mod connected_delivery;
pub mod connected_export;
pub mod connected_notifications;
pub mod connected_providers;
pub mod connected_recovery;
pub mod connected_rotation;
pub mod connected_service;
pub mod connected_workflow;
pub mod constants;
pub mod core;
pub mod db;
pub mod dns_cache;
pub mod http_client;
pub mod integrations;
pub mod licensing;
pub mod network_policy;
pub mod project_paths;
pub mod scan_runtime;
pub mod scoring;
pub mod ssl_probe;
pub mod updates;

#[cfg(feature = "browser")]
pub mod browser;
pub use sitecmd_engine::log_sanitizer;
