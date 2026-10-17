//! Portable scan engine shared by the desktop, CLI, and hosted runner.
//!
//! The crate is clockless, I/O-free, and wasm-safe. Callers inject runtime
//! facts, and golden fixtures enforce cross-runtime parity.

pub mod agent;
pub mod browser;
pub mod cap;
pub mod checks;
pub mod code_rules;
pub mod coverage;
pub mod dns;
pub mod evaluation;
pub mod header_lines;
pub mod identity;
pub mod log_sanitizer;
pub mod manifest;
pub mod measurement;
pub mod page;
pub mod probe;
pub mod profile;
pub mod release;
pub mod route;
pub mod scope;
pub mod scoring;
pub mod session;
pub mod severity_policy;
pub mod stack;
pub mod sync;
pub mod vocab;

pub use checks::Check;
pub use page::PageContext;
pub use vocab::{
    CheckResult, CheckStatus, IssueConfidence, IssueStatus, ScanCategory, Severity, VerifiedBy,
};
