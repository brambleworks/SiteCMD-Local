//! Host services for the engine module.

#[path = "../build_support.rs"]
mod build_support;
mod load;
mod session;
mod workers;

pub mod walker_pruning;
pub mod wants;

#[cfg(any(test, feature = "compile"))]
pub use load::load_bytes;
pub use load::{
    embedded_module, load, unpinned, Engine, EngineError, LOCAL_SITE_DEADLINE, MODULE_MEMORY_LIMIT,
    MODULE_TABLE_ELEMENT_LIMIT,
};
pub use session::{Interrupt, ModuleSession, MODULE_ANSWER_LIMIT};

/// Apply the host's public redaction to outbound evidence.
pub fn redact_evidence(text: String) -> String {
    sitecmd_protocol::log_sanitizer::redact_evidence_secrets(&text)
}

#[cfg(test)]
mod load_tests;

#[cfg(test)]
#[path = "../build_input.rs"]
mod build_input;
