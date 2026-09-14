//! Desktop adapters for shared integrations.

pub use sitecmd_runtime::integrations::*;
#[path = "integrations/adapters/mod.rs"]
pub mod adapters;
#[path = "integrations/desktop_google_oauth.rs"]
pub mod google_oauth;
