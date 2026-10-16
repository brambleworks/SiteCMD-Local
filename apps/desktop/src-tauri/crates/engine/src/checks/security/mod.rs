//! Portable security checks. The desktop's `checks::security` module
//! re-exports these so registration and call sites keep their paths.

pub mod client_auth;
pub mod cookies;
pub mod cors;
pub mod cross_origin;
pub mod csrf;
pub mod directory_listing;
pub mod dns_email;
pub mod email_exposure;
pub mod env_exposure;
pub mod exposed_files;
pub mod exposed_keys;
pub mod forms;
pub mod hardcoded_secrets;
pub mod headers;
pub mod https_enforcement;
pub(crate) mod key_patterns;
pub mod mixed_content;
pub mod open_redirect;
pub mod security_txt;
pub mod server_info;
pub mod sri;
pub mod tls;
pub mod vulnerable_libraries;
