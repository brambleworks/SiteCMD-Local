use super::{
    keep_url, log_safe_page_url, prepare_config_credentials, redact_log_diagnostic, redact_secrets,
    sanitize_page_url_for_site, sanitize_url_reference,
};

pub(super) fn redact_log_config_credentials(input: &str) -> String {
    redact_secrets(&prepare_config_credentials(input))
}

pub(super) fn log_safe_page_url_for_site(raw_url: &str, site_origin: Option<&str>) -> String {
    sanitize_page_url_for_site(raw_url, site_origin, keep_url)
}

pub(super) fn log_safe_url_reference(raw_url: &str) -> String {
    sanitize_url_reference(raw_url, log_safe_page_url, redact_log_diagnostic)
}
