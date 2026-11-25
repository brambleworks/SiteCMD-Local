//! Request paths and query values cannot be assembled from arbitrary text.
use sitecmd_protocol::sync::wire::{CheckId, Identifier, Timestamp};

pub(crate) struct RequestUrl(pub(super) url::Url);
impl RequestUrl {
    pub(crate) fn with_cursor(mut self, cursor: &Identifier) -> Self {
        self.0
            .query_pairs_mut()
            .append_pair("cursor", cursor.as_str());
        self
    }
    pub(crate) fn with_group_cursor(mut self, check: &CheckId) -> Self {
        self.0
            .query_pairs_mut()
            .append_pair("cursor", check.as_str());
        self
    }
    pub(crate) fn with_scan_cursor(mut self, timestamp: &Timestamp, scan: &Identifier) -> Self {
        self.0
            .query_pairs_mut()
            .append_pair("cursor", &format!("{timestamp} {scan}"));
        self
    }
    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
