//! Decode persisted scan timestamps.

use sitecmd_protocol::time::UtcTimestamp;

pub fn timestamp_text_to_ms(text: &str) -> Option<i64> {
    if let Ok(dt) = UtcTimestamp::parse_from_rfc3339(text) {
        return Some(dt.timestamp_millis());
    }
    for separator in ['T', ' '] {
        if let Ok(naive) = UtcTimestamp::parse_wall_time(text, separator) {
            return Some(naive.timestamp_millis());
        }
    }
    None
}
