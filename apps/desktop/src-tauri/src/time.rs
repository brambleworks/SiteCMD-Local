//! Native clock access for the desktop and headless runtime.

use sitecmd_protocol::time::UtcTimestamp;

pub fn now_utc() -> UtcTimestamp {
    jiff::Timestamp::now().into()
}

pub fn now_millis() -> i64 {
    jiff::Timestamp::now().as_millisecond()
}
