//! Backward-compatible custody metadata for selecting the latest persisted bearer.

use super::{StoredToken, Zeroizing};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};

static LAST_SAVE: AtomicI64 = AtomicI64::new(0);

#[derive(Serialize, Deserialize)]
pub(super) struct Record {
    #[serde(flatten)]
    pub credential: StoredToken,
    #[serde(default)]
    pub saved_at: i64,
}

impl Record {
    pub fn new(token: &StoredToken) -> Self {
        let now = jiff::Timestamp::now().as_microsecond();
        let previous = LAST_SAVE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |previous| {
                Some(now.max(previous.saturating_add(1)))
            })
            .unwrap_or_else(|previous| previous);
        Self {
            credential: token.clone(),
            saved_at: now.max(previous.saturating_add(1)),
        }
    }

    pub fn decode(bytes: Vec<u8>) -> Result<Self, String> {
        let record: Self = serde_json::from_slice(&Zeroizing::new(bytes))
            .map_err(|_| "stored credential is invalid")?;
        record.observe();
        Ok(record)
    }

    pub fn observe(&self) {
        LAST_SAVE.fetch_max(self.saved_at, Ordering::SeqCst);
    }
}
