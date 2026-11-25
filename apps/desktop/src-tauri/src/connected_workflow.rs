//! Portable connected-payload decisions shared by the desktop and CLI.

use crate::db::ProducerIdentity;

/// Return the sequence an inspector may display without reserving it.
pub fn proposed_submission_sequence(producer: Option<&ProducerIdentity>) -> Result<i64, String> {
    producer
        .map(|identity| identity.last_submission_sequence)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| "connected submission sequence is exhausted".to_string())
}
