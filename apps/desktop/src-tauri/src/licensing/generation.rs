//! Invalidates asynchronous license verdicts after database writes and restores.

/// Orders same-instance writes that row contents cannot distinguish.
/// Every attempted write bumps because a timed-out dispatch may still commit.
static LICENSE_WRITE_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The current write generation, captured before an unlocked wait.
pub fn license_write_generation() -> u64 {
    LICENSE_WRITE_GENERATION.load(std::sync::atomic::Ordering::Acquire)
}

/// Record a license-row write attempt. Call under LICENSE_MUTATION, once the
/// store call has run (landed or ambiguous alike; see the statics docs).
pub fn record_license_write() {
    LICENSE_WRITE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

/// Invalidate in-flight verdicts after an external row replacement such as import.
pub fn note_license_rows_replaced() {
    record_license_write();
}
