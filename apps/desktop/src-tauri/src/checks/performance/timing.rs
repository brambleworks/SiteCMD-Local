//! Desktop TTFB measurement transport for portable grading.

use crate::checks::{AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::performance::ttfb;

/// Whether another request fits in the budget this check shares with the
/// scanner's per-check timeout.
///
/// The scanner wraps the whole `run` in one `CHECK_TIMEOUT`, so the samples
/// share it rather than each getting their own. The first request always runs
/// with the full budget, which keeps the behaviour a single sample had: an
/// origin slow enough to grade "Very slow TTFB" still produces a graded
/// number instead of blowing the outer guard and reporting a generic timeout.
/// A repeat only happens when the first answer left at least half the budget.
fn another_sample_fits(attempt: usize, elapsed: std::time::Duration) -> bool {
    attempt == 0 || elapsed < crate::constants::CHECK_TIMEOUT / 2
}

/// What is left of the shared budget for one request, so no sample can push
/// the check past the timeout the scanner allows it.
///
/// The repeat is clamped to half the budget rather than the whole remainder.
/// The scanner's outer guard starts its clock when the future is constructed,
/// slightly before `run` is first polled, so spending the exact remainder on a
/// stalled second connection would let that guard fire first and throw the
/// good first sample into a generic timed-out row. `another_sample_fits`
/// already requires the repeat to start inside the first half of the budget,
/// so this clamp leaves the second half as headroom.
fn request_budget(attempt: usize, elapsed: std::time::Duration) -> std::time::Duration {
    let remaining = crate::constants::CHECK_TIMEOUT.saturating_sub(elapsed);
    if attempt == 0 {
        remaining
    } else {
        remaining.min(crate::constants::CHECK_TIMEOUT / 2)
    }
}

/// Measures TTFB by making a fresh request
pub struct TimingCheck;

#[async_trait::async_trait]
impl AsyncCheck for TimingCheck {
    fn id(&self) -> &str {
        "performance.ttfb"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Performance
    }

    /// The scanner runs this check alone, before the concurrent phase, so the
    /// sample measures the origin rather than the scanner's own request burst
    /// competing for the same accept queue. See `core::scanner::SOLO_PHASE_CHECK_IDS`.
    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let mut samples: Vec<u64> = Vec::with_capacity(usize::from(ttfb::TTFB_SAMPLE_COUNT));
        let mut last_error: Option<String> = None;
        let phase_started = std::time::Instant::now();

        for attempt in 0..usize::from(ttfb::TTFB_SAMPLE_COUNT) {
            if !another_sample_fits(attempt, phase_started.elapsed()) {
                break;
            }
            let budget = request_budget(attempt, phase_started.elapsed());
            if budget.is_zero() {
                break;
            }
            let start = std::time::Instant::now();

            // Deliberately the shared, compressing client rather than a raw
            // measurement probe. TTFB is graded against what a visitor's browser
            // would experience, and browsers negotiate gzip and brotli, so timing
            // the same profile is the more browser-realistic number. Enabling
            // compression shifts this value once for origins that compress on the
            // fly; after that it tracks the server, not the client.
            let response = ctx
                .client
                .get(ctx.url.as_str())
                .timeout(budget)
                .send()
                .await;

            // `send` resolves on the response head, so this is time to first
            // byte and not time to read the body.
            match response {
                Ok(_) => samples.push(start.elapsed().as_millis() as u64),
                Err(error) => last_error = Some(error.to_string()),
            }
        }

        match (samples.is_empty(), last_error) {
            (false, _) => ttfb::evaluate_ttfb_samples(&samples, ttfb::HTTP_PROBE_SOURCE),
            (true, Some(error)) => ttfb::ttfb_unavailable(&error),
            (true, None) => ttfb::ttfb_unavailable("no timing sample was taken"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::constants::CHECK_TIMEOUT;
    use std::time::Duration;

    #[test]
    fn id_matches_the_emitted_check_id() {
        assert_eq!(TimingCheck.id(), "performance.ttfb");
        assert_eq!(TimingCheck.id(), ttfb::CHECK_ID);
    }

    #[test]
    fn a_slow_origin_is_graded_from_its_first_sample_instead_of_timing_out() {
        // The scanner wraps the whole check in one CHECK_TIMEOUT. Giving each
        // of two requests that same timeout meant an origin whose real TTFB
        // sits between half and all of the budget blew the outer guard on the
        // second request and reported a generic "timed out" skip, discarding
        // the sample that would have graded Fail.
        assert!(
            another_sample_fits(0, CHECK_TIMEOUT - Duration::from_millis(1)),
            "the first request always runs, however little budget is left"
        );
        assert!(
            !another_sample_fits(1, CHECK_TIMEOUT / 2),
            "a slow first answer must end the loop and grade what it measured"
        );
        assert!(
            another_sample_fits(1, Duration::from_millis(200)),
            "a fast first answer leaves room for the repeat"
        );
    }

    #[test]
    fn the_samples_together_never_outlast_the_checks_own_timeout() {
        for elapsed_ms in [0, 1, 200, 7_000, 7_500, 14_999, 15_000] {
            let elapsed = Duration::from_millis(elapsed_ms);
            assert!(
                elapsed.saturating_add(request_budget(0, elapsed)) <= CHECK_TIMEOUT,
                "the first request must be able to spend the whole budget"
            );
        }
        assert_eq!(request_budget(0, Duration::ZERO), CHECK_TIMEOUT);
        // Past the deadline there is nothing left to spend, and the loop ends.
        assert!(request_budget(0, CHECK_TIMEOUT).is_zero());
        assert!(request_budget(0, CHECK_TIMEOUT * 4).is_zero());
    }

    #[test]
    fn the_repeat_leaves_headroom_against_the_scanners_outer_guard() {
        // The outer timeout starts counting when the future is built, a moment
        // before `run` is polled, so a repeat that could spend the exact
        // remainder would let that guard fire first and discard the first
        // sample. Every start point the loop can reach must leave real margin.
        for elapsed_ms in [0, 1, 200, 3_000, 7_499] {
            let elapsed = Duration::from_millis(elapsed_ms);
            assert!(
                another_sample_fits(1, elapsed),
                "{elapsed:?} is a start point the loop can reach"
            );
            assert!(
                elapsed.saturating_add(request_budget(1, elapsed)) < CHECK_TIMEOUT,
                "a repeat starting at {elapsed:?} must finish strictly inside {CHECK_TIMEOUT:?}"
            );
        }
        assert_eq!(request_budget(1, Duration::ZERO), CHECK_TIMEOUT / 2);
    }
}
