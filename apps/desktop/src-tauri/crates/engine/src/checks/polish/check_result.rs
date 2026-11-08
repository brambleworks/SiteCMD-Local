//! A polish signal's result as a check result, with its title, guidance and
//! confidence: the one conversion every runtime reports polish through.

use super::{guidance, titles, PolishResult, SignalWeight};
use crate::vocab::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

/// Convert a PolishResult to a CheckResult for unified storage.
pub fn polish_check_result(r: &PolishResult) -> CheckResult {
    // Preserve branch-specific signal severity unless policy overrides it.
    let (status, severity) = if r.fired {
        let weight_severity = match r.weight {
            SignalWeight::High => Severity::High,
            SignalWeight::Medium => Severity::Medium,
            SignalWeight::LowMedium | SignalWeight::Low => Severity::Low,
        };
        (CheckStatus::Fail, weight_severity)
    } else {
        (CheckStatus::Pass, Severity::Low)
    };

    // Polish signals are heuristics; grade confidence per-signal so the UI
    // (and the SiteCMD scoring) can deprioritize subjective aesthetic
    // matches relative to direct structural facts.
    let (confidence, confidence_reason) = polish_signal_confidence(&r.id);

    // Fired signals get a finding-style headline; the signal name stays the
    // identity for passing results.
    let title = if r.fired {
        titles::polish_signal_fail_title(&r.id)
            .map(str::to_string)
            .unwrap_or_else(|| r.name.clone())
    } else {
        r.name.clone()
    };
    let guidance = if r.fired {
        guidance::polish_signal_guidance(&r.id)
    } else {
        None
    };

    CheckResult {
        check_id: format!("polish.{}", r.id),
        category: ScanCategory::Polish,
        title,
        description: r.detail.clone(),
        status,
        severity,
        fix_prompt: guidance.map(|entry| entry.fix.to_string()),
        manual_fix: guidance.map(|entry| entry.fix.to_string()),
        raw_data: Some(r.data.clone()),
        confidence,
        confidence_reason: confidence_reason.map(|s| s.to_string()),
        why_it_matters: guidance.map(|entry| entry.why_it_matters.to_string()),
    }
}

/// Confirms structural facts and marks subjective Polish signals for review.
pub fn polish_signal_confidence(check_id: &str) -> (IssueConfidence, Option<&'static str>) {
    use IssueConfidence::{Confirmed, NeedsReview};
    let signal_id = check_id.strip_prefix("polish.").unwrap_or(check_id);
    match signal_id {
        "placeholder-text" => (NeedsReview, Some("A text pattern match; confirm each placeholder on the page before you change it.")),
        "dead-social-links" => (NeedsReview, Some("A link pattern match; a script can change where a link goes, so click each one before you change it.")),
        "missing-lang" | "missing-og-tags" => (Confirmed, None),
        // Create-React-App and similar templates ship the boilerplate markers
        // this signal matches even on finished production sites.
        "boilerplate-html" => (
            NeedsReview,
            Some("Framework boilerplate markers persist on many finished production sites; verify the page is actually unfinished."),
        ),
        "glassmorphism"
        | "gradient-backgrounds"
        | "gradient-text"
        | "scroll-animations"
        | "excessive-border-radius"
        | "glow-shadows"
        | "floating-blobs"
        | "three-column-grid"
        | "emoji-as-icons"
        | "eyebrow-labels" => (
            NeedsReview,
            Some("Subjective aesthetic signal; legitimate modern designs often match."),
        ),
        "em-dash-density"
        | "source-maps-production"
        | "default-page-title"
        | "ai-buzzword-dictionary"
        | "ai-header-formulas"
        | "inclusive-framing"
        | "default-favicon"
        | "default-error-page"
        | "default-deployment-subdomain" => (
            NeedsReview,
            Some("Heuristic pattern; verify against the surfaced evidence before acting."),
        ),
        "inline-style-density"
        | "tailwind-class-density"
        | "no-css-architecture"
        | "div-soup-ratio"
        | "heading-hierarchy"
        | "form-accessibility"
        | "button-vs-clickable-div" => (
            NeedsReview,
            Some("Structural heuristic; may misread modern utility-first patterns."),
        ),
        _ => (
            NeedsReview,
            Some("Heuristic pattern; review the evidence before acting."),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polish_direct_facts_and_subjective_signals_stay_distinct() {
        assert_eq!(
            polish_signal_confidence("polish.missing-lang").0,
            IssueConfidence::Confirmed
        );
        assert_eq!(
            polish_signal_confidence("polish.gradient-backgrounds").0,
            IssueConfidence::NeedsReview
        );
    }
}
