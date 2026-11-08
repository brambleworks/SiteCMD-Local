//! Finding titles for polish signals.
//! Copy states observations without judging intent; a repo guardrail enforces the vocabulary.

/// Finding-style title shown when the signal fires. Returns `None` for
/// unknown ids; callers fall back to the signal name.
pub fn polish_signal_fail_title(signal_id: &str) -> Option<&'static str> {
    Some(match signal_id {
        "placeholder-text" => "Placeholder copy left on the page",
        "dead-social-links" => "Social links that go to no profile",
        "eyebrow-labels" => "Short labels stacked above headings",
        // CSS architecture
        "inline-style-density" => "High inline-style density",
        "tailwind-class-density" => "High utility-class density",
        // Detection sees CSS delivery (stylesheets, CSS-in-JS, modules,
        // style blocks), not naming conventions - the title must not claim
        // more.
        "no-css-architecture" => "No custom CSS detected",

        // HTML quality
        "div-soup-ratio" => "Low semantic-element ratio",
        "heading-hierarchy" => "Heading structure needs review",
        "form-accessibility" => "Form inputs missing labels",
        // Detection counts ANY non-interactive element with a click handler
        // (spans, images, list items), not only divs.
        "button-vs-clickable-div" => "Click handlers on non-interactive elements",
        "missing-lang" => "Missing lang attribute on html element",

        // Copy and content
        "em-dash-density" => "High em-dash density in copy",
        "ai-buzzword-dictionary" => "High marketing buzzword density",
        "ai-header-formulas" => "Formulaic heading patterns",
        "inclusive-framing" => "Repeated audience-framing phrases",
        "emoji-as-icons" => "Emoji used as interface icons",
        "three-column-grid" => "Three-column feature grid pattern",

        // Aesthetic signals
        "gradient-backgrounds" => "Gradient-dominant background styling",
        "glassmorphism" => "Heavy backdrop-blur styling",
        "scroll-animations" => "Scroll-triggered animations throughout",
        "excessive-border-radius" => "Uniformly large border radius",
        "glow-shadows" => "Colored glow shadows detected",
        // Two of the three blob signals need no blur evidence, so the
        // title cannot claim blur.
        "gradient-text" => "Gradient fill clipped to text",
        "floating-blobs" => "Blob-style decorative elements detected",

        // Meta and infrastructure
        // Also fires for a missing or empty <title>, so the headline must
        // cover more than the framework-default case.
        "default-page-title" => "Default or missing page title",
        "missing-og-tags" => "Missing Open Graph tags",
        "default-favicon" => "Framework default favicon",
        // Detection reads page markup only (canonical link, robots meta,
        // sitemap link); robots.txt itself is never probed.
        "no-sitemap-robots" => "No page-level SEO markers found",
        // Only the sourceMappingURL comment is observed; the `.map` file is
        // never fetched, so "exposed" would overclaim.
        "source-maps-production" => "Source map references in production JS",
        "console-log-production" => "Console logging left in production",

        // Framework defaults
        "default-deployment-subdomain" => "Hosting on default platform subdomain",
        "boilerplate-html" => "Default scaffold markup detected",
        "default-error-page" => "Framework default error page",

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::polish::{run_all_signals, PolishContext};

    fn minimal_ctx() -> PolishContext<'static> {
        PolishContext::new(
            url::Url::parse("https://example.com/").expect("static url"),
            "<!doctype html><html><head><title>t</title></head><body></body></html>".into(),
            Default::default(),
        )
    }

    /// Every signal the engine can emit must have a fired-state title, so a
    /// new signal cannot ship with a subject-style headline by accident.
    #[test]
    fn every_polish_signal_has_a_fail_title() {
        let missing: Vec<String> = run_all_signals(&minimal_ctx())
            .into_iter()
            .filter(|signal| polish_signal_fail_title(&signal.id).is_none())
            .map(|signal| signal.id)
            .collect();

        assert!(
            missing.is_empty(),
            "polish signals missing fired-state titles: {missing:?}"
        );
    }

    /// Titles are fix-prompt headers; keep them headline-sized.
    #[test]
    fn fail_titles_stay_headline_sized() {
        for signal in run_all_signals(&minimal_ctx()) {
            if let Some(title) = polish_signal_fail_title(&signal.id) {
                assert!(
                    title.len() <= 60,
                    "fail title for {} exceeds 60 chars: {title}",
                    signal.id
                );
            }
        }
    }

    #[test]
    fn heading_title_covers_h1_count_and_level_review_without_claiming_a_violation() {
        let title = polish_signal_fail_title("heading-hierarchy").expect("heading title");
        assert_eq!(title, "Heading structure needs review");
    }
}
