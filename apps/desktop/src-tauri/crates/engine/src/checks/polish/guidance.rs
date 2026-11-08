//! User-facing rationale and remediation for Polish signals.

#[derive(Clone, Copy)]
pub struct PolishGuidance {
    pub why_it_matters: &'static str,
    pub fix: &'static str,
}

pub fn polish_signal_guidance(signal_id: &str) -> Option<PolishGuidance> {
    let (why_it_matters, fix) = match signal_id {
        "placeholder-text" => (
            "Sample text, sample addresses and placeholder images make a page look unfinished to the people who read it.",
            "Replace each placeholder with the real text, address or image, or remove it.",
        ),
        "dead-social-links" => (
            "Visitors who click a social icon expect your profile. A link that goes nowhere, or to the platform's home page, leaves them without it.",
            "Point each social link at your profile's full address, or remove the icon for a platform where you have no profile.",
        ),
        "eyebrow-labels" => (
            "Each short label above a heading adds a line to read before the section, and one that repeats its heading adds nothing.",
            "Keep a label only where it tells readers something the heading does not, and remove the rest.",
        ),
        "inline-style-density" => (
            "A high concentration of static inline declarations can duplicate design decisions, make global changes harder, and conflict with a strict Content Security Policy. Dynamic styles and CMS output can be legitimate.",
            "Review the detected elements, keep genuinely dynamic values inline, and move repeated static declarations into shared classes, components, or design tokens.",
        ),
        "tailwind-class-density" => (
            "Utility-first CSS is valid, but consistently long class lists can hide repeated component patterns and make visual changes harder to review.",
            "Keep one-off utility composition where it is clear. Extract only repeated or difficult-to-read combinations into reusable components or named component classes.",
        ),
        "no-css-architecture" => (
            "The rendered page showed no stylesheet, style block, or recognized CSS-in-JS marker. That can indicate an unstyled scaffold, but inaccessible cross-origin CSS or an unfamiliar runtime can also explain it.",
            "First verify that styles loaded successfully in the browser. If the page is truly relying on ad hoc markup or inline declarations, establish a documented styling approach and reusable primitives.",
        ),
        "div-soup-ratio" => (
            "Semantic landmarks and content elements give browsers and assistive technology a clearer page outline. A high div ratio is only a proxy because many divs are valid layout containers.",
            "Replace containers only when their purpose is genuinely navigation, main content, an article, a section, an aside, header, or footer, and remove wrapper elements that serve no layout or behavior purpose.",
        ),
        "heading-hierarchy" => (
            "Headings form the document outline used by screen-reader navigation and by readers scanning the page. Missing, repeated, or skipped levels can make that structure unclear.",
            "Make heading levels follow the content hierarchy, not visual size. Keep a page-level h1 where appropriate and style non-heading display text with CSS.",
        ),
        "form-accessibility" => (
            "Controls without an accessible name are difficult or impossible to identify with a screen reader, voice control, or a larger click target.",
            "Give each affected control a visible associated label where possible. A wrapping label, for/id pair, or an accurate aria-label or aria-labelledby relationship can provide the accessible name.",
        ),
        "button-vs-clickable-div" => (
            "Non-interactive elements with click handlers do not automatically provide keyboard activation, focus behavior, or the role assistive technology expects.",
            "Use a button for actions and a link with href for navigation. If a custom interactive element is unavoidable, implement its role, focusability, keyboard behavior, and disabled state deliberately.",
        ),
        "missing-lang" => (
            "The document language helps screen readers choose pronunciation rules and helps browsers offer correct translation and language services.",
            "Set the html element's lang attribute to the page's primary BCP 47 language tag, and mark passages that switch language when needed.",
        ),
        "em-dash-density" => (
            "Repeated em dashes can make copy feel mechanically paced or harder to scan, but punctuation style is editorial and is not evidence that text was AI-generated.",
            "Read the surfaced passages in context. Keep intentional punctuation and revise only sentences where a period, comma, colon, or simpler construction improves the brand voice.",
        ),
        "ai-buzzword-dictionary" => (
            "A dense cluster of generic marketing terms can obscure the concrete outcome a customer receives. Individual matched words may still be accurate and on-brand.",
            "Review each matched phrase in context and replace vague claims with specific capabilities, constraints, examples, or measurable outcomes. Keep terms that have a precise product meaning.",
        ),
        "ai-header-formulas" => (
            "Repeated headline formulas can make unrelated products sound interchangeable, but a matched heading can be effective when it accurately describes the section.",
            "Compare your headings with the matched formulas. Rewrite only generic examples so they state the audience, action, or outcome in language specific to this product.",
        ),
        "inclusive-framing" => (
            "Repeated audience-enumeration phrases can dilute positioning by addressing everyone at once. The phrasing may still be appropriate when distinct audiences truly share the same need.",
            "Name the primary customer directly, or give materially different audiences their own section. Keep the framing when the enumerated groups and shared outcome are both specific.",
        ),
        "emoji-as-icons" => (
            "Emoji appearance and meaning vary by platform, and a decorative character may not expose the accessible name or consistent visual language expected of a control.",
            "For functional controls, use a consistent SVG icon with an accessible name. Keep emoji that are deliberate content or brand expression rather than unlabeled interface controls.",
        ),
        "three-column-grid" => (
            "A uniform three-column feature grid is common and can flatten the hierarchy between primary and secondary benefits. It is also a legitimate layout for three comparable items.",
            "Keep the grid if the content is truly parallel. Otherwise use size, ordering, media, or an asymmetric layout to express which benefit matters most instead of changing it only to appear different.",
        ),
        "gradient-backgrounds" => (
            "Many gradients that blend several hues can compete with content and make a visual system feel inconsistent, but gradients are a subjective brand choice rather than a quality defect.",
            "Review the detected multi-color gradients for contrast, consistency, and purpose. Consolidate arbitrary variants into design tokens and keep intentional brand treatments.",
        ),
        "glassmorphism" => (
            "Repeated translucent, blurred surfaces can reduce text contrast and visual hierarchy. A limited glass treatment may still be an intentional part of the brand.",
            "Verify text and control contrast over every background, provide a solid reduced-transparency fallback where needed, and remove blur only where it does not support hierarchy or brand intent.",
        ),
        "scroll-animations" => (
            "Content that waits for scroll-triggered animation can be distracting, delay access to information, and create motion barriers. Purposeful motion can still explain change or hierarchy.",
            "Keep essential content visible without animation, limit decorative reveals, and honor prefers-reduced-motion with an equivalent non-animated experience.",
        ),
        "excessive-border-radius" => (
            "Using the same large radius everywhere can weaken component hierarchy, but radius scale is a subjective design-system choice.",
            "Review the detected values against the product's design tokens. Use a small, intentional scale and reserve pill or circular shapes for components whose form supports that treatment.",
        ),
        "glow-shadows" => (
            "Frequent colored glows can reduce edge clarity and compete with focus indicators. A restrained glow may still be a deliberate brand or state treatment.",
            "Check contrast and state clarity, consolidate shadows into design tokens, and keep colored glows only where they communicate focus, status, or intentional brand emphasis.",
        ),
        "gradient-text" => (
            "Text filled with a gradient changes color across its letters, so part of it can fall below readable contrast against the background.",
            "Check the text's contrast where its gradient is lightest and darkest, and use one solid color wherever part of it is hard to read.",
        ),
        "floating-blobs" => (
            "Large decorative shapes can add visual noise, overlap content at responsive sizes, or consume animation and paint work. They are not inherently unprofessional.",
            "Test the detected decoration across breakpoints, reduced-motion settings, and contrast modes. Keep it when it supports the brand without obscuring content or interaction.",
        ),
        "default-page-title" => (
            "The page title identifies the tab, browser history entry, bookmark, and search result. A missing or placeholder title makes navigation and discovery less clear.",
            "Set a concise, page-specific title that names the content and product. Apply a shared title template without making every route identical.",
        ),
        "missing-og-tags" => (
            "Open Graph metadata influences how social, chat, and link-preview clients present a URL. Missing fields can produce an incomplete or misleading preview.",
            "Add page-specific og:title, og:description, og:url, and a crawlable representative og:image, then verify the rendered production URL in the preview tools used by your audience.",
        ),
        "default-favicon" => (
            "A framework favicon can make the browser tab look unfinished or indistinguishable from other sites, but this signal is pattern-based and should be visually confirmed.",
            "Open the detected icon, verify that it is still framework artwork, and replace it with an accessible brand mark in the favicon formats and sizes your supported browsers need.",
        ),
        "no-sitemap-robots" => (
            "The page markup contains none of the page-level SEO markers this signal checks: a canonical link, robots meta directive, or sitemap link. It does not test whether robots.txt or sitemap.xml exist.",
            "Add an accurate canonical URL where duplicate URL variants are possible and a robots directive only when the page needs one. Let the dedicated robots.txt and sitemap checks determine whether those files need work.",
        ),
        "source-maps-production" => (
            "A sourceMappingURL reference reveals where a source map may live, but it does not prove the map is publicly accessible. Public maps can expose readable source and internal paths.",
            "Request the referenced map first. If it is public unintentionally, stop serving it; if error monitoring needs maps, upload private or hidden maps to that service and verify the public URL no longer returns the file.",
        ),
        "console-log-production" => (
            "Console calls left in shipped JavaScript can expose debugging context and create noise for users and support staff. A matched string does not prove every call executes in production.",
            "Inspect the surfaced bundle location, remove sensitive or obsolete logging, and route operational errors through structured monitoring. Keep deliberate diagnostics only when they are safe and useful.",
        ),
        "default-deployment-subdomain" => (
            "A platform subdomain is technically valid, but a custom production domain usually improves brand recognition, link trust, and control over canonical URLs.",
            "If this is the public production site, connect and verify the intended custom domain, redirect the platform hostname to it, and update canonical and social metadata. Keep platform URLs for previews when appropriate.",
        ),
        "boilerplate-html" => (
            "Recognized starter-template markers can indicate unfinished copy or branding, but frameworks sometimes retain harmless marker text after customization.",
            "Inspect each surfaced marker in the rendered page and source. Replace visitor-visible starter content and default assets, while leaving legitimate framework plumbing untouched.",
        ),
        "default-error-page" => (
            "A framework error page can strand visitors without product navigation or a recovery path and may expose implementation details.",
            "Create branded 404 and server-error states with a safe message, navigation, retry or support path, and no stack traces. Verify both an unknown route and a controlled server failure.",
        ),
        _ => return None,
    };

    Some(PolishGuidance {
        why_it_matters,
        fix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::polish::{run_all_signals, PolishContext};

    #[test]
    fn every_polish_signal_has_user_guidance() {
        let context = PolishContext::new(
            url::Url::parse("https://example.com").expect("static URL"),
            "<html lang=\"en\"><head><title>Example</title></head><body></body></html>".into(),
            Default::default(),
        );
        let missing = run_all_signals(&context)
            .into_iter()
            .filter(|signal| polish_signal_guidance(&signal.id).is_none())
            .map(|signal| signal.id)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "signals missing guidance: {missing:?}");
    }
}
