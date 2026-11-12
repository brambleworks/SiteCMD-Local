//! The polish signals that read only the page, one runner each, graded as the
//! CLI grades them: over the page body with no stylesheet text.
//!
//! The signals that read linked stylesheets are probe-lane rows instead.

use std::borrow::Cow;

use super::runners::Runner;
use super::EvaluationInputs;
use crate::checks::polish::{
    ai_aesthetic, copy_content, css_architecture, framework_defaults, html_quality, meta_infra,
    page_leftovers, polish_check_result, PolishContext, PolishResult,
};
use crate::vocab::CheckResult;

/// One signal's row over the route's shared polish context.
fn signal_rows(
    inputs: &EvaluationInputs,
    signal: fn(&PolishContext) -> PolishResult,
) -> Vec<CheckResult> {
    let ctx = inputs.polish.get_or_init(|| {
        PolishContext::new(
            inputs.page.url.clone(),
            Cow::Borrowed(&inputs.page.body),
            Default::default(),
        )
    });
    vec![polish_check_result(&signal(ctx))]
}

/// The page-only polish signals, in `POLISH_SIGNALS` order.
pub const POLISH_RUNNERS: &[Runner] = &[
    Runner {
        covers: &["polish.inline-style-density"],
        run: |inputs| signal_rows(inputs, css_architecture::inline_style_density),
    },
    Runner {
        covers: &["polish.tailwind-class-density"],
        run: |inputs| signal_rows(inputs, css_architecture::tailwind_class_density),
    },
    Runner {
        covers: &["polish.no-css-architecture"],
        run: |inputs| signal_rows(inputs, css_architecture::no_css_architecture),
    },
    Runner {
        covers: &["polish.div-soup-ratio"],
        run: |inputs| signal_rows(inputs, html_quality::div_soup_ratio),
    },
    Runner {
        covers: &["polish.heading-hierarchy"],
        run: |inputs| signal_rows(inputs, html_quality::heading_hierarchy),
    },
    Runner {
        covers: &["polish.form-accessibility"],
        run: |inputs| signal_rows(inputs, html_quality::form_accessibility),
    },
    Runner {
        covers: &["polish.button-vs-clickable-div"],
        run: |inputs| signal_rows(inputs, html_quality::button_vs_clickable_div),
    },
    Runner {
        covers: &["polish.missing-lang"],
        run: |inputs| signal_rows(inputs, html_quality::missing_lang),
    },
    Runner {
        covers: &["polish.dead-social-links"],
        run: |inputs| signal_rows(inputs, page_leftovers::dead_social_links),
    },
    Runner {
        covers: &["polish.em-dash-density"],
        run: |inputs| signal_rows(inputs, copy_content::em_dash_density),
    },
    Runner {
        covers: &["polish.ai-buzzword-dictionary"],
        run: |inputs| signal_rows(inputs, copy_content::ai_buzzword_dictionary),
    },
    Runner {
        covers: &["polish.ai-header-formulas"],
        run: |inputs| signal_rows(inputs, copy_content::ai_header_formulas),
    },
    Runner {
        covers: &["polish.inclusive-framing"],
        run: |inputs| signal_rows(inputs, copy_content::inclusive_framing),
    },
    Runner {
        covers: &["polish.emoji-as-icons"],
        run: |inputs| signal_rows(inputs, copy_content::emoji_as_icons),
    },
    Runner {
        covers: &["polish.three-column-grid"],
        run: |inputs| signal_rows(inputs, copy_content::three_column_grid),
    },
    Runner {
        covers: &["polish.placeholder-text"],
        run: |inputs| signal_rows(inputs, page_leftovers::placeholder_text),
    },
    Runner {
        covers: &["polish.scroll-animations"],
        run: |inputs| signal_rows(inputs, ai_aesthetic::scroll_animations),
    },
    Runner {
        covers: &["polish.eyebrow-labels"],
        run: |inputs| signal_rows(inputs, ai_aesthetic::eyebrow_labels),
    },
    Runner {
        covers: &["polish.default-page-title"],
        run: |inputs| signal_rows(inputs, meta_infra::default_page_title),
    },
    Runner {
        covers: &["polish.missing-og-tags"],
        run: |inputs| signal_rows(inputs, meta_infra::missing_og_tags),
    },
    Runner {
        covers: &["polish.default-favicon"],
        run: |inputs| signal_rows(inputs, meta_infra::default_favicon),
    },
    Runner {
        covers: &["polish.no-sitemap-robots"],
        run: |inputs| signal_rows(inputs, meta_infra::no_sitemap_robots),
    },
    Runner {
        covers: &["polish.source-maps-production"],
        run: |inputs| signal_rows(inputs, meta_infra::source_maps_production),
    },
    Runner {
        covers: &["polish.console-log-production"],
        run: |inputs| signal_rows(inputs, meta_infra::console_log_production),
    },
    Runner {
        covers: &["polish.default-deployment-subdomain"],
        run: |inputs| signal_rows(inputs, framework_defaults::default_deployment_subdomain),
    },
    Runner {
        covers: &["polish.boilerplate-html"],
        run: |inputs| signal_rows(inputs, framework_defaults::boilerplate_html),
    },
    Runner {
        covers: &["polish.default-error-page"],
        run: |inputs| signal_rows(inputs, framework_defaults::default_error_page),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation::PageArtifact;
    use crate::header_lines::HeaderLines;

    // The hosted polish context copies the page body instead of borrowing it.
    #[test]
    fn a_polish_runner_reads_the_page_body_in_place() {
        let page = PageArtifact {
            url: "https://example.com/".into(),
            requested_url: None,
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: Vec::new(),
            body: "<html><body><p>Hello</p></body></html>".into(),
            evaluation_time: "2026-10-30T00:00:00Z".parse().expect("static time"),
        }
        .page_context()
        .expect("page parses");
        let inputs = EvaluationInputs {
            page: &page,
            tls_facts: None,
            negotiated_protocol: None,
            browser_facts: None,
            header_lines: HeaderLines::default(),
            polish: std::sync::OnceLock::new(),
        };
        (POLISH_RUNNERS[0].run)(&inputs);
        let ctx = inputs.polish.get().expect("the runner built the context");
        assert_eq!(ctx.html.as_ptr(), inputs.page.body.as_ptr());
    }
}
