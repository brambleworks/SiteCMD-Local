//! Heuristic HTML and CSS polish signals grouped into six categories.
//!
//! Results describe review signals, not authorship or the tool that built a page.

pub mod ai_aesthetic;
mod check_result;
pub mod copy_content;
pub mod css_architecture;
pub mod css_counts;
mod css_grade;
pub mod framework_defaults;
pub mod gradient_hues;
pub mod guidance;
pub mod html_quality;
mod markup;
pub mod meta_infra;
pub mod page_leftovers;
pub mod titles;
pub mod types;
pub mod word_lists;

pub use check_result::{polish_check_result, polish_signal_confidence};
pub use css_counts::{
    css_signal_counts, extract_stylesheet_urls, stylesheet_request, CssSignalCounts, CssTextKind,
    STYLESHEET_SAMPLE_LIMIT,
};
pub use css_grade::{grade_stylesheet_coverage, grade_stylesheet_signals};
pub use types::*;

use std::borrow::Cow;

/// Context passed to each polish signal: the fetched page and its stylesheets,
/// owned or borrowed from the caller's page.
pub struct PolishContext<'a> {
    /// The page URL
    pub url: url::Url,
    /// Raw HTML body
    pub html: Cow<'a, str>,
    stylesheet_counts: CssSignalCounts,
    css_counts_cache: std::sync::OnceLock<CssSignalCounts>,
    /// Cached lowercase HTML. Avoids re-lowercasing the same body for every
    /// signal. Use `html_lower` to read, never touch directly.
    #[doc(hidden)]
    pub html_lower_cache: std::sync::OnceLock<String>,
}

impl<'a> PolishContext<'a> {
    /// Borrow or own the page without counting it until a stylesheet signal runs.
    pub fn new(url: url::Url, html: Cow<'a, str>, stylesheet_counts: CssSignalCounts) -> Self {
        Self {
            url,
            html,
            stylesheet_counts,
            css_counts_cache: std::sync::OnceLock::new(),
            html_lower_cache: std::sync::OnceLock::new(),
        }
    }

    /// Count page markup once, then combine it with the independently counted stylesheets.
    pub fn css_counts(&self) -> &CssSignalCounts {
        self.css_counts_cache.get_or_init(|| {
            css_signal_counts(&self.html, CssTextKind::Page) + self.stylesheet_counts
        })
    }

    /// Lowercased HTML, computed lazily on first call and cached.
    pub fn html_lower(&self) -> &str {
        self.html_lower_cache
            .get_or_init(|| self.html.to_lowercase())
    }
}

/// One polish signal and the function that grades it.
pub struct PolishSignal {
    /// The signal id; its check id is `polish.<id>`.
    pub id: &'static str,
    pub category: SignalCategory,
    /// The weight the signal publishes; a fired result may carry a lower one.
    pub weight: SignalWeight,
    /// Whether the verdict reads the linked stylesheets as well as the page.
    pub reads_stylesheets: bool,
    pub run: fn(&PolishContext) -> PolishResult,
}

/// Every polish signal, in the order their results are reported.
pub const POLISH_SIGNALS: &[PolishSignal] = &[
    PolishSignal {
        id: "inline-style-density",
        category: SignalCategory::CssArchitecture,
        weight: SignalWeight::High,
        reads_stylesheets: false,
        run: css_architecture::inline_style_density,
    },
    PolishSignal {
        id: "tailwind-class-density",
        category: SignalCategory::CssArchitecture,
        weight: SignalWeight::High,
        reads_stylesheets: false,
        run: css_architecture::tailwind_class_density,
    },
    PolishSignal {
        id: "no-css-architecture",
        category: SignalCategory::CssArchitecture,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: css_architecture::no_css_architecture,
    },
    PolishSignal {
        id: "div-soup-ratio",
        category: SignalCategory::HtmlQuality,
        weight: SignalWeight::High,
        reads_stylesheets: false,
        run: html_quality::div_soup_ratio,
    },
    PolishSignal {
        id: "heading-hierarchy",
        category: SignalCategory::HtmlQuality,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: html_quality::heading_hierarchy,
    },
    PolishSignal {
        id: "form-accessibility",
        category: SignalCategory::HtmlQuality,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: html_quality::form_accessibility,
    },
    PolishSignal {
        id: "button-vs-clickable-div",
        category: SignalCategory::HtmlQuality,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: html_quality::button_vs_clickable_div,
    },
    PolishSignal {
        id: "missing-lang",
        category: SignalCategory::HtmlQuality,
        weight: SignalWeight::Low,
        reads_stylesheets: false,
        run: html_quality::missing_lang,
    },
    PolishSignal {
        id: "dead-social-links",
        category: SignalCategory::HtmlQuality,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: page_leftovers::dead_social_links,
    },
    PolishSignal {
        id: "em-dash-density",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::High,
        reads_stylesheets: false,
        run: copy_content::em_dash_density,
    },
    PolishSignal {
        id: "ai-buzzword-dictionary",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::High,
        reads_stylesheets: false,
        run: copy_content::ai_buzzword_dictionary,
    },
    PolishSignal {
        id: "ai-header-formulas",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: copy_content::ai_header_formulas,
    },
    PolishSignal {
        id: "inclusive-framing",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: copy_content::inclusive_framing,
    },
    PolishSignal {
        id: "emoji-as-icons",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: copy_content::emoji_as_icons,
    },
    PolishSignal {
        id: "three-column-grid",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::LowMedium,
        reads_stylesheets: false,
        run: copy_content::three_column_grid,
    },
    PolishSignal {
        id: "placeholder-text",
        category: SignalCategory::CopyContent,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: page_leftovers::placeholder_text,
    },
    PolishSignal {
        id: "gradient-backgrounds",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Medium,
        reads_stylesheets: true,
        run: ai_aesthetic::gradient_backgrounds,
    },
    PolishSignal {
        id: "glassmorphism",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::LowMedium,
        reads_stylesheets: true,
        run: ai_aesthetic::glassmorphism,
    },
    PolishSignal {
        id: "scroll-animations",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: ai_aesthetic::scroll_animations,
    },
    PolishSignal {
        id: "excessive-border-radius",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Low,
        reads_stylesheets: true,
        run: ai_aesthetic::excessive_border_radius,
    },
    PolishSignal {
        id: "glow-shadows",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Low,
        reads_stylesheets: true,
        run: ai_aesthetic::glow_shadows,
    },
    PolishSignal {
        id: "floating-blobs",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Medium,
        reads_stylesheets: true,
        run: ai_aesthetic::floating_blobs,
    },
    PolishSignal {
        id: "gradient-text",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Medium,
        reads_stylesheets: true,
        run: ai_aesthetic::gradient_text,
    },
    PolishSignal {
        id: "eyebrow-labels",
        category: SignalCategory::AiAesthetic,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: ai_aesthetic::eyebrow_labels,
    },
    PolishSignal {
        id: "default-page-title",
        category: SignalCategory::MetaInfrastructure,
        weight: SignalWeight::High,
        reads_stylesheets: false,
        run: meta_infra::default_page_title,
    },
    PolishSignal {
        id: "missing-og-tags",
        category: SignalCategory::MetaInfrastructure,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: meta_infra::missing_og_tags,
    },
    PolishSignal {
        id: "default-favicon",
        category: SignalCategory::MetaInfrastructure,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: meta_infra::default_favicon,
    },
    PolishSignal {
        id: "no-sitemap-robots",
        category: SignalCategory::MetaInfrastructure,
        weight: SignalWeight::Low,
        reads_stylesheets: false,
        run: meta_infra::no_sitemap_robots,
    },
    PolishSignal {
        id: "source-maps-production",
        category: SignalCategory::MetaInfrastructure,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: meta_infra::source_maps_production,
    },
    PolishSignal {
        id: "console-log-production",
        category: SignalCategory::MetaInfrastructure,
        weight: SignalWeight::Medium,
        reads_stylesheets: false,
        run: meta_infra::console_log_production,
    },
    PolishSignal {
        id: "default-deployment-subdomain",
        category: SignalCategory::FrameworkDefaults,
        weight: SignalWeight::LowMedium,
        reads_stylesheets: false,
        run: framework_defaults::default_deployment_subdomain,
    },
    PolishSignal {
        id: "boilerplate-html",
        category: SignalCategory::FrameworkDefaults,
        weight: SignalWeight::Low,
        reads_stylesheets: false,
        run: framework_defaults::boilerplate_html,
    },
    PolishSignal {
        id: "default-error-page",
        category: SignalCategory::FrameworkDefaults,
        weight: SignalWeight::Low,
        reads_stylesheets: false,
        run: framework_defaults::default_error_page,
    },
];

/// Run all deterministic polish signals.
pub fn run_all_signals(ctx: &PolishContext) -> Vec<PolishResult> {
    POLISH_SIGNALS
        .iter()
        .map(|signal| (signal.run)(ctx))
        .collect()
}

/// Grade only signals whose scope is this page, without reading linked stylesheets.
pub fn run_page_signals(ctx: &PolishContext) -> Vec<PolishResult> {
    POLISH_SIGNALS
        .iter()
        .filter(|signal| !signal.reads_stylesheets)
        .map(|signal| (signal.run)(ctx))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_ctx() -> PolishContext<'static> {
        PolishContext::new(
            url::Url::parse("https://example.com").unwrap(),
            "<html><head><title>Test</title></head><body><p>Hello</p></body></html>".into(),
            Default::default(),
        )
    }

    // A row names another signal's function or misstates its id, category or
    // weight, which the published signal manifest is built from.
    #[test]
    fn each_signal_reports_the_id_category_and_weight_its_row_declares() {
        let results = run_all_signals(&fixture_ctx());
        assert_eq!(results.len(), POLISH_SIGNALS.len());
        for (signal, result) in POLISH_SIGNALS.iter().zip(results) {
            assert_eq!(result.id, signal.id);
            assert_eq!(result.category, signal.category, "{}", signal.id);
            assert_eq!(result.weight, signal.weight, "{}", signal.id);
        }
    }

    // Two rows share an id, so one signal would be reported twice.
    #[test]
    fn signal_ids_are_unique() {
        let mut ids: Vec<&str> = POLISH_SIGNALS.iter().map(|signal| signal.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), POLISH_SIGNALS.len());
    }
}
