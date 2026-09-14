//! Heuristic HTML and CSS polish signals grouped into six categories.
//!
//! Results describe review signals, not authorship or the tool that built a page.

pub mod ai_aesthetic;
pub mod copy_content;
pub mod css_architecture;
pub mod css_fetch;
pub mod framework_defaults;
pub mod guidance;
pub mod html_quality;
pub mod meta_infra;
pub mod stylesheet_cache;
pub mod titles;
pub mod types;

pub use stylesheet_cache::StylesheetCache;
pub use types::*;

/// Context passed to each polish signal - the fetched page data + CSS content.
pub struct PolishContext {
    /// The page URL
    pub url: url::Url,
    /// Raw HTML body
    pub html: String,
    /// Concatenated CSS from the linked stylesheets that were fetched, up to
    /// `css_fetch::MAX_CSS_FILES` of them (empty if none were fetched)
    pub css: String,
    /// Cached lowercase HTML. Avoids re-lowercasing the same body for every
    /// signal. Use `html_lower` to read, never touch directly.
    #[doc(hidden)]
    pub html_lower_cache: std::sync::OnceLock<String>,
}

impl PolishContext {
    /// Lowercased HTML, computed lazily on first call and cached.
    pub fn html_lower(&self) -> &str {
        self.html_lower_cache
            .get_or_init(|| self.html.to_lowercase())
    }
}

/// Run all deterministic polish signals.
pub fn run_all_signals(ctx: &PolishContext) -> Vec<PolishResult> {
    vec![
        // Category 1: CSS Architecture
        css_architecture::inline_style_density(ctx),
        css_architecture::tailwind_class_density(ctx),
        css_architecture::no_css_architecture(ctx),
        css_architecture::utility_to_custom_ratio(ctx),
        // Category 2: HTML Quality
        html_quality::div_soup_ratio(ctx),
        html_quality::heading_hierarchy(ctx),
        html_quality::form_accessibility(ctx),
        html_quality::button_vs_clickable_div(ctx),
        html_quality::missing_lang(ctx),
        // Category 4: Copy & Content
        copy_content::em_dash_density(ctx),
        copy_content::ai_buzzword_dictionary(ctx),
        copy_content::ai_header_formulas(ctx),
        copy_content::inclusive_framing(ctx),
        copy_content::emoji_as_icons(ctx),
        copy_content::three_column_grid(ctx),
        // Category 3: AI Aesthetic Design Patterns
        ai_aesthetic::gradient_backgrounds(ctx),
        ai_aesthetic::glassmorphism(ctx),
        ai_aesthetic::scroll_animations(ctx),
        ai_aesthetic::excessive_border_radius(ctx),
        ai_aesthetic::glow_shadows(ctx),
        ai_aesthetic::floating_blobs(ctx),
        // Category 5: Meta & Infrastructure
        meta_infra::default_page_title(ctx),
        meta_infra::missing_og_tags(ctx),
        meta_infra::default_favicon(ctx),
        meta_infra::no_sitemap_robots(ctx),
        meta_infra::source_maps_production(ctx),
        meta_infra::console_log_production(ctx),
        // Category 6: Framework Defaults
        framework_defaults::default_deployment_subdomain(ctx),
        framework_defaults::boilerplate_html(ctx),
        framework_defaults::default_error_page(ctx),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_ctx() -> PolishContext {
        PolishContext {
            url: url::Url::parse("https://example.com").unwrap(),
            html: "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
                .to_string(),
            css: String::new(),
            html_lower_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn run_all_signals_returns_30() {
        let results = run_all_signals(&fixture_ctx());
        assert_eq!(
            results.len(),
            30,
            "Expected 30 signals, got {}",
            results.len()
        );
    }

    /// Keep the generated public-scanner signal manifest in sync.
    #[test]
    fn signal_manifest_is_in_sync_with_the_generated_copy() {
        let signals: Vec<serde_json::Value> = run_all_signals(&fixture_ctx())
            .iter()
            .map(|r| serde_json::json!({ "id": r.id, "weight": r.weight, "category": r.category }))
            .collect();
        let manifest = serde_json::json!({
            "_generated": "checks::polish::tests::signal_manifest_is_in_sync_with_the_generated_copy \
                           (apps/desktop/src-tauri). Do not edit by hand: change checks/polish/, \
                           run cargo test, commit the diff.",
            "signals": signals,
        });
        let expected =
            serde_json::to_string_pretty(&manifest).expect("serialize signal manifest") + "\n";

        let json_path = std::path::PathBuf::from(env!("SITECMD_SOURCE_ROOT"))
            .parent()
            .expect("desktop app root")
            .join("src")
            .join("generated")
            .join("polish_signal_manifest.json");

        let actual = std::fs::read_to_string(&json_path).unwrap_or_default();
        if actual != expected {
            std::fs::write(&json_path, &expected).expect("write polish_signal_manifest.json");
            panic!(
                "apps/desktop/src/generated/polish_signal_manifest.json was stale (rewrote it). \
                 Review with `git diff apps/desktop/src/generated/polish_signal_manifest.json`, \
                 re-run `pnpm facts:generate`, and re-run."
            );
        }
    }
}
