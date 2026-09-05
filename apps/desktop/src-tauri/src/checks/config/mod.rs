//! Configuration checks: favicon, error pages, security.txt, robots.txt format.

pub mod basics;
pub use sitecmd_engine::checks::config::deprecated_html;
pub mod extras;
pub mod web_manifest;

use super::{AsyncCheck, Check};

pub fn sync_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(basics::AnalyticsCheck),
        Box::new(deprecated_html::DeprecatedHtmlCheck),
        Box::new(extras::PrintStylesheetCheck),
        Box::new(extras::ResponsiveDesignCheck),
        Box::new(extras::TrailingSlashCheck),
    ]
}

pub fn async_checks() -> Vec<Box<dyn AsyncCheck>> {
    vec![
        // Favicon validation fetches the icon and runs asynchronously.
        Box::new(basics::FaviconCheck),
        Box::new(web_manifest::WebManifestCheck),
        Box::new(basics::Custom404Check),
        Box::new(basics::WwwRedirectCheck),
        Box::new(extras::SitemapInRobotsCheck),
    ]
}

#[cfg(test)]
mod copy_guardrails {
    /// Enforce banned copy tokens across accessibility, compliance, and config checks.
    #[test]
    fn accessibility_compliance_config_sources_have_no_banned_tokens() {
        // "a" + "11y": the abbreviation of Accessibility.
        let abbreviation = format!("a{}", "11y");
        let manifest = std::path::Path::new(env!("SITECMD_SOURCE_ROOT"));
        let mut offenders = Vec::new();
        for base in [
            manifest.join("src/checks"),
            manifest.join("crates/engine/src/checks"),
        ] {
            for dir in ["accessibility", "compliance", "config"] {
                let scanned = base.join(dir);
                if scanned.is_dir() {
                    scan_dir(&scanned, &abbreviation, &mut offenders);
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "em-dash (U+2014) or abbreviated Accessibility found in check sources:\n{}",
            offenders.join("\n")
        );
    }

    fn scan_dir(dir: &std::path::Path, abbreviation: &str, offenders: &mut Vec<String>) {
        let entries = std::fs::read_dir(dir).expect("check source dir exists"); // allow-expect: test-only path under CARGO_MANIFEST_DIR
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, abbreviation, offenders);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = std::fs::read_to_string(&path).unwrap_or_default();
                for (index, line) in source.lines().enumerate() {
                    if line.contains('\u{2014}') || line.to_ascii_lowercase().contains(abbreviation)
                    {
                        offenders.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            index + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
}
