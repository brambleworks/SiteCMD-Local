//! The CLI's polish transport: the linked stylesheets a page names, fetched
//! on the entry page. The signals themselves are the engine's.

pub mod css_fetch;

pub use sitecmd_engine::checks::polish::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep the generated public-scanner signal manifest in sync.
    #[test]
    fn signal_manifest_is_in_sync_with_the_generated_copy() {
        let signals: Vec<serde_json::Value> = POLISH_SIGNALS
            .iter()
            .map(|s| serde_json::json!({ "id": s.id, "weight": s.weight, "category": s.category }))
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
