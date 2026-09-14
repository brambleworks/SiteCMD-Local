use super::web_check_ids;
use std::collections::HashSet;
use std::path::Path;

#[test]
fn check_inventory_snapshot_matches_the_registries() {
    let path = Path::new(env!("SITECMD_SOURCE_ROOT")).join("check-inventory.json");
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({ "web": web_check_ids() })).unwrap()
    );
    if std::env::var_os("SITECMD_UPDATE_CHECK_INVENTORY").is_some() || !path.exists() {
        std::fs::write(&path, &rendered).expect("write inventory snapshot");
    }
    assert_eq!(
        std::fs::read_to_string(&path).expect("read inventory snapshot"),
        rendered,
        "check-inventory.json is stale; rerun with SITECMD_UPDATE_CHECK_INVENTORY=1 and commit it"
    );
}

#[test]
fn every_emitted_web_check_id_has_a_manifest_contract() {
    let entries: Vec<_> = sitecmd_engine::manifest::registry::entries().collect();
    let runner_ids: HashSet<&str> = sitecmd_engine::manifest::registry::RUNNER_IDS
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let missing: Vec<String> = web_check_ids()
        .into_iter()
        .filter(|id| !runner_ids.contains(id.as_str()))
        .filter(|id| {
            !entries.iter().any(|entry| {
                if entry.family {
                    id.starts_with(entry.check)
                } else {
                    entry.check == id
                }
            })
        })
        .collect();
    assert!(
        missing.is_empty(),
        "emitted ids without a manifest row: {missing:?}"
    );
}

/// Runner shells whose `emitted_ids` still returns only the shell id. Lower as
/// overrides land; the manifest completeness test only sees sub-ids once the
/// override exists. `seo.headings` is a fifth `RUNNER_IDS` entry, but it is
/// not counted here: `seo::sync_checks()` deliberately excludes the shell.
/// Its H1 half runs as the registered `seo.headings.h1`, and heading order
/// stays with `accessibility.headings` (see `src/checks/seo/mod.rs` tests),
/// so the bare shell id never appears in `web_check_ids()` to begin with.
const RUNNER_SHELLS_WITHOUT_EMITTED_IDS: usize = 0;

#[test]
fn runner_shells_declare_their_emitted_ids() {
    let ids: HashSet<String> = web_check_ids().into_iter().collect();
    let undeclared = sitecmd_engine::manifest::registry::RUNNER_IDS
        .iter()
        .filter(|(id, _)| ids.contains(*id))
        .count();
    assert_eq!(undeclared, RUNNER_SHELLS_WITHOUT_EMITTED_IDS);
}

/// Manifest rows no `Check`/`AsyncCheck` object in the desktop registries
/// can produce, grouped by why:
/// - Browser Run measurements (Core Web Vitals, evaluated live in the
///   analyzer webview through `crates/engine/src/evaluation`, never through
///   a static check registry) and the browser-only polish signal.
/// - `seo.headings.h1`/`.hierarchy`: `HeadingsCheck` is deliberately never
///   registered in `seo::sync_checks()` (`src/checks/seo/mod.rs` tests
///   pin this) in favor of `accessibility.headings`.
///
/// Shrinks only if one of these gains a registry-visible emitter; never
/// grows without a reviewed reason.
const UNREACHABLE_MANIFEST_ROWS: &[&str] = &[
    "performance.cls",
    "performance.fcp",
    "performance.lcp",
    "performance.long_task_blocking",
    "polish.js-errors",
    "seo.headings.h1",
    "seo.headings.hierarchy",
];

#[test]
fn every_non_family_manifest_row_is_emitted_or_allowlisted() {
    let ids: HashSet<String> = web_check_ids().into_iter().collect();
    let missing: Vec<&str> = sitecmd_engine::manifest::registry::entries()
        .filter(|entry| !entry.family)
        .map(|entry| entry.check)
        .filter(|check| !ids.contains(*check))
        .filter(|check| !UNREACHABLE_MANIFEST_ROWS.contains(check))
        .collect();
    assert!(
        missing.is_empty(),
        "manifest rows missing from web_check_ids() and not allowlisted: {missing:?}"
    );
}
