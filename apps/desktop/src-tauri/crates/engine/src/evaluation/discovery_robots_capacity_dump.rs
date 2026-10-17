//! Writes native capacity inputs and their checked sizes for hosted measurements.

use super::inputs::{self, Fixture, Ladder, Shape};
use super::{checked_rules, support};
use crate::checks::seo::sitemap_walk::SITEMAP_URL_LIMIT;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

const CASES: &[(Ladder, usize, bool, &str, usize, usize)] = &[
    (
        Ladder::Pieces,
        8000,
        false,
        "repeated-w478-n400-l3",
        296820,
        7600,
    ),
    (
        Ladder::Pieces,
        8000,
        true,
        "periodic-w480-n400-l3",
        297618,
        7600,
    ),
    (
        Ladder::Pieces,
        4000,
        false,
        "repeated-w479-n400-l91",
        522820,
        3600,
    ),
    (
        Ladder::Pieces,
        4000,
        true,
        "periodic-w480-n400-l2",
        238419,
        3600,
    ),
    (
        Ladder::Pieces,
        2000,
        false,
        "repeated-w480-n400-l261",
        523220,
        1600,
    ),
    (
        Ladder::Pieces,
        2000,
        true,
        "periodic-w480-n400-l262",
        524159,
        1600,
    ),
    (
        Ladder::Pieces,
        1000,
        false,
        "repeated-w478-n400-l32",
        204620,
        600,
    ),
    (
        Ladder::Pieces,
        1000,
        true,
        "periodic-w480-n400-l476",
        293745,
        600,
    ),
    (
        Ladder::Stars,
        400,
        false,
        "repeated-w479-n400-l3",
        297220,
        7600,
    ),
    (
        Ladder::Stars,
        400,
        true,
        "periodic-w480-n400-l34",
        520787,
        7600,
    ),
    (
        Ladder::Stars,
        200,
        false,
        "periodic-w480-n200-l3",
        204820,
        7800,
    ),
    (
        Ladder::Stars,
        200,
        true,
        "periodic-w480-n200-l8",
        242813,
        7800,
    ),
    (
        Ladder::Stars,
        100,
        false,
        "pieces-w64-n100-l308",
        524220,
        1700,
    ),
    (
        Ladder::Stars,
        100,
        true,
        "periodic-w480-n100-l3",
        158418,
        7900,
    ),
    (
        Ladder::Stars,
        50,
        false,
        "pieces-w128-n50-l308",
        523720,
        1650,
    ),
    (
        Ladder::Stars,
        50,
        true,
        "pieces-w128-n50-l308",
        523413,
        1650,
    ),
    (
        Ladder::Stars,
        25,
        false,
        "pieces-w256-n25-l308",
        523470,
        1625,
    ),
    (
        Ladder::Stars,
        25,
        true,
        "pieces-w256-n25-l308",
        523163,
        1625,
    ),
];

fn selected_fixture(
    ladder: Ladder,
    count: usize,
    blocked: bool,
    recipe: &str,
    path: &str,
) -> Fixture {
    // Resolve filler lengths through the same helpers as the native measurement.
    let matches: Vec<_> = inputs::configs(ladder, count, Shape::Mixed, blocked, path)
        .into_iter()
        .flat_map(|config| {
            let fixture = inputs::fixture(ladder, count, config, blocked, path);
            inputs::filler_configs(fixture.config)
        })
        .filter(|config| config.label() == recipe)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "{} {count} blocked={blocked}: expected one config for {recipe}",
        ladder.label()
    );
    let fixture = inputs::fixture(ladder, count, matches[0], blocked, path);
    assert_eq!(fixture.config.label(), recipe, "fixture recipe changed");
    fixture
}

fn write_paths(directory: &Path, file: &str, paths: &[String]) -> Value {
    let mut body = paths.join("\n");
    body.push('\n');
    fs::write(directory.join(file), body).expect("write capacity paths");
    json!({
        "file": file,
        "lines": paths.len(),
        "longest_path_length": paths.iter().map(String::len).max().unwrap_or(0),
    })
}

#[test]
#[ignore = "writes capacity inputs to SITECMD_CAPACITY_DUMP"]
fn dump_capacity_inputs() {
    let directory = std::env::var_os("SITECMD_CAPACITY_DUMP")
        .filter(|value| !value.is_empty())
        .expect("Set SITECMD_CAPACITY_DUMP to an output directory");
    let directory = Path::new(&directory);
    fs::create_dir_all(directory).expect("create capacity output directory");
    let paths = support::paths();
    let path = &paths[0];
    let mut robots = Vec::new();
    for &(ladder, count, blocked, recipe, bytes, rules) in CASES {
        let fixture = selected_fixture(ladder, count, blocked, recipe, path);
        let selected = checked_rules(&fixture, ladder, count, blocked, path);
        let suffix = if blocked { "root" } else { "plain" };
        let file = format!("robots-{}-{count}-{suffix}.txt", ladder.label());
        assert_eq!(fixture.raw.len(), bytes, "{file}: raw byte length drifted");
        assert_eq!(selected.rules.len(), rules, "{file}: rule count drifted");
        fs::write(directory.join(&file), &fixture.raw).expect("write capacity robots");
        robots.push(json!({
            "file": file,
            "ladder": ladder.label(),
            "count": count,
            "blocked": blocked,
            "recipe": recipe,
            "bytes": fixture.raw.len(),
            "rules": selected.rules.len(),
        }));
    }
    let (page_paths, sitemap_paths) = paths.split_at(support::link_count());
    assert_eq!(sitemap_paths.len(), SITEMAP_URL_LIMIT);
    let manifest = json!({
        "robots": robots,
        "paths": [
            write_paths(directory, "page-paths.txt", page_paths),
            write_paths(directory, "sitemap-paths.txt", sitemap_paths),
        ],
    });
    let mut manifest = serde_json::to_vec_pretty(&manifest).expect("serialize capacity manifest");
    manifest.push(b'\n');
    fs::write(directory.join("manifest.json"), manifest).expect("write capacity manifest");
}
