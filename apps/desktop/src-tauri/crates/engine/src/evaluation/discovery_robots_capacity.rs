//! Release measurements for bounded discovery on long, hostile paths.

#[path = "discovery_robots_capacity_inputs.rs"]
mod inputs;
#[path = "discovery_robots_capacity_support.rs"]
mod support;

use super::RobotsRules;
use inputs::{Fixture, Ladder, Shape};
use std::hint::black_box;
use std::time::Instant;

fn checked_rules(
    fixture: &Fixture,
    ladder: Ladder,
    count: usize,
    blocked: bool,
    path: &str,
) -> RobotsRules {
    let rules = RobotsRules::parse(&fixture.body, "SiteCMD");
    assert_eq!(
        rules
            .rules
            .iter()
            .map(|rule| rule.pieces.len())
            .sum::<usize>(),
        ladder.pieces(count)
    );
    let stars = rules
        .rules
        .iter()
        .filter(|rule| rule.pieces.len() > 1)
        .count();
    assert!(stars <= ladder.stars(count));
    if matches!(ladder, Ladder::Stars) {
        assert_eq!(stars, count);
    }
    assert!(rules
        .rules
        .iter()
        .all(|rule| rule.literal_bytes <= path.len()));
    assert_eq!(rules.allowed(path), !blocked);
    assert_eq!(
        crate::probe::decode_probe_body(fixture.raw.clone()).text,
        fixture.body
    );
    rules
}

fn candidate_us(rules: &RobotsRules, path: &str) -> f64 {
    support::measurement_start();
    let mut samples = [0.0; 5];
    for elapsed in &mut samples {
        let started = Instant::now();
        for _ in 0..20 {
            black_box(rules.allowed(black_box(path)));
        }
        *elapsed = started.elapsed().as_secs_f64() * 50_000.0;
    }
    println!("CANDIDATE_SAMPLES {samples:?}");
    samples.sort_by(f64::total_cmp);
    samples[2]
}

fn trial(
    fixture: &Fixture,
    ladder: Ladder,
    count: usize,
    family: Shape,
    blocked: bool,
    path: &str,
) -> f64 {
    let rules = checked_rules(fixture, ladder, count, blocked, path);
    let elapsed = candidate_us(&rules, path);
    println!(
        "TRIAL {} {count} {} {blocked} {} {elapsed:.3}",
        ladder.label(),
        family.label(),
        fixture.config.label()
    );
    elapsed
}

fn measure(ladder: Ladder, count: usize) {
    let paths = support::paths();
    let shapes: &[Shape] = match ladder {
        Ladder::Stars => &[
            Shape::Pieces,
            Shape::Star,
            Shape::Encoded,
            Shape::Lossy,
            Shape::Halves,
            Shape::Repeated,
            Shape::Periodic,
        ],
        Ladder::Pieces => &[Shape::Plain, Shape::Dense, Shape::Mixed, Shape::Periodic],
    };
    for blocked in [false, true] {
        for &shape in shapes {
            if std::env::var("SITECMD_CAPACITY_SHAPE").is_ok_and(|value| value != shape.label())
                || std::env::var("SITECMD_CAPACITY_BLOCKED")
                    .is_ok_and(|value| value != blocked.to_string())
            {
                continue;
            }
            println!(
                "CAPACITY_START {} {count} {} {blocked}",
                ladder.label(),
                shape.label()
            );
            let mut selected = None;
            let mut maximum = -1.0;
            for config in inputs::configs(ladder, count, shape, blocked, &paths[0]) {
                let fixture = inputs::fixture(ladder, count, config, blocked, &paths[0]);
                let elapsed = trial(&fixture, ladder, count, shape, blocked, &paths[0]);
                if elapsed > maximum {
                    selected = Some(fixture.config);
                    maximum = elapsed;
                }
            }
            let mut selected = selected.expect("profiles fit both limits");
            for config in inputs::filler_configs(selected) {
                let fixture = inputs::fixture(ladder, count, config, blocked, &paths[0]);
                let elapsed = trial(&fixture, ladder, count, shape, blocked, &paths[0]);
                if elapsed > maximum {
                    selected = fixture.config;
                    maximum = elapsed;
                }
            }
            let fixture = inputs::fixture(ladder, count, selected, blocked, &paths[0]);
            let rules = checked_rules(&fixture, ladder, count, blocked, &paths[0]);
            let candidate = candidate_us(&rules, &paths[0]);
            let raw_bytes = fixture.raw.len();
            let session = support::session(&paths, fixture.raw);
            let expected = if blocked { 0 } else { 99 };
            assert_eq!(
                session.discover(&[], 99).routes.expect("routes").len(),
                expected
            );
            let mut samples = [0.0; 3];
            for elapsed in &mut samples {
                support::measurement_start();
                let started = Instant::now();
                let answer = black_box(session.discover(black_box(&[]), black_box(99)));
                *elapsed = started.elapsed().as_secs_f64() * 1000.0;
                println!("ENTRY_SAMPLE {elapsed:.3}");
                assert_eq!(answer.routes.expect("routes").len(), expected);
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "CAPACITY {} {count} {} {blocked} {} {} {} {candidate:.3} {:.3}",
                ladder.label(),
                shape.label(),
                rules.rules.len(),
                raw_bytes,
                selected.label(),
                samples[1]
            );
        }
    }
}

#[test]
fn capacity_fixtures_respect_both_limits() {
    let path = &support::paths()[0];
    for (ladder, counts, shapes) in [
        (
            Ladder::Stars,
            &[25, 50, 100, 200, 400][..],
            &[
                Shape::Pieces,
                Shape::Star,
                Shape::Encoded,
                Shape::Lossy,
                Shape::Halves,
                Shape::Repeated,
                Shape::Periodic,
            ][..],
        ),
        (
            Ladder::Pieces,
            &[1000, 2000, 4000, 8000][..],
            &[Shape::Plain, Shape::Dense, Shape::Mixed, Shape::Periodic][..],
        ),
    ] {
        for &count in counts {
            let limit = match ladder {
                Ladder::Stars => super::ROBOTS_STAR_RULE_LIMIT,
                Ladder::Pieces => super::ROBOTS_PIECE_LIMIT,
            };
            if count > limit {
                continue;
            }
            for &shape in shapes {
                for blocked in [false, true] {
                    let config = inputs::configs(ladder, count, shape, blocked, path)
                        .pop()
                        .expect("profile");
                    let fixture = inputs::fixture(ladder, count, config, blocked, path);
                    checked_rules(&fixture, ladder, count, blocked, path);
                }
            }
        }
    }
}

macro_rules! capacity_cases {
    ($ladder:ident; $($name:ident: $count:literal),+ $(,)?) => {$(
        #[test]
        #[ignore = "release capacity measurement"]
        fn $name() { measure(Ladder::$ladder, $count); }
    )+};
}

capacity_cases!(Stars; stars_25: 25, stars_50: 50, stars_100: 100, stars_200: 200, stars_400: 400);
capacity_cases!(Pieces; pieces_1000: 1000, pieces_2000: 2000, pieces_4000: 4000, pieces_8000: 8000);

#[test]
fn capacity_paths_fill_the_page_cap_and_sitemap_limit() {
    let route_bytes =
        crate::log_sanitizer::ISSUE_EVIDENCE_URL_MAX_CHARS - "https://example.com".len();
    let page_bytes = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../../../../../product-facts.json"
    ))
    .expect("product facts")["scannerIdentity"]["limits"]["pageBodyMaxBytes"]
        .as_u64()
        .expect("page cap") as usize;
    let links = (page_bytes - "<!doctype html><html><body></body></html>".len())
        / (route_bytes + "<a href=''>Page</a>".len());
    assert_eq!(
        support::paths().len(),
        links + crate::checks::seo::sitemap_walk::SITEMAP_URL_LIMIT
    );
}

#[test]
fn capacity_candidates_include_the_exact_halves_needle() {
    let path = &support::paths()[0];
    let half = "a".repeat((path.len() - 2) / 2);
    let needle = format!("/*{half}Q{half}");
    assert!(inputs::configs(
        Ladder::Pieces,
        super::ROBOTS_PIECE_LIMIT,
        Shape::Mixed,
        true,
        path
    )
    .into_iter()
    .any(|config| {
        inputs::fixture(
            Ladder::Pieces,
            super::ROBOTS_PIECE_LIMIT,
            config,
            true,
            path,
        )
        .body
        .contains(&needle)
    }));
}

#[test]
fn capacity_candidates_keep_a_fixed_long_periodic_needle() {
    let path = &support::paths()[0];
    for ladder in [Ladder::Stars, Ladder::Pieces] {
        let count = if matches!(ladder, Ladder::Stars) {
            super::ROBOTS_STAR_RULE_LIMIT
        } else {
            super::ROBOTS_PIECE_LIMIT
        };
        assert!(inputs::configs(ladder, count, Shape::Mixed, true, path)
            .iter()
            .any(|config| config.shape.label() == "periodic" && config.width == path.len() - 1));
    }
}
