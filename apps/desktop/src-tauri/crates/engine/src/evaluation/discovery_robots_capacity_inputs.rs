//! Adversarial patterns within both selected-group limits and the probe-body cap.

use super::super::{ROBOTS_PIECE_LIMIT, ROBOTS_STAR_RULE_LIMIT};

const PROBE_BYTES: usize = 512 * 1024;
const HEADER: &str = "User-agent: SiteCMD\n";
const ROOT: &str = "Disallow: /\n";

#[derive(Clone, Copy, Debug)]
pub(super) enum Ladder {
    Stars,
    Pieces,
}

impl Ladder {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Stars => "stars",
            Self::Pieces => "pieces",
        }
    }

    pub(super) fn pieces(self, count: usize) -> usize {
        match self {
            Self::Stars => ROBOTS_PIECE_LIMIT,
            Self::Pieces => count,
        }
    }

    pub(super) fn stars(self, count: usize) -> usize {
        match self {
            Self::Stars => count,
            Self::Pieces => ROBOTS_STAR_RULE_LIMIT,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Shape {
    Dense,
    Halves,
    Repeated,
    Periodic,
    Encoded,
    Lossy,
    Pieces,
    Plain,
    Star,
    Mixed,
}

impl Shape {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Dense => "dense",
            Self::Halves => "halves",
            Self::Repeated => "repeated",
            Self::Periodic => "periodic",
            Self::Encoded => "encoded",
            Self::Lossy => "lossy",
            Self::Pieces => "pieces",
            Self::Plain => "plain",
            Self::Star => "star",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Config {
    pub(super) shape: Shape,
    pub(super) width: usize,
    pub(super) stars: usize,
    pub(super) filler: usize,
}

impl Config {
    pub(super) fn label(self) -> String {
        format!(
            "{}-w{}-n{}-l{}",
            self.shape.label(),
            self.width,
            self.stars,
            self.filler
        )
    }
}

pub(super) struct Fixture {
    pub(super) body: String,
    pub(super) raw: Vec<u8>,
    pub(super) config: Config,
}

fn widths(maximum: usize) -> Vec<usize> {
    let mut widths: Vec<_> = [2, 3, 4, 8, 16, 32, 39, 64, 128, 256, maximum]
        .into_iter()
        .filter(|width| *width <= maximum)
        .collect();
    widths.sort_unstable();
    widths.dedup();
    widths
}

pub(super) fn configs(
    ladder: Ladder,
    count: usize,
    family: Shape,
    blocked: bool,
    path: &str,
) -> Vec<Config> {
    let pieces = ladder.pieces(count) - usize::from(blocked);
    let stars = ladder.stars(count).min(pieces / 2);
    let shapes: &[Shape] = if matches!(family, Shape::Mixed) {
        &[
            Shape::Pieces,
            Shape::Star,
            Shape::Encoded,
            Shape::Lossy,
            Shape::Halves,
            Shape::Repeated,
            Shape::Periodic,
        ]
    } else {
        std::slice::from_ref(&family)
    };
    let mut result = Vec::new();
    for &shape in shapes {
        let counts = if matches!(family, Shape::Mixed) {
            vec![stars, stars / 2, stars / 4]
        } else {
            vec![stars]
        };
        for stars in counts {
            let maximum = match shape {
                Shape::Pieces => (pieces / stars).min(path.len() - 6),
                Shape::Dense => path.len() - 6,
                Shape::Plain => ((PROBE_BYTES - HEADER.len() - ROOT.len()) / pieces)
                    .saturating_sub(11)
                    .min(path.len() - 5),
                Shape::Encoded => (path.len() - 2) / 3 + 2,
                Shape::Lossy | Shape::Star | Shape::Halves | Shape::Repeated => path.len(),
                Shape::Periodic => path.len() - 1,
                Shape::Mixed => unreachable!(),
            };
            let widths = if matches!(shape, Shape::Periodic) {
                vec![maximum]
            } else if matches!(shape, Shape::Repeated) {
                ((path.len() - 6)..=maximum).collect()
            } else {
                widths(maximum)
            };
            for width in widths {
                if matches!(shape, Shape::Dense) && pieces.div_ceil(width) > ladder.stars(count) {
                    continue;
                }
                result.push(Config {
                    shape,
                    width,
                    stars,
                    filler: usize::MAX,
                });
            }
        }
    }
    result
}

fn raw(body: &str) -> Vec<u8> {
    body.chars()
        .map(|character| {
            if character == '\u{fffd}' {
                0xff
            } else {
                u8::try_from(character as u32).expect("ASCII fixture")
            }
        })
        .collect()
}

fn append(body: &mut String, pattern: &str, count: usize) {
    body.push_str(&format!("Disallow: {pattern}\n").repeat(count));
}

fn pattern(config: Config) -> String {
    match config.shape {
        Shape::Pieces | Shape::Dense => format!("/{}*Q", "*a".repeat(config.width - 2)),
        Shape::Halves => {
            let half = "a".repeat((config.width - 2) / 2);
            format!("/*{half}Q{half}")
        }
        Shape::Repeated | Shape::Periodic => format!("/*{}", "a".repeat(config.width - 1)),
        Shape::Star => format!("/*{}Q", "a".repeat(config.width - 2)),
        Shape::Encoded => format!("/*{}Q", "[".repeat(config.width - 2)),
        Shape::Lossy => format!(
            "/*{}{}Q",
            "\u{fffd}".repeat((config.width - 2) / 9),
            "a".repeat((config.width - 2) % 9)
        ),
        Shape::Plain | Shape::Mixed => unreachable!(),
    }
}

pub(super) fn fixture(
    ladder: Ladder,
    count: usize,
    mut config: Config,
    blocked: bool,
    path: &str,
) -> Fixture {
    let pieces = ladder.pieces(count) - usize::from(blocked);
    let mut body = HEADER.to_string();
    let used = match config.shape {
        Shape::Plain => 0,
        Shape::Dense => {
            append(&mut body, &pattern(config), pieces / config.width);
            let tail = pieces % config.width;
            if tail > 1 {
                append(
                    &mut body,
                    &pattern(Config {
                        width: tail,
                        ..config
                    }),
                    1,
                );
            }
            pieces - usize::from(tail == 1)
        }
        _ => {
            append(&mut body, &pattern(config), config.stars);
            config.stars
                * if matches!(config.shape, Shape::Pieces) {
                    config.width
                } else {
                    2
                }
        }
    };
    let filler = pieces - used;
    let available = PROBE_BYTES - raw(&body).len() - if blocked { ROOT.len() } else { 0 };
    if let Some(per_rule) = available.checked_div(filler) {
        let maximum = per_rule.saturating_sub(11).min(path.len() - 5);
        assert!(maximum >= 2, "plain filler fits the probe cap");
        config.filler = if matches!(config.shape, Shape::Plain) {
            config.width.min(maximum)
        } else {
            config.filler.min(maximum)
        };
        append(
            &mut body,
            &format!("{}Q", &path[..config.filler - 1]),
            filler,
        );
    } else {
        config.filler = 0;
    }
    if blocked {
        body.push_str(ROOT);
    }
    let raw = raw(&body);
    assert!(raw.len() <= PROBE_BYTES);
    Fixture { body, raw, config }
}

pub(super) fn filler_configs(config: Config) -> Vec<Config> {
    widths(config.filler)
        .into_iter()
        .map(|filler| Config { filler, ..config })
        .collect()
}
