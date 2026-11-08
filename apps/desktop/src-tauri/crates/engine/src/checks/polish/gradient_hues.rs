//! Balanced gradient functions and chromatic stop comparisons.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Minimum number of multi-hue gradients needed for a finding.
pub const MULTI_HUE_GRADIENT_MIN: usize = 5;
/// Minimum circular distance between two chromatic stops, in OKLCH degrees.
pub const GRADIENT_HUE_MIN_DEGREES: f32 = 30.0;
/// Stops below this OKLCH chroma are treated as achromatic.
pub const GRADIENT_CHROMA_MIN: f32 = 0.03;

static GRADIENT_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i-u:(?:-(?:webkit|moz|ms|o)-)?\b(?:repeating-)?(?:linear|radial|conic)-gradient\s*\()",
    )
    .expect("gradient opening regex")
});

/// With a 30-degree threshold, stops near the first hue occupy one short arc.
#[derive(Default)]
struct HueRange {
    first: Option<f32>,
    low: f32,
    high: f32,
}

impl HueRange {
    fn separates(&self, hue: f32) -> bool {
        self.first.is_some_and(|first| {
            [first, first + self.low, first + self.high]
                .into_iter()
                .any(|other| hue_distance(hue, other) >= GRADIENT_HUE_MIN_DEGREES)
        })
    }

    fn add(&mut self, hue: f32) -> bool {
        let first = *self.first.get_or_insert(hue);
        let delta = (hue - first + 180.0).rem_euclid(360.0) - 180.0;
        self.low = self.low.min(delta);
        self.high = self.high.max(delta);
        delta.abs() >= GRADIENT_HUE_MIN_DEGREES || self.high - self.low >= GRADIENT_HUE_MIN_DEGREES
    }
}

fn hue_distance(left: f32, right: f32) -> f32 {
    let difference = (left - right).abs().rem_euclid(360.0);
    difference.min(360.0 - difference)
}

fn chromatic_hue(color: &str) -> Option<f32> {
    let color = csscolorparser::parse(color).ok()?;
    let [_, chroma, hue, alpha] = color.to_oklcha();
    (alpha > 0.0 && chroma >= GRADIENT_CHROMA_MIN).then(|| hue.to_degrees())
}

fn stop_hue(stop: &str) -> Option<f32> {
    let stop = stop.trim();
    let mut depth = 0usize;
    let mut end = stop.len();
    for (index, byte) in stop.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b if b.is_ascii_whitespace() && depth == 0 => {
                end = index;
                break;
            }
            _ => {}
        }
    }
    chromatic_hue(&stop[..end])
}

/// Consume the whole function even after finding two hues, including an unclosed tail.
fn read_gradient(text: &str, start: usize) -> (usize, bool) {
    let bytes = text.as_bytes();
    let mut index = start;
    let mut stop_start = start;
    let mut depth = 1usize;
    let mut quote = None;
    let mut hues = HueRange::default();
    let mut multi_hue = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if byte == b'\\' {
                index = (index + 2).min(bytes.len());
                continue;
            }
            if byte == delimiter {
                quote = None;
            }
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index < bytes.len()
                && !(bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/'))
            {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        } else {
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => depth += 1,
                b')' if depth == 1 => {
                    if !multi_hue {
                        multi_hue =
                            stop_hue(&text[stop_start..index]).is_some_and(|hue| hues.add(hue));
                    }
                    return (index + 1, multi_hue);
                }
                b')' => depth -= 1,
                b',' if depth == 1 => {
                    if !multi_hue {
                        multi_hue =
                            stop_hue(&text[stop_start..index]).is_some_and(|hue| hues.add(hue));
                    }
                    stop_start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    if !multi_hue && depth == 1 {
        multi_hue = stop_hue(&text[stop_start..]).is_some_and(|hue| hues.add(hue));
    }
    (index, multi_hue)
}

/// Count vendor variants of a gradient once within each declaration block.
pub(super) fn multi_hue_gradients(text: &str) -> usize {
    let mut cursor = 0;
    let mut count = 0;
    let mut variants: HashMap<String, HashMap<String, usize>> = HashMap::new();
    while let Some(opening) = GRADIENT_START.find_at(text, cursor) {
        if text[cursor..opening.start()].contains(['{', '}', '<', '>']) {
            variants.clear();
        }
        let (end, multi_hue) = read_gradient(text, opening.end());
        if multi_hue {
            let function = &text[opening.start()..end];
            let (vendor, function) = if let Some(rest) = function.strip_prefix('-') {
                let (vendor, function) = rest.split_once('-').expect("vendor prefix separator");
                (vendor, function)
            } else {
                ("", function)
            };
            let key = function
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .map(|c| c.to_ascii_lowercase())
                .collect();
            let vendors = variants.entry(key).or_default();
            let previous = vendors.values().copied().max().unwrap_or(0);
            *vendors.entry(vendor.to_ascii_lowercase()).or_default() += 1;
            count += vendors.values().copied().max().unwrap_or(0) - previous;
        }
        cursor = end;
    }
    count
}

// technical vocabulary: https://raw.githubusercontent.com/tailwindlabs/tailwindcss/v4.3.0/packages/tailwindcss/theme.css
const NEUTRAL_FAMILIES: &[&str] = &[
    "slate", "gray", "zinc", "neutral", "stone", "mauve", "olive", "mist", "taupe",
];

type ShadeColor = (u16, f32, f32);

/// Default shade chroma for every stop and hue for family/literal comparisons.
// technical vocabulary: https://raw.githubusercontent.com/tailwindlabs/tailwindcss/v4.3.0/packages/tailwindcss/theme.css
const FAMILY_STOPS: &[(&str, &[ShadeColor])] = &[
    (
        "red",
        &[
            (50, 0.013, 17.38),
            (100, 0.032, 17.717),
            (200, 0.062, 18.334),
            (300, 0.114, 19.571),
            (400, 0.191, 22.216),
            (500, 0.237, 25.331),
            (600, 0.245, 27.325),
            (700, 0.213, 27.518),
            (800, 0.177, 26.899),
            (900, 0.141, 25.723),
            (950, 0.092, 26.042),
        ],
    ),
    (
        "orange",
        &[
            (50, 0.016, 73.684),
            (100, 0.038, 75.164),
            (200, 0.076, 70.697),
            (300, 0.128, 66.29),
            (400, 0.183, 55.934),
            (500, 0.213, 47.604),
            (600, 0.222, 41.116),
            (700, 0.195, 38.402),
            (800, 0.157, 37.304),
            (900, 0.123, 38.172),
            (950, 0.079, 36.259),
        ],
    ),
    (
        "amber",
        &[
            (50, 0.022, 95.277),
            (100, 0.059, 95.617),
            (200, 0.12, 95.746),
            (300, 0.169, 91.605),
            (400, 0.189, 84.429),
            (500, 0.188, 70.08),
            (600, 0.179, 58.318),
            (700, 0.163, 48.998),
            (800, 0.137, 46.201),
            (900, 0.112, 45.904),
            (950, 0.077, 45.635),
        ],
    ),
    (
        "yellow",
        &[
            (50, 0.026, 102.212),
            (100, 0.071, 103.193),
            (200, 0.129, 101.54),
            (300, 0.182, 98.111),
            (400, 0.199, 91.936),
            (500, 0.184, 86.047),
            (600, 0.162, 75.834),
            (700, 0.135, 66.442),
            (800, 0.114, 61.907),
            (900, 0.095, 57.708),
            (950, 0.066, 53.813),
        ],
    ),
    (
        "lime",
        &[
            (50, 0.031, 120.757),
            (100, 0.067, 122.328),
            (200, 0.127, 124.321),
            (300, 0.196, 126.665),
            (400, 0.238, 128.85),
            (500, 0.233, 130.85),
            (600, 0.2, 131.684),
            (700, 0.157, 131.589),
            (800, 0.124, 130.933),
            (900, 0.101, 131.063),
            (950, 0.072, 132.109),
        ],
    ),
    (
        "green",
        &[
            (50, 0.018, 155.826),
            (100, 0.044, 156.743),
            (200, 0.084, 155.995),
            (300, 0.15, 154.449),
            (400, 0.209, 151.711),
            (500, 0.219, 149.579),
            (600, 0.194, 149.214),
            (700, 0.154, 150.069),
            (800, 0.119, 151.328),
            (900, 0.095, 152.535),
            (950, 0.065, 152.934),
        ],
    ),
    (
        "emerald",
        &[
            (50, 0.021, 166.113),
            (100, 0.052, 163.051),
            (200, 0.093, 164.15),
            (300, 0.143, 164.978),
            (400, 0.177, 163.223),
            (500, 0.17, 162.48),
            (600, 0.145, 163.225),
            (700, 0.118, 165.612),
            (800, 0.095, 166.913),
            (900, 0.077, 168.94),
            (950, 0.051, 172.552),
        ],
    ),
    (
        "teal",
        &[
            (50, 0.014, 180.72),
            (100, 0.051, 180.801),
            (200, 0.096, 180.426),
            (300, 0.138, 181.071),
            (400, 0.152, 181.912),
            (500, 0.14, 182.503),
            (600, 0.118, 184.704),
            (700, 0.096, 186.391),
            (800, 0.078, 188.216),
            (900, 0.063, 188.416),
            (950, 0.046, 192.524),
        ],
    ),
    (
        "cyan",
        &[
            (50, 0.019, 200.873),
            (100, 0.045, 203.388),
            (200, 0.08, 205.041),
            (300, 0.127, 207.078),
            (400, 0.154, 211.53),
            (500, 0.143, 215.221),
            (600, 0.126, 221.723),
            (700, 0.105, 223.128),
            (800, 0.085, 224.283),
            (900, 0.07, 227.392),
            (950, 0.056, 229.695),
        ],
    ),
    (
        "sky",
        &[
            (50, 0.013, 236.62),
            (100, 0.026, 236.824),
            (200, 0.058, 230.902),
            (300, 0.111, 230.318),
            (400, 0.16, 232.661),
            (500, 0.169, 237.323),
            (600, 0.158, 241.966),
            (700, 0.134, 242.749),
            (800, 0.11, 240.79),
            (900, 0.09, 240.876),
            (950, 0.066, 243.157),
        ],
    ),
    (
        "blue",
        &[
            (50, 0.014, 254.604),
            (100, 0.032, 255.585),
            (200, 0.059, 254.128),
            (300, 0.105, 251.813),
            (400, 0.165, 254.624),
            (500, 0.214, 259.815),
            (600, 0.245, 262.881),
            (700, 0.243, 264.376),
            (800, 0.199, 265.638),
            (900, 0.146, 265.522),
            (950, 0.091, 267.935),
        ],
    ),
    (
        "indigo",
        &[
            (50, 0.018, 272.314),
            (100, 0.034, 272.788),
            (200, 0.065, 274.039),
            (300, 0.115, 274.713),
            (400, 0.182, 276.935),
            (500, 0.233, 277.117),
            (600, 0.262, 276.966),
            (700, 0.24, 277.023),
            (800, 0.195, 277.366),
            (900, 0.144, 278.697),
            (950, 0.09, 281.288),
        ],
    ),
    (
        "violet",
        &[
            (50, 0.016, 293.756),
            (100, 0.029, 294.588),
            (200, 0.057, 293.283),
            (300, 0.111, 293.571),
            (400, 0.183, 293.541),
            (500, 0.25, 292.717),
            (600, 0.281, 293.009),
            (700, 0.27, 292.581),
            (800, 0.232, 292.759),
            (900, 0.189, 293.745),
            (950, 0.141, 291.089),
        ],
    ),
    (
        "purple",
        &[
            (50, 0.014, 308.299),
            (100, 0.033, 307.174),
            (200, 0.063, 306.703),
            (300, 0.119, 306.383),
            (400, 0.203, 305.504),
            (500, 0.265, 303.9),
            (600, 0.288, 302.321),
            (700, 0.265, 301.924),
            (800, 0.218, 303.724),
            (900, 0.176, 304.987),
            (950, 0.149, 302.717),
        ],
    ),
    (
        "fuchsia",
        &[
            (50, 0.017, 320.058),
            (100, 0.037, 318.852),
            (200, 0.076, 319.62),
            (300, 0.145, 321.434),
            (400, 0.238, 322.16),
            (500, 0.295, 322.15),
            (600, 0.293, 322.896),
            (700, 0.253, 323.949),
            (800, 0.211, 324.591),
            (900, 0.17, 325.612),
            (950, 0.136, 325.661),
        ],
    ),
    (
        "pink",
        &[
            (50, 0.014, 343.198),
            (100, 0.028, 342.258),
            (200, 0.061, 343.231),
            (300, 0.12, 346.018),
            (400, 0.202, 349.761),
            (500, 0.241, 354.308),
            (600, 0.249, 0.584),
            (700, 0.223, 3.958),
            (800, 0.187, 3.815),
            (900, 0.153, 2.432),
            (950, 0.109, 3.907),
        ],
    ),
    (
        "rose",
        &[
            (50, 0.015, 12.422),
            (100, 0.03, 12.58),
            (200, 0.058, 10.001),
            (300, 0.117, 11.638),
            (400, 0.194, 13.428),
            (500, 0.246, 16.439),
            (600, 0.253, 17.585),
            (700, 0.222, 16.935),
            (800, 0.188, 13.697),
            (900, 0.159, 10.272),
            (950, 0.105, 12.094),
        ],
    ),
];

pub(super) fn variant_utility(token: &str) -> (&str, &str) {
    let mut depth = 0usize;
    let mut start = 0;
    for (index, byte) in token.bytes().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b':' if depth == 0 => start = index + 1,
            _ => {}
        }
    }
    (&token[..start], token[start..].trim_matches('!'))
}

/// Count each variant's gradient independently, without pooling colors across states.
pub(super) fn tailwind_multi_hue_gradients(class_value: &str) -> usize {
    let mut variants = std::collections::HashMap::<&str, Vec<&str>>::new();
    for token in class_value.split_ascii_whitespace() {
        let (variant, utility) = variant_utility(token);
        if utility.starts_with("from-") || utility.starts_with("via-") || utility.starts_with("to-")
        {
            variants.entry(variant).or_default().push(utility);
        }
    }
    variants
        .values()
        .filter(|utilities| variant_is_multi_hue(utilities))
        .count()
}

fn variant_is_multi_hue(utilities: &[&str]) -> bool {
    let mut family = None;
    let mut literal_hues = HueRange::default();
    let mut named_hues = Vec::<(u16, f32)>::new();
    for utility in utilities {
        let Some(value) = utility
            .strip_prefix("from-")
            .or_else(|| utility.strip_prefix("via-"))
            .or_else(|| utility.strip_prefix("to-"))
        else {
            continue;
        };
        if let Some(color) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let color = color
                .strip_prefix("color:")
                .unwrap_or(color)
                .replace('_', " ");
            if chromatic_hue(&color).is_some_and(|hue| {
                literal_hues.add(hue)
                    || named_hues
                        .iter()
                        .any(|(_, named)| hue_distance(hue, *named) >= GRADIENT_HUE_MIN_DEGREES)
            }) {
                return true;
            }
            continue;
        }
        let (value, opacity) = value
            .split_once('/')
            .map_or((value, None), |(v, a)| (v, Some(a)));
        if opacity.is_some_and(|alpha| alpha.parse::<f32>().is_ok_and(|n| n == 0.0)) {
            continue;
        }
        let Some((name, shade)) = value.rsplit_once('-') else {
            continue;
        };
        if NEUTRAL_FAMILIES.contains(&name) {
            continue;
        }
        if !shade
            .parse::<u16>()
            .is_ok_and(|n| n == 50 || n == 950 || (100..=900).contains(&n) && n % 100 == 0)
        {
            continue;
        }
        let Some((_, shades)) = FAMILY_STOPS
            .iter()
            .find(|(candidate, _)| *candidate == name)
        else {
            continue;
        };
        let shade = shade.parse::<u16>().expect("validated Tailwind shade");
        if let Some((_, chroma, hue)) = shades.iter().find(|(value, _, _)| *value == shade) {
            if *chroma >= GRADIENT_CHROMA_MIN {
                if family.is_some_and(|previous| previous != name) {
                    return true;
                }
                family = Some(name);
                if literal_hues.separates(*hue) {
                    return true;
                }
                // Deduplicating the default shades bounds this collection to the source palette.
                if !named_hues.iter().any(|(value, _)| *value == shade) {
                    named_hues.push((shade, *hue));
                }
            }
        }
    }
    false
}

/// Gradient text needs a gradient function, regardless of its stop hues.
pub(super) fn has_gradient_function(text: &str) -> bool {
    GRADIENT_START.is_match(text)
}

/// Resolve a gradient utility using the same default palette as background gradients.
pub(super) fn is_tailwind_gradient(utility: &str) -> bool {
    if utility
        .strip_prefix("bg-gradient-")
        .is_some_and(|tail| !tail.is_empty())
        || utility
            .strip_prefix("bg-linear-")
            .is_some_and(|tail| !tail.is_empty())
    {
        return true;
    }
    let Some(value) = utility.strip_prefix("from-") else {
        return false;
    };
    if let Some(color) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return csscolorparser::parse(
            &color
                .strip_prefix("color:")
                .unwrap_or(color)
                .replace('_', " "),
        )
        .is_ok();
    }
    let value = value.split_once('/').map_or(value, |(value, _)| value);
    // technical vocabulary: https://www.w3.org/TR/css-color-4/
    if matches!(value, "black" | "white" | "transparent") {
        return true;
    }
    let Some((family, shade)) = value.rsplit_once('-') else {
        return false;
    };
    let Ok(shade) = shade.parse::<u16>() else {
        return false;
    };
    FAMILY_STOPS
        .iter()
        .any(|(name, shades)| *name == family && shades.iter().any(|(value, _, _)| *value == shade))
        || NEUTRAL_FAMILIES.contains(&family)
            && (shade == 50 || shade == 950 || (100..=900).contains(&shade) && shade % 100 == 0)
}
