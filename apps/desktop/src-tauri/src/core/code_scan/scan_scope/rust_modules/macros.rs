//! Module declarations inside macro definitions have invocation-dependent paths.

use std::ops::Range;
use std::sync::LazyLock;

static MACRO_RULES: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\bmacro_rules\s*!\s*\w+\s*([{(\[])")
        .expect("static Rust macro definition pattern") // allow-expect: compile-time literal regex
});

pub(super) fn bodies(structure: &str) -> Vec<Range<usize>> {
    MACRO_RULES
        .captures_iter(structure)
        .filter_map(|capture| {
            let whole = capture.get(0)?;
            let opening = capture[1].as_bytes()[0];
            let closing = match opening {
                b'{' => b'}',
                b'(' => b')',
                _ => b']',
            };
            let mut depth = 1;
            let end = structure.as_bytes()[whole.end()..]
                .iter()
                .position(|byte| {
                    if *byte == opening {
                        depth += 1;
                    }
                    if *byte == closing {
                        depth -= 1;
                    }
                    depth == 0
                })
                .map(|offset| whole.end() + offset)
                .unwrap_or(structure.len());
            Some(whole.end()..end)
        })
        .collect()
}
