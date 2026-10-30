//! Literal includes contribute edges from the including file's directory.

use super::declarations::{attributes_require_test, Module};
use std::sync::LazyLock;

static INCLUDE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"((?:#\s*\[[^\]]*\]\s*)*)\binclude\s*!\s*([({\[])")
        .expect("static Rust include pattern") // allow-expect: compile-time literal regex
});

pub(super) fn edges(content: &str, structure: &str, modules: &[Module]) -> Vec<Module> {
    let mut edges = Vec::new();
    for capture in INCLUDE.captures_iter(structure) {
        let Some(whole) = capture.get(0) else {
            continue;
        };
        let opening = capture[2].as_bytes()[0];
        let closing = match opening {
            b'(' => b')',
            b'{' => b'}',
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
        let argument = content[whole.end()..end]
            .trim()
            .trim_end_matches(',')
            .trim();
        let path = literal_path(argument);
        edges.push(Module {
            start: whole.start(),
            end: end + usize::from(end < structure.len()),
            inline: false,
            test_only: attributes_require_test(&capture[1])
                || modules.iter().any(|module| {
                    module.inline
                        && module.test_only
                        && module.start < whole.start()
                        && module.end > end
                }),
            name: "<include>".into(),
            uncertainty: path.is_none().then_some("unreadable include argument"),
            path,
            parents: Vec::new(),
        });
    }
    edges
}

fn literal_path(argument: &str) -> Option<String> {
    if let Some(raw) = argument.strip_prefix('r') {
        let quote = raw.find('"')?;
        let hashes = &raw[..quote];
        if hashes.bytes().all(|byte| byte == b'#') {
            return raw[quote + 1..]
                .strip_suffix(&format!("\"{hashes}"))
                .map(str::to_string);
        }
        return None;
    }
    argument
        .strip_prefix('"')?
        .strip_suffix('"')
        .filter(|value| !value.contains(['"', '\\']))
        .map(str::to_string)
}
