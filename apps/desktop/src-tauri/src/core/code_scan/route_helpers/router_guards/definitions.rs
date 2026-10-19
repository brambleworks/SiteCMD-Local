use super::*;
use std::ops::Range;

static FUNCTION: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(r"(?m)(?:^|[;}\n])[\t ]*(export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(")
});
static VARIABLE: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(r"(?m)(?:^|[;}\n])[\t ]*(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b")
});

pub(super) struct Definition {
    pub(super) name: String,
    pub(super) exported: bool,
    pub(super) body: Range<usize>,
    pub(super) expression: bool,
}

fn top_level(structure: &str, start: usize) -> bool {
    structure[..start]
        .bytes()
        .fold(0isize, |depth, byte| match byte {
            b'{' => depth + 1,
            b'}' => depth - 1,
            _ => depth,
        })
        == 0
}

fn body_open(structure: &str, after: usize) -> Option<usize> {
    let mut angles = 0usize;
    for (offset, byte) in structure.bytes().enumerate().skip(after) {
        match byte {
            b'<' => angles += 1,
            b'>' => angles = angles.saturating_sub(1),
            b'{' if angles == 0 => return Some(offset),
            b';' if angles == 0 => return None,
            _ => {}
        }
    }
    None
}

pub(super) fn definitions(structure: &str) -> Vec<Definition> {
    let mut definitions = Vec::new();
    for capture in FUNCTION.captures_iter(structure) {
        let Some(full) = capture.get(0) else {
            continue;
        };
        if !top_level(
            structure,
            capture.get(2).map_or(full.start(), |name| name.start()),
        ) {
            continue;
        }
        let Some(params_end) = js_spans::matching(structure, full.end() - 1) else {
            continue;
        };
        let Some(open) = body_open(structure, params_end + 1) else {
            continue;
        };
        let Some(end) = js_spans::matching(structure, open) else {
            continue;
        };
        definitions.push(Definition {
            name: capture[2].to_string(),
            exported: capture.get(1).is_some(),
            body: open + 1..end,
            expression: false,
        });
    }
    for capture in VARIABLE.captures_iter(structure) {
        let Some(full) = capture.get(0) else {
            continue;
        };
        if !top_level(
            structure,
            capture.get(2).map_or(full.start(), |name| name.start()),
        ) {
            continue;
        }
        let Some(equal) = structure[full.end()..].find('=') else {
            continue;
        };
        let start = full.end() + equal + 1;
        if structure[full.end()..start].contains(';') {
            continue;
        }
        let value = structure[start..].trim_start();
        let value = value.strip_prefix("async ").unwrap_or(value).trim_start();
        let signature = structure.len() - value.len();
        let after = if value.starts_with('(') {
            let Some(end) = js_spans::matching(structure, signature) else {
                continue;
            };
            end + 1
        } else {
            let Some(end) = value.find("=>") else {
                continue;
            };
            if !IDENTIFIER.is_match(value[..end].trim()) {
                continue;
            }
            signature + end
        };
        let Some(arrow) = structure[after..].find("=>") else {
            continue;
        };
        if structure[after..after + arrow].contains([';', '{', '=']) {
            continue;
        }
        let body = after + arrow + 2;
        let body = body + structure[body..].len() - structure[body..].trim_start().len();
        let (span, expression) = if structure[body..].starts_with('{') {
            let Some(end) = js_spans::matching(structure, body) else {
                continue;
            };
            (body + 1..end, false)
        } else {
            let mut end = body;
            while end < structure.len() && structure.as_bytes()[end] != b';' {
                if matches!(structure.as_bytes()[end], b'(' | b'[' | b'{') {
                    let Some(close) = js_spans::matching(structure, end) else {
                        break;
                    };
                    end = close;
                }
                end += 1;
            }
            (body..end, true)
        };
        definitions.push(Definition {
            name: capture[2].to_string(),
            exported: capture.get(1).is_some(),
            body: span,
            expression,
        });
    }
    definitions
}
