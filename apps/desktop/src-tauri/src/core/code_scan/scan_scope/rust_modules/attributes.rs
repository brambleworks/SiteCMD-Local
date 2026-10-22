//! Conditional module paths use structural predicates and literal path values.

use std::ops::Range;
use std::sync::LazyLock;

static CFG_ATTR: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"#\s*\[\s*cfg_attr\s*\(([^\]]*)\)\s*\]")
        .expect("static conditional Rust attribute pattern") // allow-expect: compile-time literal regex
});
static PATH_VALUE: LazyLock<regex::Regex> = LazyLock::new(|| {
    let regex = regex::Regex::new(r#"^\s*path\s*=\s*"([^"\\]+)"\s*$"#);
    regex.expect("static Rust path value pattern") // allow-expect: literal regex
});
static ATTRIBUTE_START: LazyLock<regex::Regex> = LazyLock::new(|| {
    let regex = regex::Regex::new(r"#\s*\[");
    regex.expect("static Rust attribute opening pattern") // allow-expect: literal regex
});
static PATH_ASSIGNMENT: LazyLock<regex::Regex> = LazyLock::new(|| {
    let regex = regex::Regex::new(r"\bpath\s*=");
    regex.expect("static Rust path assignment pattern") // allow-expect: literal regex
});

pub(super) fn conditional_paths(raw: &str, structure: &str) -> Vec<(String, bool)> {
    let mut paths = Vec::new();
    for attribute in CFG_ATTR.captures_iter(structure) {
        let Some(inner) = attribute.get(1) else {
            continue;
        };
        let arguments = argument_ranges(inner.as_str());
        let Some(predicate) = arguments.first() else {
            continue;
        };
        let test_only = requires_test(&inner.as_str()[predicate.clone()]);
        for argument in arguments.iter().skip(1) {
            let start = inner.start() + argument.start;
            let end = inner.start() + argument.end;
            if let Some(path) = PATH_VALUE.captures(&raw[start..end]) {
                paths.push((path[1].to_string(), test_only));
            }
        }
    }
    paths
}

fn argument_ranges(expression: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (index, byte) in expression.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                ranges.push(start..index);
                start = index + 1;
            }
            _ => {}
        }
    }
    ranges.push(start..expression.len());
    ranges
}

pub(super) fn path_attribute_count(structure: &str) -> usize {
    let mut count = 0;
    for opening in ATTRIBUTE_START.find_iter(structure) {
        let start = opening.end();
        let mut depth = 1;
        let end = structure.as_bytes()[start..]
            .iter()
            .position(|byte| {
                match byte {
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .map(|offset| start + offset)
            .unwrap_or(structure.len());
        let attribute = structure[start..end].trim_start();
        match attribute
            .split(|value: char| !value.is_alphanumeric() && value != '_')
            .next()
        {
            Some("path") => count += 1,
            Some("cfg_attr") => count += PATH_ASSIGNMENT.find_iter(attribute).count(),
            _ => {}
        }
    }
    count
}

pub(super) fn requires_test(expression: &str) -> bool {
    let expression = expression.trim();
    if expression == "test" {
        return true;
    }
    let Some(open) = expression.find('(') else {
        return false;
    };
    if expression[..open].trim() != "all" || !expression.ends_with(')') {
        return false;
    }
    let arguments = &expression[open + 1..expression.len() - 1];
    let mut depth = 0;
    let mut start = 0;
    for (index, byte) in arguments.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                if requires_test(&arguments[start..index]) {
                    return true;
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    requires_test(&arguments[start..])
}
