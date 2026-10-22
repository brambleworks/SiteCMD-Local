//! Rust module declarations and their conditional path edges.

use super::super::super::file_analysis::blank_rust_non_code;
use super::attributes::requires_test;
use std::collections::HashSet;
use std::sync::LazyLock;

static PATH_ATTRIBUTE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?:#\s*\[\s*path\b|\bpath\s*=)")
        .expect("static Rust path attribute pattern") // allow-expect: compile-time literal regex
});
static DECLARATION: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\bmod\s+([^\s;{}]+)\s*[;{]")
        .expect("static Rust module declaration pattern") // allow-expect: compile-time literal regex
});
static MODULE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"((?:#\s*\[[^\]]*\]\s*)*)(?:pub(?:\s*\([^)]*\))?\s+)?\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])")
        .expect("static Rust module pattern") // allow-expect: compile-time literal regex
});
static CFG_TEST: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"#\s*\[\s*cfg\s*\(([^\]]*)\)\s*\]")
        .expect("static Rust test attribute pattern") // allow-expect: compile-time literal regex
});
static MODULE_PATH: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]"#)
        .expect("static Rust module path pattern") // allow-expect: compile-time literal regex
});

#[derive(Clone, Debug)]
pub(super) struct Module {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) inline: bool,
    pub(super) test_only: bool,
    pub(super) name: String,
    pub(super) path: Option<String>,
    pub(super) parents: Vec<String>,
    pub(super) uncertainty: Option<&'static str>,
}

pub(super) fn modules(content: &str) -> Vec<Module> {
    let structure = blank_rust_non_code(content);
    let mut found: Vec<Module> = Vec::new();
    let mut parsed = HashSet::new();
    for capture in MODULE.captures_iter(&structure) {
        let (Some(whole), Some(attributes)) = (capture.get(0), capture.get(1)) else {
            continue;
        };
        parsed.insert(capture.get(2).map(|name| name.start()));
        let inline = &capture[3] == "{";
        let mut end = whole.end();
        if inline {
            let mut depth = 1;
            for (offset, byte) in structure.as_bytes()[end..].iter().enumerate() {
                match byte {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    end += offset + 1;
                    break;
                }
            }
        }
        let parents = found
            .iter()
            .filter(|parent| parent.inline && parent.end > whole.start())
            .collect::<Vec<_>>();
        let test_only = CFG_TEST
            .captures_iter(attributes.as_str())
            .any(|cfg| requires_test(&cfg[1]))
            || parents.iter().any(|parent| parent.test_only);
        let raw_attributes = &content[attributes.range()];
        let path = MODULE_PATH.captures_iter(raw_attributes).find_map(|path| {
            let start = attributes.start() + path.get(0)?.start();
            (structure.as_bytes()[start] == b'#').then(|| path[1].to_string())
        });
        let parent_names = parents.iter().map(|parent| parent.name.clone()).collect();
        let module = Module {
            start: whole.start(),
            end,
            inline,
            test_only,
            name: capture[2].to_string(),
            path,
            parents: parent_names,
            uncertainty: None,
        };
        if !inline {
            for (path, predicate_test_only) in
                super::attributes::conditional_paths(raw_attributes, attributes.as_str())
            {
                found.push(Module {
                    path: Some(path),
                    test_only: test_only || predicate_test_only,
                    ..module.clone()
                });
            }
        }
        found.push(module);
        let readable = found
            .iter()
            .filter(|module| module.start == whole.start() && module.path.is_some())
            .count();
        let unread = PATH_ATTRIBUTE.find_iter(attributes.as_str()).count() > readable;
        for module in found
            .iter_mut()
            .filter(|module| module.start == whole.start())
        {
            module.uncertainty = (unread || (module.inline && module.path.is_some()))
                .then_some("unreadable path attribute");
        }
    }
    let readable = found.iter().filter(|module| module.path.is_some()).count();
    if super::attributes::path_attribute_count(&structure) > readable
        && !found.iter().any(|module| module.uncertainty.is_some())
    {
        found.push(Module {
            start: 0,
            end: 0,
            inline: true,
            test_only: false,
            name: "<path attribute>".into(),
            path: None,
            parents: Vec::new(),
            uncertainty: Some("unreadable path attribute"),
        });
    }
    for capture in DECLARATION.captures_iter(&structure) {
        let Some(name) = capture.get(1) else {
            continue;
        };
        if !parsed.contains(&Some(name.start())) {
            found.push(Module {
                start: name.start(),
                end: name.end(),
                inline: false,
                test_only: false,
                name: name.as_str().to_string(),
                path: None,
                parents: Vec::new(),
                uncertainty: Some("unreadable module declaration"),
            });
        }
    }
    found.extend(super::includes::edges(content, &structure, &found));
    let macro_bodies = super::macros::bodies(&structure);
    for module in &mut found {
        if macro_bodies.iter().any(|body| body.contains(&module.start)) {
            module.uncertainty = Some("module declaration inside macro_rules body");
        }
    }
    found
}

pub(super) fn attributes_require_test(attributes: &str) -> bool {
    CFG_TEST
        .captures_iter(attributes)
        .any(|cfg| requires_test(&cfg[1]))
}
