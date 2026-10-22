use super::*;

pub(in crate::core::code_scan) fn collect_js_package_refs(
    files: &[SourceFile],
) -> Vec<PackageReference> {
    let mut refs = Vec::new();

    for file in files {
        let Some(ext) = file
            .absolute_path
            .extension()
            .and_then(|value| value.to_str())
        else {
            continue;
        };
        if !JS_SOURCE_EXTENSIONS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(ext))
        {
            continue;
        }

        // Commented-out imports and package names quoted inside ordinary
        // strings are not dependencies. Both blankers preserve byte positions,
        // so line numbers computed against the original content stay correct.
        let scannable = blank_non_specifier_strings(&blank_js_comments(&file.content));
        for pattern in IMPORT_CAPTURE_PATTERNS.iter() {
            for capture in pattern.captures_iter(&scannable) {
                let Some(specifier_match) = capture.get(1) else {
                    continue;
                };
                let Some(package_name) = normalize_package_spec(specifier_match.as_str()) else {
                    continue;
                };

                refs.push(PackageReference {
                    package_name,
                    relative_path: file.relative_path.clone(),
                    absolute_path: file.absolute_path.to_string_lossy().to_string(),
                    line: Some(line_number(&file.content, specifier_match.start())),
                });
            }
        }
    }

    refs
}

/// Blank `//` and `/* */` comment interiors with spaces (newlines kept,
/// byte positions preserved) so commented-out imports are never parsed
/// as package references. String and template literals are tracked so a
/// `/*` inside a string does not start a comment.
pub(in crate::core::code_scan) fn blank_js_comments(content: &str) -> String {
    enum State {
        Code,
        Line,
        Block,
        Str(u8),
    }
    let bytes = content.as_bytes();
    let mut out = bytes.to_vec();
    let mut state = State::Code;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match state {
            State::Code => match byte {
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    state = State::Line;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    continue;
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    state = State::Block;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    continue;
                }
                b'"' | b'\'' | b'`' => state = State::Str(byte),
                _ => {}
            },
            State::Line => {
                if byte == b'\n' {
                    state = State::Code;
                } else {
                    out[i] = b' ';
                }
            }
            State::Block => {
                if byte == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    state = State::Code;
                    i += 2;
                    continue;
                }
                if byte != b'\n' {
                    out[i] = b' ';
                }
            }
            State::Str(quote) => {
                if byte == b'\\' {
                    i += 2;
                    continue;
                }
                if byte == quote || (quote != b'`' && byte == b'\n') {
                    state = State::Code;
                }
            }
        }
        i += 1;
    }
    // Only ASCII bytes are overwritten with spaces (multibyte chars inside
    // comments are blanked byte-by-byte, whole), so this stays valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

/// Blank the interior of every string and template literal except the ones
/// that are module specifiers (the literal directly after `from`, `import`,
/// `require(`, or `import(`). Comment blanking must run first so a quote
/// inside a comment cannot open a literal. Byte positions are preserved and
/// newlines are kept, so both line numbers and `(?m)` anchors stay correct.
///
/// Without this, a package-shaped word inside ordinary source text (`return
/// 'Hello from "Controller"!'`, `params.get("from") || "/x"`) reads as an
/// import specifier.
///
/// Only a literal that closes with its own quote is blanked. A lone quote the
/// lexer misreads (an apostrophe in JSX text, a backtick inside a regex
/// literal) would otherwise blank everything after it, and for a backtick that
/// runs to the end of the file because template literals span lines.
pub(in crate::core::code_scan) fn blank_non_specifier_strings(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'"' && quote != b'\'' && quote != b'`' {
            index += 1;
            continue;
        }
        let keep = precedes_module_specifier(&out[..index]);
        index += 1;
        let interior_start = index;
        let mut closed = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == quote {
                closed = true;
                break;
            }
            if quote != b'`' && byte == b'\n' {
                break;
            }
            index += 1;
        }
        let interior_end = index.min(bytes.len());
        if closed && !keep {
            for slot in out[interior_start..interior_end].iter_mut() {
                if *slot != b'\n' {
                    *slot = b' ';
                }
            }
        }
        if closed {
            index += 1;
        }
    }
    // Only whole ASCII bytes are overwritten with spaces, and a multibyte
    // character inside a blanked literal is overwritten byte by byte in full,
    // so the result stays valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

/// Whether the code before a string literal makes it a module specifier.
fn precedes_module_specifier(before: &[u8]) -> bool {
    let end = trim_trailing_ascii_whitespace(before);
    if end == 0 {
        return false;
    }
    if before[end - 1] == b'(' {
        let callee_end = trim_trailing_ascii_whitespace(&before[..end - 1]);
        let callee = trailing_identifier(&before[..callee_end]);
        return callee == b"require" || callee == b"import";
    }
    let keyword = trailing_identifier(&before[..end]);
    keyword == b"from" || keyword == b"import"
}

fn trim_trailing_ascii_whitespace(bytes: &[u8]) -> usize {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn trailing_identifier(bytes: &[u8]) -> &[u8] {
    let mut start = bytes.len();
    while start > 0 {
        let byte = bytes[start - 1];
        if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' {
            start -= 1;
        } else {
            break;
        }
    }
    &bytes[start..]
}

/// Package names referenced by imports in content outside the normal source walk.
pub(in crate::core::code_scan) fn collect_package_names_in_content(
    content: &str,
) -> std::collections::HashSet<String> {
    let content = blank_non_specifier_strings(&blank_js_comments(content));
    let mut names = std::collections::HashSet::new();
    for pattern in IMPORT_CAPTURE_PATTERNS.iter() {
        for capture in pattern.captures_iter(&content) {
            if let Some(name) = capture
                .get(1)
                .and_then(|m| normalize_package_spec(m.as_str()))
            {
                names.insert(name);
            }
        }
    }
    names
}

pub(in crate::core::code_scan) fn normalize_package_spec(specifier: &str) -> Option<String> {
    let specifier = specifier.trim();
    if specifier.is_empty()
        || specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.starts_with("@/")
        || specifier.starts_with("~/")
        || specifier.starts_with('#')
        || specifier.starts_with('$')
        || specifier.starts_with("http://")
        || specifier.starts_with("https://")
        // Node builtins are never npm dependencies, regardless of whether
        // NODE_BUILTINS lists the exact name (e.g. `node:module`).
        || specifier.starts_with("node:")
    {
        return None;
    }

    // Scheme-prefixed virtual modules are not npm packages.
    if specifier
        .split('/')
        .next()
        .is_some_and(|head| head.contains(':'))
    {
        return None;
    }

    let package_name = if specifier.starts_with('@') {
        let mut segments = specifier.split('/');
        let scope = segments.next()?;
        let name = segments.next()?;
        format!("{}/{}", scope, name)
    } else {
        specifier.split('/').next()?.to_string()
    };

    if NODE_BUILTINS.iter().any(|builtin| *builtin == package_name) {
        return None;
    }

    if COMMON_INTERNAL_IMPORT_ROOTS
        .iter()
        .any(|candidate| *candidate == package_name)
        && specifier.contains('/')
    {
        return None;
    }

    Some(package_name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_framework_virtual_modules_and_node_builtins() {
        assert_eq!(normalize_package_spec("astro:content"), None);
        assert_eq!(normalize_package_spec("astro:middleware"), None);
        assert_eq!(normalize_package_spec("cloudflare:workers"), None);
        assert_eq!(normalize_package_spec("virtual:my-plugin"), None);
        assert_eq!(normalize_package_spec("node:module"), None);
        assert_eq!(normalize_package_spec("node:fs"), None);
        // Bare builtins (no `node:` prefix) must also be recognised -- these were
        // reported as undeclared on twenty/n8n.
        assert_eq!(normalize_package_spec("async_hooks"), None);
        assert_eq!(normalize_package_spec("worker_threads"), None);
        assert_eq!(normalize_package_spec("vm"), None);
        assert_eq!(normalize_package_spec("tls"), None);
        assert_eq!(normalize_package_spec("querystring"), None);
        assert_eq!(normalize_package_spec("perf_hooks"), None);
        // Subpath builtins reduce to their first segment.
        assert_eq!(normalize_package_spec("fs/promises"), None);
    }

    #[test]
    fn keeps_real_npm_packages() {
        assert_eq!(normalize_package_spec("preact"), Some("preact".to_string()));
        assert_eq!(
            normalize_package_spec("@astrojs/preact"),
            Some("@astrojs/preact".to_string())
        );
        assert_eq!(
            normalize_package_spec("react/jsx-runtime"),
            Some("react".to_string())
        );
    }

    fn source_file(content: &str) -> SourceFile {
        SourceFile {
            absolute_path: std::path::PathBuf::from("/tmp/sample.ts"),
            relative_path: "sample.ts".to_string(),
            content: content.to_string(),
            line_count: content.lines().count(),
            inline_rust_tests: false,
        }
    }

    #[test]
    fn ignores_import_keyword_inside_string_literal() {
        let file = source_file(
            "export function detectLanguage (code: string): string {\n  if (code.includes('import ') || code.includes('export ') || code.includes(': ')) return 'typescript'\n}\n",
        );
        let refs = collect_js_package_refs(std::slice::from_ref(&file));
        assert!(
            refs.is_empty(),
            "expected no package refs, got: {:?}",
            refs.iter().map(|r| &r.package_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn commented_out_imports_are_not_package_references() {
        let file = source_file(
            "/*\nimport ghost from \"ghost-package\";\nconst old = require(\"legacy-pkg\");\n*/\n// const gone = require(\"line-comment-pkg\");\nconst s = \"/* not a comment\";\nimport real from \"real-pkg\";\n",
        );
        let names = collect_js_package_refs(std::slice::from_ref(&file))
            .into_iter()
            .map(|r| r.package_name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["real-pkg".to_string()],
            "only the uncommented import counts (a string containing /* must not hide it)"
        );
    }

    #[test]
    fn still_detects_real_import_statements() {
        let file = source_file(
            "import { EditorView } from '@codemirror/view'\nimport express from 'express'\nconst pg = require('pg')\nconst mod = await import('lodash')\n",
        );
        let names = collect_js_package_refs(std::slice::from_ref(&file))
            .into_iter()
            .map(|r| r.package_name)
            .collect::<Vec<_>>();
        assert!(names.contains(&"@codemirror/view".to_string()), "{names:?}");
        assert!(names.contains(&"express".to_string()), "{names:?}");
        assert!(names.contains(&"pg".to_string()), "{names:?}");
        assert!(names.contains(&"lodash".to_string()), "{names:?}");
    }

    /// A file with no semicolons used to let the import scan run past the
    /// declaration and capture the next `from "..."` it met, wherever that
    /// was: inside a call argument, or inside an ordinary string.
    #[test]
    fn from_inside_a_string_literal_is_not_an_import() {
        let file = source_file(
            "import { useSearchParams } from 'next/navigation'\n\nexport function Form() {\n  const params = useSearchParams()\n  return params?.get(\"from\") || \"/dashboard\"\n}\n",
        );
        let names = collect_js_package_refs(std::slice::from_ref(&file))
            .into_iter()
            .map(|reference| reference.package_name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["next".to_string()]);
    }

    /// `export class X {` is not an export-from declaration, so a `from` in
    /// the class body's strings must not be read as its specifier.
    #[test]
    fn export_declarations_do_not_swallow_later_strings() {
        let file = source_file(
            "export class MiddlewareController {\n  hello() {\n    return 'Hello from \"MiddlewareController\"!'\n  }\n}\n",
        );
        let refs = collect_js_package_refs(std::slice::from_ref(&file));
        assert!(
            refs.is_empty(),
            "got: {:?}",
            refs.iter().map(|r| &r.package_name).collect::<Vec<_>>()
        );
    }

    /// A package name quoted in ordinary code (a config value, a message) is
    /// not a dynamic import of that package.
    #[test]
    fn package_names_quoted_in_ordinary_code_are_not_references() {
        let file = source_file(
            "const message = \"run require('ghost-pkg') to load\";\nconst target = 'pino-pretty';\nexport { message, target };\n",
        );
        let refs = collect_js_package_refs(std::slice::from_ref(&file));
        assert!(
            refs.is_empty(),
            "got: {:?}",
            refs.iter().map(|r| &r.package_name).collect::<Vec<_>>()
        );
    }

    /// Every declaration shape the clause pattern has to accept: bundled and
    /// minified sources drop the space after the keyword, and a type import
    /// keeps its own. The default type import is the shape a corpus re-audit
    /// caught going missing (cal.com `apps/api/v2/src/lib/logger.ts:4`).
    #[test]
    fn every_static_declaration_shape_is_captured() {
        let file = source_file(concat!(
            "import{createApp}from\"vue\"\n",
            "import*as path from\"pathe\"\n",
            "export*from\"zod\"\n",
            "export{z}from\"valibot\"\n",
            "import type Transport from \"winston-transport\";\n",
            "import type { LoggerOptions } from \"winston\";\n",
            "import type{Config}from\"jest\";\n",
            "import defaultExport, { named } from \"axios\";\n",
            "import * as React from \"react\";\n",
            "export type { Options } from \"tsup\";\n",
        ));
        let names = collect_js_package_refs(std::slice::from_ref(&file))
            .into_iter()
            .map(|reference| reference.package_name)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            names,
            [
                "vue",
                "pathe",
                "zod",
                "valibot",
                "winston-transport",
                "winston",
                "jest",
                "axios",
                "react",
                "tsup",
            ]
            .iter()
            .map(|name| name.to_string())
            .collect::<std::collections::HashSet<_>>()
        );
    }

    /// A declaration keyword is not an export-from clause.
    #[test]
    fn other_export_declarations_are_not_export_from_clauses() {
        let file = source_file(
            "export class Client {\n  url = 'https://example.com from \"ghost-pkg\"'\n}\nexport default Client\n",
        );
        let refs = collect_js_package_refs(std::slice::from_ref(&file));
        assert!(
            refs.is_empty(),
            "got: {:?}",
            refs.iter().map(|r| &r.package_name).collect::<Vec<_>>()
        );
    }

    /// A backtick the lexer misreads (inside a regex literal, say) has no
    /// closing partner and template literals span lines, so blanking from it
    /// would swallow every later import in the file.
    #[test]
    fn an_unpaired_quote_does_not_blank_the_rest_of_the_file() {
        let file = source_file(
            "const backtick = /[`]/\nconst apostrophe = <p>don't</p>\nimport pkg from \"lodash\";\nconst late = require(\"pg\");\n",
        );
        let names = collect_js_package_refs(std::slice::from_ref(&file))
            .into_iter()
            .map(|reference| reference.package_name)
            .collect::<std::collections::HashSet<_>>();
        assert!(names.contains("lodash"), "{names:?}");
        assert!(names.contains("pg"), "{names:?}");
    }

    #[test]
    fn specifier_strings_survive_blanking_and_keep_byte_offsets() {
        let source = "const label = \"from lodash\";\nimport pkg from \"lodash\";\n";
        let blanked = blank_non_specifier_strings(source);
        assert_eq!(blanked.len(), source.len());
        assert!(blanked.contains("\"lodash\""), "{blanked}");
        assert!(!blanked.contains("from lodash"), "{blanked}");
        // Line structure is preserved so `(?m)` anchors still line up.
        assert_eq!(blanked.lines().count(), source.lines().count());
    }

    #[test]
    fn detects_multiline_imports_and_package_re_exports() {
        let file = source_file(
            "import {\n  createTransport,\n  type Envelope,\n} from '@sentry/core';\nexport { captureException }\n  from \"@sentry/browser\";\nexport * from 'zod';\n",
        );
        let names = collect_js_package_refs(std::slice::from_ref(&file))
            .into_iter()
            .map(|reference| reference.package_name)
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(
            names,
            std::collections::HashSet::from([
                "@sentry/core".to_string(),
                "@sentry/browser".to_string(),
                "zod".to_string(),
            ])
        );
    }
}
