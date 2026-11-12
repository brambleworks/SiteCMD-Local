use std::sync::LazyLock;

// Node.js built-ins excluded from undeclared-dependency findings.
pub(in crate::core::code_scan) static NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

pub(in crate::core::code_scan) static COMMON_INTERNAL_IMPORT_ROOTS: &[&str] = &[
    "app",
    "assets",
    "client",
    "components",
    "core",
    "features",
    "hooks",
    "lib",
    "pages",
    "server",
    "shared",
    "src",
    "stores",
    "styles",
    "utils",
];

pub(in crate::core::code_scan) static POPULAR_PACKAGE_NAMES: &[&str] = &[
    "openai",
    "anthropic",
    "react",
    "next",
    "express",
    "supabase",
    "stripe",
    "axios",
    "zod",
    "prisma",
    "jsonwebtoken",
    "lodash",
    "@prisma/client",
    "@supabase/supabase-js",
    "drizzle-orm",
];

/// Legitimate package basenames excluded from near-name typo-squat findings.
pub(in crate::core::code_scan) static KNOWN_GOOD_PACKAGE_BASENAMES: &[&str] =
    &["preact", "nuxt", "nest"];

pub(in crate::core::code_scan) static SUPPORTED_NPM_LOCKFILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
];

pub(in crate::core::code_scan) static IMPORT_CAPTURE_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            // Side-effect imports have no `from` clause.
            regex::Regex::new(r#"(?m)^[\t ]*import[\t ]*["']([^"']+)["']"#)
                .expect("static side-effect import regex"), // allow-expect: compile-time literal regex
            // Static import/export-from declarations may span multiple lines,
            // so the clause between the keyword and `from` is spelled out
            // instead of "anything up to the next semicolon": a run-on match
            // used to reach past the declaration and capture a `from "..."`
            // that belonged to a string literal further down the file.
            // Each clause shape carries its own separator: a brace or star
            // needs no space after the keyword, because bundled and minified
            // sources write `import{a}from"x"` and `export*from"x"`, while a
            // bare identifier needs one so `import type X from "pkg"` and
            // `import pkg from "x"` both keep their clause intact.
            regex::Regex::new(
                r#"(?ms)^[\t ]*import(?:\s*\{[^{}]*\}|\s*\*\s*as\s+[\w$]+|\s+type\s*\{[^{}]*\}|\s+type\s*\*\s*as\s+[\w$]+|\s+(?:type\s+)?[\w$]+(?:\s*,\s*(?:\{[^{}]*\}|\*\s*as\s+[\w$]+))?)\s*from\s*["']([^"']+)["']"#,
            )
            .expect("static import-from regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(
                r#"(?ms)^[\t ]*export(?:\s*\{[^{}]*\}|\s*\*(?:\s*as\s+[\w$]+)?|\s+type\s*\{[^{}]*\}|\s+type\s*\*(?:\s*as\s+[\w$]+)?)\s*from\s*["']([^"']+)["']"#,
            )
            .expect("static export-from regex"), // allow-expect: compile-time literal regex
            // Dynamic forms can appear mid-expression, so they stay unanchored,
            // but a word boundary keeps `require(`/`import(` from matching when
            // glued onto an identifier (e.g. `myrequire(`).
            regex::Regex::new(r#"\brequire\(\s*["']([^"']+)["']\s*\)"#).unwrap(),
            regex::Regex::new(r#"\bimport\(\s*["']([^"']+)["']\s*\)"#).unwrap(),
            // A resolved module path reads the package as surely as `require`
            // does, and may take an options argument after the specifier.
            regex::Regex::new(r#"\brequire\.resolve\(\s*["']([^"']+)["']\s*[,)]"#)
                .expect("static require.resolve regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r#"\bimport\.meta\.resolve\(\s*["']([^"']+)["']\s*[,)]"#)
                .expect("static import.meta.resolve regex"), // allow-expect: compile-time literal regex
        ]
    });

/// Value-shaped credential formats: the matched text is itself a provider
/// token (sk-, sk-ant-, ghp_, AIza...). A match is a direct structural fact,
/// so `config-secret` keeps High confidence for these.
pub(in crate::core::code_scan) static MCP_SECRET_VALUE_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r#"sk-[A-Za-z0-9_-]{20,}"#).unwrap(),
            regex::Regex::new(r#"sk-ant-[A-Za-z0-9_-]{20,}"#).unwrap(),
            regex::Regex::new(r#"ghp_[A-Za-z0-9]{20,}"#).unwrap(),
            regex::Regex::new(r#"AIza[0-9A-Za-z\-_]{20,}"#).unwrap(),
        ]
    });

/// Secret-like name/value heuristic; callers downgrade unverified matches.
pub(in crate::core::code_scan) static MCP_SECRET_NAME_VALUE_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| {
        regex::Regex::new(r#"(?i)["']?(api[_-]?key|access[_-]?token|auth[_-]?token|secret)["']?\s*[:=]\s*["'][^"'\n]{8,}["']"#).unwrap()
    });

/// Combined set for consumers that only need "does any credential pattern
/// match" (agent-instructions-secret, which always ships NeedsReview).
pub(in crate::core::code_scan) static MCP_SECRET_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        let mut patterns = MCP_SECRET_VALUE_PATTERNS.clone();
        patterns.push(MCP_SECRET_NAME_VALUE_PATTERN.clone());
        patterns
    });
