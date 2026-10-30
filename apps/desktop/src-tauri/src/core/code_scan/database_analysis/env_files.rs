use super::*;

pub(in crate::core::code_scan) fn collect_source_env_keys_from_file(
    file: &SourceFile,
) -> HashSet<String> {
    collect_source_env_keys_with_build(file, None)
}

pub(super) fn collect_source_env_keys_with_build(
    file: &SourceFile,
    injected: Option<&HashSet<String>>,
) -> HashSet<String> {
    let path = Path::new(&file.relative_path);
    let is_rust = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
    let content = &file.content;
    let structure = super::super::file_analysis::blank_non_code_for_env(file);
    let mut keys = HashSet::new();
    for pattern in SOURCE_ENV_KEY_PATTERNS.iter() {
        for capture in pattern.captures_iter(content) {
            let Some(full_match) = capture.get(0) else {
                continue;
            };
            if structure
                .as_bytes()
                .get(full_match.start())
                .is_none_or(u8::is_ascii_whitespace)
            {
                continue;
            }
            let Some(key) = capture
                .iter()
                .skip(1)
                .flatten()
                .next()
                .map(|value| value.as_str().trim())
            else {
                continue;
            };
            let compile_time = is_rust
                && (full_match.as_str().starts_with("env!")
                    || full_match.as_str().starts_with("option_env!"));
            if compile_time && injected.is_some_and(|keys| keys.contains(key)) {
                continue;
            }
            if !key.is_empty() {
                keys.insert(key.to_string());
            }
        }
    }
    keys
}

#[cfg(test)]
mod source_env_key_tests {
    use super::collect_source_env_keys_from_file;
    use crate::core::code_scan::filesystem::SourceFile;
    use std::path::PathBuf;

    fn source_file(relative_path: &str, content: &str) -> SourceFile {
        SourceFile {
            absolute_path: PathBuf::from(relative_path),
            relative_path: relative_path.to_string(),
            line_count: content.lines().count(),
            inline_rust_tests: false,
            content: content.to_string(),
        }
    }

    #[test]
    fn rust_env_read_after_quote_characters_is_executable() {
        for literal in [r#"'"'"#, r#"'\"'"#, r#"b'"'"#] {
            let content = format!("fn start() {{ let _ = {literal}; let _ = std::env::var(\"RUNTIME_AFTER_QUOTE\"); }}");
            let keys = collect_source_env_keys_from_file(&source_file("src/lib.rs", &content));
            assert!(keys.contains("RUNTIME_AFTER_QUOTE"), "{literal}: {keys:?}");
        }
    }

    #[test]
    fn extracts_supported_executable_env_access_forms() {
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "app.ts",
                "const a = process.env.API_URL;\nconst b = process.env['AUTH_TOKEN'];",
                &["API_URL", "AUTH_TOKEN"],
            ),
            (
                "vite.ts",
                "const a = import.meta.env.VITE_API_URL;\nconst b = import.meta.env['VITE_AUTH_TOKEN'];",
                &["VITE_API_URL", "VITE_AUTH_TOKEN"],
            ),
            (
                "deno.ts",
                "const token = Deno.env.get('DENO_TOKEN');",
                &["DENO_TOKEN"],
            ),
            (
                "main.rs",
                "let a = std::env::var(\"RUST_VALUE\");\nlet b = option_env!(\"RUST_OPTIONAL\");",
                &["RUST_VALUE", "RUST_OPTIONAL"],
            ),
            (
                "app.py",
                "a = os.getenv('PYTHON_VALUE')\nb = os.environ.get('PYTHON_OTHER')\nc = os.environ['PYTHON_REQUIRED']",
                &["PYTHON_VALUE", "PYTHON_OTHER", "PYTHON_REQUIRED"],
            ),
            (
                "main.go",
                "value := os.Getenv(\"GO_VALUE\")",
                &["GO_VALUE"],
            ),
            (
                "app.rb",
                "value = ENV.fetch('RUBY_VALUE')\nother = ENV['RUBY_OTHER']",
                &["RUBY_VALUE", "RUBY_OTHER"],
            ),
            (
                "App.java",
                "String value = System.getenv(\"JAVA_VALUE\");",
                &["JAVA_VALUE"],
            ),
            (
                "App.cs",
                "var value = Environment.GetEnvironmentVariable(\"DOTNET_VALUE\");",
                &["DOTNET_VALUE"],
            ),
            (
                "schema.prisma",
                "url = env(\"DATABASE_URL\")",
                &["DATABASE_URL"],
            ),
        ];

        for (path, content, expected) in cases {
            let keys = collect_source_env_keys_from_file(&source_file(path, content));
            for key in *expected {
                assert!(keys.contains(*key), "expected {key} from {path}: {keys:?}");
            }
        }
    }

    #[test]
    fn ignores_env_access_syntax_inside_comments_and_code_example_strings() {
        let typescript = source_file(
            "fix-guide.ts",
            r#"
// process.env.COMMENTED_KEY
const guide = "Replace process.env.QUOTED_KEY before release";
const sample = `Deno.env.get('TEMPLATE_SAMPLE')`;
/* import.meta.env.BLOCK_COMMENT_KEY */
"#,
        );
        let rust = source_file(
            "scanner.rs",
            r##"
// std::env::var("COMMENTED_RUST_KEY")
const GUIDE: &str = r#"Use std::env::var("QUOTED_RUST_KEY")"#;
"##,
        );

        assert!(collect_source_env_keys_from_file(&typescript).is_empty());
        assert!(collect_source_env_keys_from_file(&rust).is_empty());
    }
}

pub(in crate::core::code_scan) fn collect_env_files(
    project_files: &[ProjectFile],
    include_local_values: bool,
    text_budget: &mut ScanTextBudget<'_>,
) -> Result<Vec<EnvFileSnapshot>, CodeScanError> {
    let mut env_files = Vec::new();
    for file in project_files {
        text_budget.check_cancelled()?;
        let Some(file_name) = file.absolute_path.file_name() else {
            continue;
        };
        if !file_name.to_string_lossy().starts_with(".env")
            || file.size > 64_000
            || (!include_local_values && !is_example_env_file(&file.relative_path))
        {
            continue;
        }
        let Some(content) = text_budget.read_project_file(file, 64_000)? else {
            continue;
        };
        let entries = parse_env_entries(&content);
        if entries.is_empty() {
            continue;
        }
        let keys = entries.keys().cloned().collect::<HashSet<_>>();

        env_files.push(EnvFileSnapshot {
            absolute_path: file.absolute_path.clone(),
            relative_path: file.relative_path.clone(),
            content,
            keys,
            entries,
        });
    }
    Ok(env_files)
}

fn parse_env_entries(content: &str) -> HashMap<String, String> {
    let mut entries = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        if key
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
            && key
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            entries.insert(key.to_string(), value.trim().to_string());
        }
    }
    entries
}

pub(in crate::core::code_scan) fn is_example_env_file(relative_path: &str) -> bool {
    let normalized = relative_path.to_ascii_lowercase();
    normalized.ends_with("/.env.example")
        || normalized == ".env.example"
        || normalized.ends_with("/.env.sample")
        || normalized == ".env.sample"
        || normalized.ends_with("/.env.template")
        || normalized == ".env.template"
}

/// Return whether an env file is a peer deployment environment.
/// Base and `*.local` files are layered configuration and are not compared.
fn is_environment_parallel_env_file(relative_path: &str) -> bool {
    let normalized = relative_path.to_ascii_lowercase();
    if normalized.ends_with(".local") {
        return false;
    }
    normalized.ends_with(".env.production")
        || normalized.ends_with(".env.staging")
        || normalized.ends_with(".env.development")
        || normalized.ends_with(".env.preview")
}

pub(in crate::core::code_scan) fn is_local_dev_env_file(relative_path: &str) -> bool {
    let normalized = relative_path.to_ascii_lowercase();
    normalized.ends_with(".env")
        || normalized.ends_with(".env.local")
        || normalized.ends_with(".env.development")
        || normalized.ends_with(".env.development.local")
        || normalized.ends_with(".env.test")
        || normalized.ends_with(".env.test.local")
}

pub(in crate::core::code_scan) fn looks_like_database_url_key(key: &str) -> bool {
    let normalized = key.to_ascii_uppercase();
    normalized == "DATABASE_URL"
        || normalized == "DIRECT_URL"
        || normalized == "SHADOW_DATABASE_URL"
        || normalized.ends_with("_DATABASE_URL")
        || normalized.ends_with("_DB_URL")
        || normalized.ends_with("_POSTGRES_URL")
        || normalized.ends_with("_MYSQL_URL")
}

pub(in crate::core::code_scan) fn looks_like_literal_database_url(value: &str) -> bool {
    let normalized = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    normalized == ":memory:"
        || normalized.starts_with("postgres://")
        || normalized.starts_with("postgresql://")
        || normalized.starts_with("mysql://")
        || normalized.starts_with("mysql2://")
        || normalized.starts_with("mariadb://")
        || normalized.starts_with("sqlite:")
        || normalized.starts_with("file:")
}

fn summarize_database_target(value: &str) -> String {
    let normalized = value.trim().trim_matches('"').trim_matches('\'');
    if normalized.eq_ignore_ascii_case(":memory:") {
        return "sqlite::memory:".into();
    }

    if normalized.to_ascii_lowercase().starts_with("file:") {
        return "sqlite file".into();
    }

    if normalized.to_ascii_lowercase().starts_with("sqlite:") {
        return "sqlite target".into();
    }

    if let Ok(url) = url::Url::parse(normalized) {
        if let Some(host) = url.host_str() {
            return format!("{}://{}", url.scheme(), host);
        }

        if let Some(socket_host) = url
            .query_pairs()
            .find_map(|(key, value)| (key == "host").then(|| value.into_owned()))
        {
            if socket_host.starts_with('/') {
                return format!("{} via unix socket", url.scheme());
            }
        }

        return url.scheme().to_string();
    }

    "database target".into()
}

pub(in crate::core::code_scan) fn summarize_remote_local_dev_database_targets(
    env_files: &[EnvFileSnapshot],
) -> Option<(&EnvFileSnapshot, String)> {
    let mut findings = Vec::new();

    for file in env_files
        .iter()
        .filter(|file| is_local_dev_env_file(&file.relative_path))
    {
        for (key, value) in &file.entries {
            if !looks_like_database_url_key(key) || !looks_like_literal_database_url(value) {
                continue;
            }

            if is_mysql_database_target(value) {
                continue;
            }

            if validate_local_database_target(value).is_err()
                && !looks_like_container_service_host(value)
            {
                findings.push((
                    file,
                    format!(
                        "{} defines {} -> {}",
                        file.relative_path,
                        key,
                        summarize_database_target(value)
                    ),
                ));
            }
        }
    }

    if findings.is_empty() {
        return None;
    }

    let anchor = findings[0].0;
    let summary = findings
        .iter()
        .map(|(_, detail)| detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    Some((anchor, summary))
}

/// Recognize single-label container DNS hosts as local infrastructure.
/// The deep-scan connection gate still requires loopback.
fn looks_like_container_service_host(value: &str) -> bool {
    let normalized = value.trim().trim_matches('"').trim_matches('\'');
    let Ok(url) = url::Url::parse(normalized) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    !host.is_empty() && !host.contains('.') && !host.contains(':')
}

pub(in crate::core::code_scan) fn summarize_env_drift<'a>(
    env_files: &'a [EnvFileSnapshot],
    source_env_keys: &HashSet<String>,
) -> Vec<(&'a EnvFileSnapshot, String)> {
    let mut groups = std::collections::BTreeMap::<&str, Vec<&EnvFileSnapshot>>::new();
    for file in env_files
        .iter()
        .filter(|file| is_environment_parallel_env_file(&file.relative_path))
    {
        let scope = file
            .relative_path
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .unwrap_or("");
        groups.entry(scope).or_default().push(file);
    }

    let mut summaries = Vec::new();
    for runtime_envs in groups.values_mut() {
        runtime_envs.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if runtime_envs.len() < 2 {
            continue;
        }

        let mut relevant_keys = source_env_keys.clone();
        if relevant_keys.is_empty() {
            for file in runtime_envs.iter() {
                for key in &file.keys {
                    if looks_sensitive_env_key(key) {
                        relevant_keys.insert(key.clone());
                    }
                }
            }
        }
        let mut relevant_keys = relevant_keys.into_iter().collect::<Vec<_>>();
        relevant_keys.sort_unstable();

        let mut mismatches = Vec::new();
        for key in &relevant_keys {
            let present_in = runtime_envs
                .iter()
                .filter(|file| file.keys.contains(key))
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>();
            if present_in.is_empty() || present_in.len() == runtime_envs.len() {
                continue;
            }
            let missing_in = runtime_envs
                .iter()
                .filter(|file| !file.keys.contains(key))
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>();
            mismatches.push(format!(
                "{} present in {} but missing from {}",
                key,
                present_in.join(", "),
                missing_in.join(", ")
            ));
        }

        if !mismatches.is_empty() {
            summaries.push((
                runtime_envs[0],
                mismatches
                    .into_iter()
                    .take(4)
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
    }
    summaries
}

pub(in crate::core::code_scan) fn looks_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "SECRET",
        "TOKEN",
        "KEY",
        "DATABASE",
        "PASSWORD",
        "AUTH",
        "OPENAI",
        "ANTHROPIC",
        "STRIPE",
        "SUPABASE",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

pub(in crate::core::code_scan) fn format_key_list(keys: &[String]) -> String {
    // Announce truncation so the evidence does not imply a complete list.
    const MAX_LISTED_KEYS: usize = 6;
    let mut listed = keys
        .iter()
        .take(MAX_LISTED_KEYS)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if keys.len() > MAX_LISTED_KEYS {
        listed.push_str(&format!(", and {} more", keys.len() - MAX_LISTED_KEYS));
    }
    listed
}

#[cfg(test)]
mod format_key_list_tests {
    use super::format_key_list;

    #[test]
    fn key_list_truncation_is_announced() {
        let keys: Vec<String> = (1..=8).map(|index| format!("KEY_{index}")).collect();
        assert_eq!(
            format_key_list(&keys),
            "KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, and 2 more"
        );
        // Short lists stay untouched.
        assert_eq!(format_key_list(&["A".to_string(), "B".to_string()]), "A, B");
    }
}
