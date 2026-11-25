//! Public runtime build configuration.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

const BAKED_ENVS: &[&str] = &["SITECMD_CONNECTED_ENDPOINT"];

fn repo_env_file(source_root: &Path) -> Option<PathBuf> {
    let mut path = source_root.to_path_buf();
    for _ in 0..3 {
        path.pop();
    }
    path.push(".env");
    // Cargo treats a missing watched file as dirty on every build.
    path.is_file().then_some(path)
}

fn parse_dotenv_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return None;
    }

    let raw_value = value.trim();
    let mut value = raw_value.to_string();
    if raw_value.len() >= 2 {
        let starts_with_single = raw_value.starts_with('\'') && raw_value.ends_with('\'');
        let starts_with_double = raw_value.starts_with('"') && raw_value.ends_with('"');
        if starts_with_single || starts_with_double {
            value = raw_value[1..raw_value.len() - 1].to_string();
        } else if let Some((before_comment, _)) = raw_value.split_once(" #") {
            value = before_comment.trim_end().to_string();
        }
    }

    Some((key.to_string(), value))
}

fn load_dotenv_values(path: &Path) -> HashMap<String, String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.lines().filter_map(parse_dotenv_line).collect())
        .unwrap_or_default()
}

fn config_value(key: &str, dotenv: &HashMap<String, String>) -> Option<String> {
    std::env::var(key)
        .ok()
        .or_else(|| dotenv.get(key).cloned())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn expose_dotenv_fallbacks(dotenv: &HashMap<String, String>) {
    for key in BAKED_ENVS {
        if std::env::var(key).is_err() {
            if let Some(value) = config_value(key, dotenv) {
                println!("cargo:rustc-env={key}={value}");
            }
        }
    }
}

pub fn configure_runtime(source_root: &Path) {
    println!(
        "cargo:rustc-env=SITECMD_SOURCE_ROOT={}",
        source_root.display()
    );
    let env_file = repo_env_file(source_root);
    if let Some(path) = &env_file {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let dotenv = env_file
        .as_deref()
        .map(load_dotenv_values)
        .unwrap_or_default();

    for key in BAKED_ENVS {
        println!("cargo:rerun-if-env-changed={key}");
    }
    expose_dotenv_fallbacks(&dotenv);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_optional_dotenv_is_only_watched_when_it_exists() {
        // Bug: Watching a missing dotenv makes clean checkouts rebuild on every command.
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("apps/desktop/src-tauri");
        fs::create_dir_all(&source).unwrap();
        let dotenv = root.path().join(".env");

        assert_eq!(repo_env_file(&source), None);
        fs::write(
            &dotenv,
            "SITECMD_CONNECTED_ENDPOINT=https://connect.sitecmd.com",
        )
        .unwrap();
        assert_eq!(repo_env_file(&source), Some(dotenv.clone()));
        fs::remove_file(&dotenv).unwrap();
        assert_eq!(repo_env_file(&source), None);
    }
}
