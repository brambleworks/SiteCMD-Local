//! Pure dotenv parsing and database declaration recognition.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EnvFileSnapshot {
    pub absolute_path: PathBuf,
    pub relative_path: String,
    pub content: String,
    pub keys: HashSet<String>,
    pub entries: HashMap<String, String>,
}

impl EnvFileSnapshot {
    /// Yield each key at its first declaration with its effective value.
    pub fn entries_in_order(&self) -> impl Iterator<Item = (&str, &str)> {
        let mut seen = HashSet::new();
        self.content
            .lines()
            .filter_map(parse_entry)
            .filter(move |(key, _)| seen.insert(*key))
            .filter_map(|(key, _)| Some((key, self.entries.get(key)?.as_str())))
    }
}

pub fn parse_env_file(
    absolute_path: PathBuf,
    relative_path: String,
    content: String,
) -> Option<EnvFileSnapshot> {
    let entries = parse_env_entries(&content);
    if entries.is_empty() {
        return None;
    }
    let keys = entries.keys().cloned().collect();
    Some(EnvFileSnapshot {
        absolute_path,
        relative_path,
        content,
        keys,
        entries,
    })
}

fn parse_env_entries(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(parse_entry)
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn parse_entry(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let (key, value) = trimmed.split_once('=')?;
    let key = key.trim();
    (key.chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then_some((key, value.trim()))
}

pub fn is_example_env_file(relative_path: &str) -> bool {
    let normalized = relative_path.to_ascii_lowercase();
    normalized.ends_with("/.env.example")
        || normalized == ".env.example"
        || normalized.ends_with("/.env.sample")
        || normalized == ".env.sample"
        || normalized.ends_with("/.env.template")
        || normalized == ".env.template"
}

pub fn is_local_dev_env_file(relative_path: &str) -> bool {
    let normalized = relative_path.to_ascii_lowercase();
    normalized.ends_with(".env")
        || normalized.ends_with(".env.local")
        || normalized.ends_with(".env.development")
        || normalized.ends_with(".env.development.local")
        || normalized.ends_with(".env.test")
        || normalized.ends_with(".env.test.local")
}

/// Whether a file name identifies a private dotenv input.
pub fn is_private_dotenv(name: &str) -> bool {
    name.get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".env"))
        && is_local_dev_env_file(name)
}

pub fn looks_like_database_url_key(key: &str) -> bool {
    let normalized = key.to_ascii_uppercase();
    normalized == "DATABASE_URL"
        || normalized == "DIRECT_URL"
        || normalized == "SHADOW_DATABASE_URL"
        || normalized.ends_with("_DATABASE_URL")
        || normalized.ends_with("_DB_URL")
        || normalized.ends_with("_POSTGRES_URL")
        || normalized.ends_with("_MYSQL_URL")
}

pub fn looks_like_literal_database_url(value: &str) -> bool {
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
