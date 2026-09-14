//! Public configuration shared by the desktop and headless runtime builds.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

const NUMERIC_LICENSE_CONFIG_ENVS: &[&str] = &[
    "SITECMD_LICENSE_STORE_ID",
    "SITECMD_LICENSE_CORE_MONTHLY_VARIANT_ID",
    "SITECMD_LICENSE_CORE_ANNUAL_VARIANT_ID",
    "SITECMD_LICENSE_PRO_MONTHLY_VARIANT_ID",
    "SITECMD_LICENSE_PRO_ANNUAL_VARIANT_ID",
];

const CHECKOUT_URL_ENVS: &[&str] = &[
    "SITECMD_LICENSE_CORE_CHECKOUT_URL",
    "SITECMD_LICENSE_PRO_CHECKOUT_URL",
];

// Bake optional public connected-service configuration into release binaries.
const OPTIONAL_BAKED_ENVS: &[&str] = &[
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GITHUB_CLIENT_ID",
    "SITECMD_CONNECTED_ENDPOINT",
    "VITE_SITECMD_SENTRY_DSN",
];

const REQUIRE_LICENSE_CONFIG_ENV: &str = "SITECMD_REQUIRE_LICENSE_CONFIG";
const CHECKOUT_URL_PREFIX: &str = "https://shop.sitecmd.com/checkout/buy/";

fn repo_env_file(source_root: &Path) -> Option<PathBuf> {
    let mut path = source_root.to_path_buf();
    for _ in 0..3 {
        path.pop();
    }
    path.push(".env");
    Some(path)
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
    for key in NUMERIC_LICENSE_CONFIG_ENVS
        .iter()
        .chain(CHECKOUT_URL_ENVS.iter())
        .chain(OPTIONAL_BAKED_ENVS.iter())
    {
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
        .as_ref()
        .filter(|path| path.exists())
        .map(|path| load_dotenv_values(path))
        .unwrap_or_default();

    for key in NUMERIC_LICENSE_CONFIG_ENVS
        .iter()
        .chain(CHECKOUT_URL_ENVS.iter())
        .chain(OPTIONAL_BAKED_ENVS.iter())
    {
        println!("cargo:rerun-if-env-changed={key}");
    }
    println!("cargo:rerun-if-env-changed={REQUIRE_LICENSE_CONFIG_ENV}");
    expose_dotenv_fallbacks(&dotenv);

    if config_value(REQUIRE_LICENSE_CONFIG_ENV, &dotenv).as_deref() == Some("1") {
        let mut missing_or_invalid: Vec<_> = NUMERIC_LICENSE_CONFIG_ENVS
            .iter()
            .filter(|key| {
                config_value(key, &dotenv)
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none_or(|value| value == 0)
            })
            .copied()
            .collect();

        missing_or_invalid.extend(
            CHECKOUT_URL_ENVS
                .iter()
                .filter(|key| {
                    config_value(key, &dotenv).is_none_or(|value| {
                        let value = value.trim();
                        value.is_empty() || !value.starts_with(CHECKOUT_URL_PREFIX)
                    })
                })
                .copied(),
        );

        if !missing_or_invalid.is_empty() {
            panic!(
                "release builds require real LemonSqueezy config; missing/invalid env vars: {}",
                missing_or_invalid.join(", ")
            );
        }
    }
}
