use crate::core::database_targets::{is_mysql_database_target, validate_local_database_target};
use sitecmd_protocol::database_env::{
    is_local_dev_env_file, looks_like_database_url_key, looks_like_literal_database_url,
    EnvFileSnapshot,
};

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

pub(in crate::core) fn summarize_remote_local_dev_database_targets(
    env_files: &[EnvFileSnapshot],
) -> Option<(&EnvFileSnapshot, String)> {
    let mut findings = Vec::new();

    for file in env_files
        .iter()
        .filter(|file| is_local_dev_env_file(&file.relative_path))
    {
        for (key, value) in file.entries_in_order() {
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

#[cfg(test)]
mod tests {
    use crate::core::database_targets::env::summarize_remote_local_dev_database_targets;
    use sitecmd_protocol::database_env::parse_env_file;

    #[test]
    fn remote_database_summaries_follow_declaration_order() {
        // Iterating the lookup map can reorder remote database declarations.
        let first = "PRIMARY_DATABASE_URL=postgres://user:pw@first.example/db";
        let second = "REPLICA_DATABASE_URL=postgres://user:pw@second.example/db";
        let forward = parse_env_file(
            ".env.local".into(),
            ".env.local".into(),
            format!("{first}\n{second}"),
        )
        .unwrap();
        let mut reverse = forward.clone();
        reverse.content = format!("{second}\n{first}");

        let first_summary = ".env.local defines PRIMARY_DATABASE_URL -> postgres://first.example";
        let second_summary = ".env.local defines REPLICA_DATABASE_URL -> postgres://second.example";
        for (file, expected) in [
            (forward, format!("{first_summary}; {second_summary}")),
            (reverse, format!("{second_summary}; {first_summary}")),
        ] {
            let (_, summary) = summarize_remote_local_dev_database_targets(&[file]).unwrap();
            assert_eq!(summary, expected);
        }
    }
}
