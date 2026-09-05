use super::{IntegrationConfig, IntegrationType};

const MAX_API_KEY_CHARS: usize = 16 * 1024;
const MAX_SITE_ID_CHARS: usize = 2_048;
const MAX_EXTRA_BYTES: usize = 64 * 1024;
const MAX_GITHUB_OWNER_CHARS: usize = 100;
const MAX_GITHUB_REPOSITORY_CHARS: usize = 100;
const MAX_JIRA_EMAIL_CHARS: usize = 254;
const MAX_JIRA_ISSUE_TYPE_CHARS: usize = 100;

fn bounded_text(value: &str, label: &str, max_chars: usize) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > max_chars
        || trimmed.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} is empty, too long, or contains control characters."
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_github_path_component(
    value: &str,
    label: &str,
    max_chars: usize,
    owner: bool,
) -> Result<(), String> {
    if value.is_empty() || value == "." || value == ".." || value.chars().count() > max_chars {
        return Err(format!("GitHub {label} is invalid."));
    }
    let valid = value.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || character == '-'
            || (!owner && matches!(character, '_' | '.'))
    });
    if !valid {
        return Err(format!("GitHub {label} contains invalid characters."));
    }
    Ok(())
}

/// Validate and normalize the `owner/repository` token used inside GitHub API
/// paths. Keeping this as a path-safe token prevents stored configuration from
/// injecting extra path segments, query strings, or fragments.
pub fn normalize_github_repo_slug(value: &str) -> Result<String, String> {
    let slug = bounded_text(
        value,
        "GitHub repository",
        MAX_GITHUB_OWNER_CHARS + MAX_GITHUB_REPOSITORY_CHARS + 1,
    )?;
    let mut parts = slug.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err("GitHub repository must use exactly owner/repository.".to_string());
    }
    validate_github_path_component(owner, "owner", MAX_GITHUB_OWNER_CHARS, true)?;
    validate_github_path_component(repository, "repository", MAX_GITHUB_REPOSITORY_CHARS, false)?;
    Ok(format!("{owner}/{repository}"))
}

pub fn split_github_repo_slug(value: &str) -> Result<(String, String), String> {
    let normalized = normalize_github_repo_slug(value)?;
    let (owner, repository) = normalized
        .split_once('/')
        .ok_or("GitHub repository must use owner/repository.")?;
    Ok((owner.to_string(), repository.to_string()))
}

/// Accept a plain Jira Cloud hostname or an HTTPS origin and normalize it to a
/// lowercase `*.atlassian.net` hostname. Paths, ports, credentials, queries,
/// fragments, IP literals, and non-HTTPS schemes are rejected.
pub fn normalize_jira_cloud_host(value: &str) -> Result<String, String> {
    let value = bounded_text(value, "Jira Cloud tenant", MAX_SITE_ID_CHARS)?;
    let candidate = if value.contains("://") {
        value
    } else {
        format!("https://{value}")
    };
    let parsed =
        url::Url::parse(&candidate).map_err(|_| "Jira Cloud tenant URL is invalid.".to_string())?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "Jira Cloud tenant must be an HTTPS atlassian.net origin without a path or port."
                .to_string(),
        );
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => return Err("Jira Cloud tenant must use an atlassian.net hostname.".to_string()),
    };
    if host == "atlassian.net"
        || !host.ends_with(".atlassian.net")
        || host.trim_end_matches(".atlassian.net").is_empty()
    {
        return Err("Jira Cloud tenant must end in .atlassian.net.".to_string());
    }
    Ok(host)
}

pub fn normalize_jira_email(value: &str) -> Result<String, String> {
    let email = bounded_text(value, "Jira account email", MAX_JIRA_EMAIL_CHARS)?;
    let (local, domain) = email
        .rsplit_once('@')
        .ok_or("Jira account email is invalid.")?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || !domain
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
    {
        return Err("Jira account email is invalid.".to_string());
    }
    Ok(email)
}

pub fn jira_email_domain(value: &str) -> String {
    let domain = value
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .filter(|domain| !domain.is_empty() && !domain.chars().any(char::is_control))
        .unwrap_or("invalid");
    domain
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
        .take(120)
        .collect()
}

pub fn normalize_jira_project_key(value: &str) -> Result<String, String> {
    let key = bounded_text(value, "Jira project key", 10)?.to_ascii_uppercase();
    let mut characters = key.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_uppercase())
        || !characters.all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
    {
        return Err(
            "Jira project key must start with a letter and contain only letters and digits."
                .to_string(),
        );
    }
    Ok(key)
}

pub fn normalize_jira_issue_type(value: &str) -> Result<String, String> {
    bounded_text(value, "Jira issue type", MAX_JIRA_ISSUE_TYPE_CHARS)
}

pub fn validate_jira_issue_key(value: &str) -> Result<String, String> {
    let key = bounded_text(value, "Jira issue key", 32)?;
    let (project, issue_number) = key.rsplit_once('-').ok_or("Jira issue key is invalid.")?;
    if project.is_empty()
        || !project
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
        || issue_number.is_empty()
        || !issue_number
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err("Jira issue key is invalid.".to_string());
    }
    Ok(key)
}

/// Validate renderer-supplied integration settings before they can influence
/// secure storage or a later credentialed request.
pub fn validate_and_normalize_config(
    config: &IntegrationConfig,
) -> Result<IntegrationConfig, String> {
    let mut normalized = config.clone();

    if let Some(api_key) = normalized.api_key.as_deref() {
        let api_key = bounded_text(api_key, "Integration credential", MAX_API_KEY_CHARS)?;
        if api_key == crate::constants::KEYRING_PLACEHOLDER {
            return Err(
                "Integration credentials must be entered directly when saving.".to_string(),
            );
        }
        normalized.api_key = Some(api_key);
    }
    if let Some(site_id) = normalized.site_id.as_deref() {
        normalized.site_id = Some(bounded_text(
            site_id,
            "Integration site identifier",
            MAX_SITE_ID_CHARS,
        )?);
    }
    if let Some(extra) = normalized.extra.as_ref() {
        let bytes = serde_json::to_vec(extra)
            .map_err(|_| "Integration settings could not be serialized.".to_string())?;
        if bytes.len() > MAX_EXTRA_BYTES {
            return Err("Integration settings are too large.".to_string());
        }
    }

    match &normalized.integration_type {
        IntegrationType::GitHub => {
            let repo = normalized
                .site_id
                .as_deref()
                .ok_or("GitHub repository must use owner/repository.")?;
            normalized.site_id = Some(normalize_github_repo_slug(repo)?);
        }
        IntegrationType::Jira => {
            let extra = normalized
                .extra
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("Jira settings must be an object.")?;
            if extra.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "instance_url" | "email" | "project_key" | "issue_type"
                )
            }) {
                return Err("Jira settings contain an unsupported field.".to_string());
            }
            let host = normalize_jira_cloud_host(
                extra
                    .get("instance_url")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("Jira Cloud tenant is required.")?,
            )?;
            let email = normalize_jira_email(
                extra
                    .get("email")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("Jira account email is required.")?,
            )?;
            let project_key = normalize_jira_project_key(
                extra
                    .get("project_key")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("Jira project key is required.")?,
            )?;
            let issue_type = normalize_jira_issue_type(
                extra
                    .get("issue_type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("Task"),
            )?;
            extra.insert("instance_url".to_string(), serde_json::Value::String(host));
            extra.insert("email".to_string(), serde_json::Value::String(email));
            extra.insert(
                "project_key".to_string(),
                serde_json::Value::String(project_key),
            );
            extra.insert(
                "issue_type".to_string(),
                serde_json::Value::String(issue_type),
            );
        }
        _ => {}
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_slug_rejects_path_query_and_fragment_injection() {
        assert_eq!(
            normalize_github_repo_slug("brambleworks/SiteCMD").unwrap(),
            "brambleworks/SiteCMD"
        );
        for value in [
            "brambleworks/SiteCMD/issues",
            "brambleworks/SiteCMD?state=open",
            "brambleworks/SiteCMD#fragment",
            "../repos/admin",
            "brambleworks/",
        ] {
            assert!(
                normalize_github_repo_slug(value).is_err(),
                "unsafe slug accepted: {value}"
            );
        }
    }

    #[test]
    fn jira_cloud_host_accepts_only_bare_or_https_atlassian_origins() {
        assert_eq!(
            normalize_jira_cloud_host("Example.atlassian.net").unwrap(),
            "example.atlassian.net"
        );
        assert_eq!(
            normalize_jira_cloud_host("https://example.atlassian.net/").unwrap(),
            "example.atlassian.net"
        );
        for value in [
            "http://example.atlassian.net",
            "https://example.atlassian.net/path",
            "https://example.atlassian.net:8443",
            "https://user@example.atlassian.net",
            "localhost",
            "jira.example.com",
        ] {
            assert!(
                normalize_jira_cloud_host(value).is_err(),
                "unsafe tenant accepted: {value}"
            );
        }
    }

    #[test]
    fn renderer_cannot_reuse_the_internal_keyring_placeholder() {
        let config = IntegrationConfig {
            integration_type: IntegrationType::GitHub,
            api_key: Some(crate::constants::KEYRING_PLACEHOLDER.to_string()),
            site_id: Some("brambleworks/SiteCMD".to_string()),
            extra: None,
            enabled: true,
        };
        assert!(validate_and_normalize_config(&config)
            .unwrap_err()
            .contains("entered directly"));
    }
}
