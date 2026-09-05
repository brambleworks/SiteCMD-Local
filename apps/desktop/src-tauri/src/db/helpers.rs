//! Internal helpers for the database layer.

use rusqlite::Connection;

/// Type-erased message: a boxed closure that executes on the DB thread.
pub(crate) type DbOp = Box<dyn FnOnce(&mut Connection) + Send>;

/// Normalize DB URL keys by lowercasing the origin, trimming the terminal slash,
/// and returning both slash variants. Path case remains significant.
#[tracing::instrument(skip(url))]
pub(crate) fn normalize_url(url: &str) -> (String, String) {
    let normalized = lowercase_origin(url.trim_end_matches('/'));
    let with_slash = format!("{}/", normalized);
    (normalized, with_slash)
}

/// Lowercase an observed URL's origin without changing route identity.
pub(crate) fn normalize_occurrence_url(url: &str) -> String {
    lowercase_origin(url)
}

/// Lowercase a URL's scheme and host while preserving path, query, and fragment.
/// Non-URL inputs are unchanged; behavior must match `normalizeAppUrlForKey`.
fn lowercase_origin(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = scheme_end + 3;
    let rest = &url[after_scheme..];
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    format!(
        "{}{}{}",
        url[..after_scheme].to_ascii_lowercase(),
        rest[..host_end].to_ascii_lowercase(),
        &rest[host_end..],
    )
}

/// Normalize an optional environment URL into its DB key form, returning an
/// empty string when absent. The single shared env-url normalizer for the db
/// layer; modules import this instead of re-deriving `normalize_url(...).0`.
pub fn normalize_env_url(url: Option<&str>) -> String {
    url.map(|value| normalize_url(value).0).unwrap_or_default()
}

/// Return the shared lifecycle key: normalized URL for web environments or the
/// verbatim `project:<id>` key for code-only scopes.
pub(crate) fn lifecycle_env_url(environment_scope_key: &str) -> String {
    if environment_scope_key.starts_with("project:") {
        environment_scope_key.to_string()
    } else {
        normalize_url(environment_scope_key).0
    }
}

/// Mint an opaque local identifier from `prefix` and 128 random bits.
pub(crate) fn mint_local_id(prefix: &str) -> Result<String, super::DbError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| super::DbError::Other(format!("OS RNG unavailable: {error}")))?;
    Ok(format!("{prefix}{}", hex::encode(bytes)))
}

/// SQL predicate matching `sites si` to the oldest project environment owning
/// either normalized URL form. Parameter numbers refer to the enclosing query.
pub(crate) fn site_project_scope_predicate(url_param: u8, slash_param: u8) -> String {
    format!(
        "si.project_id IS (SELECT project_id FROM environments \
         WHERE url = ?{url} OR url = ?{slash} ORDER BY id ASC LIMIT 1)",
        url = url_param,
        slash = slash_param
    )
}

/// Parse an enum-like TEXT column whose corruption must fail the whole read
/// instead of being reclassified. Use this for persisted issue verdict fields:
/// substituting a default changes the product's claim about a finding.
pub(crate) fn parse_required_enum<T>(column: usize, field: &str, value: &str) -> rusqlite::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid persisted {field} '{value}': {error}"),
            )),
        )
    })
}

/// Strict nullable enum parsing: NULL remains unknown, while an invalid
/// non-NULL value fails the row instead of being relabeled as NULL/default.
pub(crate) fn parse_optional_enum_required<T>(
    column: usize,
    field: &str,
    value: Option<String>,
) -> rusqlite::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .as_deref()
        .map(|raw| parse_required_enum(column, field, raw))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_lowercases_scheme_and_host_and_strips_trailing_slash() {
        // Scheme + host lowercased, path case preserved, trailing slash dropped --
        // must match the TS normalizeAppUrlForKey pinned by app-targets.test.ts.
        assert_eq!(
            normalize_url("https://Example.COM/About/").0,
            "https://example.com/About"
        );
        assert_eq!(
            normalize_url("Https://SiteCMD.com").0,
            "https://sitecmd.com"
        );
        // Non-URL input passes through unchanged (minus the trailing slash).
        assert_eq!(normalize_url("not-a-url/").0, "not-a-url");
    }

    #[test]
    fn normalize_env_url_handles_absent_and_present() {
        assert_eq!(normalize_env_url(None), "");
        assert_eq!(
            normalize_env_url(Some("https://Example.COM/x/")),
            "https://example.com/x"
        );
    }
}
