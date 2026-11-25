use std::{borrow::Cow, sync::LazyLock};

mod basic;
mod counted_regex;
use counted_regex::{Captures, CountedRegex};
mod literal;
pub mod mask;
mod path_credentials;
mod pem;
pub use literal::may_contain_literal;
use path_credentials::private_path_segment;
mod provider_tokens;
use provider_tokens::redact_webhook_urls;
use provider_tokens::{
    redact_embedded_mcp_values, redact_error_tokens, redact_mcp_values_outside_urls,
};

pub type UrlMask = for<'a> fn(&'a str) -> Cow<'a, str>;

fn keep_url(text: &str) -> Cow<'_, str> {
    Cow::Borrowed(text)
}

static EVIDENCE_URL: LazyLock<CountedRegex> = LazyLock::new(|| {
    CountedRegex::new(r#"(?i)(?-u:\b)https?://[^\s<>\"']+"#).expect("static evidence URL regex")
});

static EVIDENCE_EMAIL: LazyLock<CountedRegex> = LazyLock::new(|| {
    CountedRegex::new(r"(?i)(?-u:\b)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}")
        .expect("static evidence email regex")
});

/// Whether text contains an email-shaped run, regardless of its surrounding syntax.
pub fn contains_email(text: &str) -> bool {
    EVIDENCE_EMAIL.is_match(text)
}

/// Scrub generic credential formats from errors and logs. Provider key-table
/// formats use separate masks supplied by the scan producer.
pub fn redact_secrets(input: &str) -> String {
    redact_secrets_with_url_mask(input, keep_url)
}

/// Mask credentials in host evidence before publication.
pub fn redact_evidence_secrets(input: &str) -> String {
    let generic = redact_secrets_with_url_mask(input, redact_evidence_provider_tokens);
    match redact_evidence_provider_tokens(&generic) {
        Cow::Borrowed(_) => generic,
        Cow::Owned(masked) => masked,
    }
}

/// Apply the provider-format evidence masks.
pub fn redact_evidence_provider_tokens(input: &str) -> Cow<'_, str> {
    provider_tokens::redact_evidence_tokens(input)
}

pub fn redact_secrets_with_url_mask(input: &str, mask_url: UrlMask) -> String {
    let input = path_credentials::redact_url_credentials(input, mask_url);
    let input = pem::redact_pem_lines(&input);
    let input = redact_error_tokens(&input);
    redact_mcp_values_outside_urls(&input, &EVIDENCE_URL)
}

pub fn prime_ascii_masks() {
    provider_tokens::prime_ascii_masks();
}

pub fn prepare_config_credentials(input: &str) -> String {
    redact_embedded_mcp_values(&pem::redact_pem_lines(input))
}

pub fn log_safe_url_target(raw_url: &str) -> String {
    let Ok(parsed) = url::Url::parse(raw_url) else {
        return "[invalid-url]".to_string();
    };
    let Some(host) = parsed.host_str() else {
        return format!("{}://[unknown-host]", parsed.scheme());
    };
    let port = parsed
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();
    let path_hint = if parsed.path().is_empty() || parsed.path() == "/" {
        ""
    } else {
        "/[path]"
    };
    format!("{}://{}{}{}", parsed.scheme(), host, port, path_hint)
}

/// Keep a safe path hint for a page URL in diagnostics.
pub fn log_safe_page_url(raw_url: &str) -> String {
    sanitize_page_url(raw_url, false, keep_url)
}

/// Same policy, with two allowances for a URL on the scanned site's own
/// origin: long letter-and-digit path segments are kept (they are its asset
/// names, which the fix needs, while a foreign host may be a CDN carrying
/// signed path tokens), and the query survives as parameter names without
/// their values. The site's own failing request is reproducible that way:
/// `https://astro.build/_image` cannot be re-requested, and the sampler's 400
/// came from the query that was dropped.
pub fn sanitize_page_url_for_site(
    raw_url: &str,
    site_origin: Option<&str>,
    mask_url: UrlMask,
) -> String {
    let same_origin = site_origin.is_some_and(|origin| {
        // Reparse `site_origin` too so a default port embedded in either side
        // folds away the same way; an unparsable or opaque origin can never match.
        let Ok(site_url) = url::Url::parse(origin) else {
            return false;
        };
        let site_origin = site_url.origin();
        site_origin.is_tuple()
            && url::Url::parse(raw_url)
                .map(|parsed| {
                    parsed.origin().ascii_serialization() == site_origin.ascii_serialization()
                })
                .unwrap_or(false)
    });
    sanitize_page_url(raw_url, same_origin, mask_url)
}

/// An npm-style `name@version` path segment, which `security.sri` and
/// `security.vulnerable_libraries` promise to reproduce exactly. A scoped
/// package (`@scope`) has no local part at all, so only the versioned form
/// needs the check.
pub fn package_coordinate(segment: &str) -> bool {
    if contains_email(segment) {
        return false;
    }
    if segment.starts_with('@') {
        return true;
    }
    segment.rsplit_once('@').is_some_and(|(name, version)| {
        !name.is_empty()
            && (PACKAGE_VERSION_RE.is_match(version)
                || matches!(
                    version,
                    "latest" | "next" | "beta" | "alpha" | "canary" | "rc"
                ))
    })
}

/// `1`, `4.17`, `4.17.21`, `v2.0.0-beta.1`, `1.0.0+build.5`.
static PACKAGE_VERSION_RE: LazyLock<CountedRegex> = LazyLock::new(|| {
    CountedRegex::new(r"^v?\d+(\.\d+){0,2}([-+][0-9A-Za-z.]+)?$").expect("static version regex")
});

/// Extensions whose filenames are build output, not credentials. A long
/// letter-and-digit segment ending in one of these is a content hash in an
/// asset name, and the fix needs it verbatim: SRI, image, third-party, and
/// asset-weight evidence on gov.uk, github.com, and bbc.co.uk was reduced to
/// `[redacted]` for every bundle it named.
const STATIC_ASSET_EXTENSIONS: [&str; 15] = [
    "js", "mjs", "cjs", "css", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "woff2",
    "woff", "json",
];

/// Whether a path segment names a static asset file rather than an opaque
/// token. The extension is what carries the meaning: a bearer value in a URL
/// path does not end in `.js` or `.woff2`.
fn static_asset_filename(segment: &str) -> bool {
    segment.rsplit_once('.').is_some_and(|(name, extension)| {
        !name.is_empty()
            && STATIC_ASSET_EXTENSIONS
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    })
}

/// How many query parameter names one evidence URL keeps. A page can carry an
/// arbitrarily long query; the names exist to make the request reproducible,
/// not to reproduce the whole string.
const MAX_EVIDENCE_QUERY_NAMES: usize = 8;

/// Rebuild a query as parameter names only. Values are where credentials,
/// identifiers, and personal data live, so none of them survives; the names
/// stay because a URL stripped of its whole query is not the URL that failed
/// (`https://astro.build/_image` cannot be re-requested, and the sampler's
/// 400 came from the query it dropped).
fn redacted_query(query: &str) -> String {
    let mut names: Vec<String> = Vec::new();
    let mut truncated = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if names.len() == MAX_EVIDENCE_QUERY_NAMES {
            truncated = true;
            break;
        }
        let name = pair.split(['=', ';']).next().unwrap_or_default().trim();
        if name.is_empty() {
            continue;
        }
        // A valueless parameter is the whole pair, so a bare token in the
        // query would arrive here as a "name". Apply the same shape rule the
        // path segments use rather than persisting it.
        let name: String = if looks_like_opaque_token(name) {
            "[redacted]".to_string()
        } else {
            name.chars().take(40).collect()
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return String::new();
    }
    format!("?{}{}", names.join("&"), if truncated { "&…" } else { "" })
}

/// A long mixed letter-and-digit run with no file extension: the shape of a
/// session id, signature, or bearer value rather than a name.
fn looks_like_opaque_token(value: &str) -> bool {
    let Some(value) = crate::url_path::normalized_segment(value) else {
        return true;
    };
    value.chars().count() >= 32
        && !crate::url_path::word_slug(&value)
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && !static_asset_filename(&value)
}

/// `same_origin` is true only for a URL on the scanned page's own origin. It
/// widens two rules at once: long path segments survive, and query parameter
/// names survive without their values. A foreign host keeps the strict policy,
/// since its path and query can carry signed tokens this scan cannot read.
pub fn sanitize_page_url(raw_url: &str, same_origin: bool, mask_url: UrlMask) -> String {
    let Ok(parsed) = url::Url::parse(raw_url) else {
        return "[invalid-url]".to_string();
    };
    let Some(host) = parsed.host_str() else {
        return format!("{}://[unknown-host]", parsed.scheme());
    };
    let port = parsed
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();
    let mut redact_next_segment = false;
    let safe_path = parsed
        .path()
        .split('/')
        .map(|segment| {
            if segment.is_empty() {
                return segment.to_string();
            }
            if redact_next_segment {
                redact_next_segment = false;
                return "[redacted]".to_string();
            }
            let lower = segment.to_ascii_lowercase();
            // These routes commonly carry a bearer value in the next segment.
            redact_next_segment = matches!(
                lower.as_str(),
                "reset"
                    | "password-reset"
                    | "verify"
                    | "verification"
                    | "magic-link"
                    | "magic"
                    | "invite"
                    | "invitation"
                    | "activate"
                    | "activation"
                    | "confirm"
                    | "confirmation"
                    | "unsubscribe"
            );
            let token_like = !same_origin && looks_like_opaque_token(segment);
            let retina_asset = segment
                .rsplit_once('@')
                .and_then(|(_, suffix)| suffix.split_once('.'))
                .is_some_and(|(scale, extension)| {
                    scale.strip_suffix('x').is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                    }) && matches!(
                        extension.to_ascii_lowercase().as_str(),
                        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg"
                    )
                });
            let email_like = !retina_asset
                && (crate::url_path::normalized_segment(segment)
                    .is_none_or(|value| contains_email(&value))
                    || segment.split_once('@').is_some_and(|(local, domain)| {
                        !local.is_empty() && domain.contains('.') && !package_coordinate(segment)
                    }));
            if private_path_segment(segment)
                || token_like
                || email_like
                || lower.contains("%40")
                || provider_tokens::encoded_segment_contains_credentials(segment, mask_url)
            {
                "[redacted]".to_string()
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let query = parsed
        .query()
        .filter(|_| same_origin)
        .map(redacted_query)
        .unwrap_or_default();
    let safe_url = redact_error_tokens(&format!(
        "{}://{}{}{}{}",
        parsed.scheme(),
        host,
        port,
        safe_path,
        query
    ));
    bounded_evidence_url(&mask_url(&safe_url))
}

pub fn sanitize_url_reference(
    raw_url: &str,
    safe_page_url: fn(&str) -> String,
    redact_diagnostic: fn(&str) -> String,
) -> String {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return "[empty-url]".to_string();
    }

    if trimmed.starts_with("//") {
        let safe = safe_page_url(&format!("https:{trimmed}"));
        return safe.strip_prefix("https:").unwrap_or(&safe).to_string();
    }

    if let Ok(parsed) = url::Url::parse(trimmed) {
        return if matches!(parsed.scheme(), "http" | "https") {
            safe_page_url(trimmed)
        } else {
            bounded_evidence_url(&format!("{}:[redacted]", parsed.scheme()))
        };
    }

    if let Ok(base) = url::Url::parse("https://evidence.invalid/") {
        if let Ok(resolved) = base.join(trimmed) {
            let safe = safe_page_url(resolved.as_str());
            if let Some(relative) = safe.strip_prefix("https://evidence.invalid") {
                return if trimmed.starts_with('/') {
                    relative.to_string()
                } else {
                    relative.strip_prefix('/').unwrap_or(relative).to_string()
                };
            }
        }
    }

    let redacted = redact_diagnostic(trimmed);
    let without_query = redacted.split(['?', '#']).next().unwrap_or(&redacted);
    bounded_evidence_url(without_query)
}

/// Remove personal data and generic credentials from log diagnostics.
fn redact_log_diagnostic(input: &str) -> String {
    redact_secrets(&prepare_issue_evidence(input, log_safe_page_url))
}

pub fn prepare_issue_evidence(input: &str, safe_page_url: fn(&str) -> String) -> String {
    let input = pem::redact_pem_lines(input);
    let input = redact_webhook_urls(&input);
    let urls_redacted = redact_evidence_urls(&input, safe_page_url);
    EVIDENCE_EMAIL
        .replace_all(&urls_redacted, |captures: &Captures<'_>| {
            let email = captures.get(0).expect("whole email capture");
            let ssh_git = email.as_str().starts_with("git@")
                && urls_redacted[..email.start()].ends_with("ssh://");
            if ssh_git {
                email.as_str().to_string()
            } else {
                "[email]".to_string()
            }
        })
        .into_owned()
}

fn redact_evidence_urls(input: &str, safe_page_url: fn(&str) -> String) -> String {
    let mut safe_urls = std::collections::HashMap::new();
    EVIDENCE_URL
        .replace_all(input, |captures: &Captures<'_>| {
            let matched = &input[captures.get(0).expect("whole URL capture").range()];
            let url = matched.trim_end_matches(['.', ',', ';', ':', ')', ']', '}']);
            let punctuation = &matched[url.len()..];
            let safe = safe_urls.entry(url).or_insert_with(|| {
                safe_page_url(url)
                    .split('/')
                    .enumerate()
                    .map(|(index, segment)| {
                        if index >= 3 && segment.contains("***") {
                            "[redacted]"
                        } else {
                            segment
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            });
            format!("{safe}{punctuation}")
        })
        .into_owned()
}

/// Maximum characters persisted for one sanitized URL/reference in issue
/// evidence. Long data URLs and adversarial path segments must not create
/// unbounded scan rows even after credentials and query values are removed.
pub const ISSUE_EVIDENCE_URL_MAX_CHARS: usize = 500;

/// Maximum characters persisted for one free-form diagnostic or response
/// header in issue evidence. These values originate outside SiteCMD and can
/// otherwise create oversized issue rows or retain irrelevant response data.
pub const ISSUE_EVIDENCE_TEXT_MAX_CHARS: usize = 1_000;

/// Mask generic credentials and personal data before capping a log diagnostic.
pub fn bounded_log_diagnostic(input: &str) -> String {
    let redacted = redact_log_diagnostic(input);
    bounded_evidence(&redacted, ISSUE_EVIDENCE_TEXT_MAX_CHARS)
}

fn bounded_evidence_url(value: &str) -> String {
    bounded_evidence(value, ISSUE_EVIDENCE_URL_MAX_CHARS)
}

pub fn bounded_evidence(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut bounded = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
use test_support::{
    log_safe_page_url_for_site, log_safe_url_reference, redact_log_config_credentials,
};

#[cfg(test)]
mod authorization_tests;

#[cfg(test)]
mod bearer_encoding_tests;

#[cfg(test)]
mod basic_body_tests;

#[cfg(test)]
mod unicode_boundary_tests;

#[cfg(test)]
mod url_encoding_tests;

#[cfg(test)]
mod path_safety_tests;

#[cfg(test)]
mod login_mask_tests;

#[cfg(test)]
mod credential_tests;

#[cfg(test)]
mod pem_comment_tests;

#[cfg(any(test, feature = "test-support"))]
mod literal_test_support;

#[cfg(any(test, feature = "test-support"))]
mod shared_test_support;

#[cfg(feature = "test-support")]
pub mod testing {
    pub use super::literal_test_support::{assert_literal_coverage, mask_corpus};
    pub use super::shared_test_support::*;
}

#[cfg(test)]
mod tests {
    use super::{
        bounded_log_diagnostic, log_safe_page_url, log_safe_page_url_for_site,
        log_safe_url_reference, log_safe_url_target, redact_log_diagnostic,
    };

    #[test]
    fn log_safe_url_target_removes_query_fragment_and_path_tokens() {
        let redacted = log_safe_url_target(
            "https://example.com/reset/secret-token?token=abc123&email=person@example.com#frag",
        );

        assert_eq!(redacted, "https://example.com/[path]");
        assert!(!redacted.contains("secret-token"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("person@example.com"));
        assert!(!redacted.contains("frag"));
    }

    #[test]
    fn log_safe_url_target_keeps_localhost_port_without_query() {
        assert_eq!(
            log_safe_url_target("http://127.0.0.1:4321/?preview_token=abc"),
            "http://127.0.0.1:4321"
        );
    }

    #[test]
    fn log_safe_page_url_keeps_path_but_removes_secrets() {
        let safe = log_safe_page_url(
            "https://user:pass@example.com/docs/abc12345678901234567890123456789?token=secret#part",
        );
        // A foreign host keeps the strict policy: no query at all.
        assert_eq!(safe, "https://example.com/docs/[redacted]");
        assert!(!safe.contains("user"));
        assert!(!safe.contains("pass"));
        assert!(!safe.contains("secret"));
        assert!(!safe.contains("part"));
    }

    #[test]
    fn log_safe_page_url_redacts_short_tokens_after_sensitive_routes() {
        let safe =
            log_safe_page_url("https://example.com/account/reset/short-token?continue=/settings");
        assert_eq!(safe, "https://example.com/account/reset/[redacted]");
        assert!(!safe.contains("short-token"));
        assert!(!safe.contains("settings"));
    }

    #[test]
    fn log_safe_page_url_keeps_retina_asset_names_but_redacts_email_paths() {
        assert_eq!(
            log_safe_page_url("https://cdn.example.com/img/logo@2x.png?token=secret"),
            "https://cdn.example.com/img/logo@2x.png"
        );
        assert_eq!(
            log_safe_page_url("https://example.com/users/person@example.com/profile"),
            "https://example.com/users/[redacted]/profile"
        );
    }

    #[test]
    fn redact_secrets_masks_known_token_formats() {
        use super::redact_secrets;
        assert_eq!(
            redact_secrets("token refresh failed: 1//0gabcdEFGHijkl_mnop"),
            "token refresh failed: 1//***"
        );
        assert_eq!(
            redact_secrets(&format!("github gho_{} rejected", "aB3".repeat(8))),
            "github gho_*** rejected"
        );
        let basic = redact_secrets("connect https://user:s3cretPass@db.example.com failed");
        assert!(
            basic.contains("https://***:***@db.example.com"),
            "got {basic}"
        );
        assert!(!basic.contains("s3cretPass"), "secret leaked: {basic}");
    }

    #[test]
    fn issue_evidence_redacts_authorization_bearer_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        let detail = format!("request failed with Authorization: Bearer {token}");

        for redacted in [
            redact_log_diagnostic(&detail),
            bounded_log_diagnostic(&detail),
        ] {
            assert!(
                !redacted.contains(token),
                "bearer token leaked into issue evidence: {redacted}"
            );
            assert!(
                !redacted.contains("payload.signature"),
                "token tail leaked: {redacted}"
            );
        }
    }

    #[test]
    fn same_origin_asset_names_survive_but_sensitive_routes_and_foreign_tokens_do_not() {
        let site = Some("https://sitecmd.com");
        let own_asset = "https://sitecmd.com/images/screenshots/problem/dashboard-health-score-before-fix-2026.png";
        assert_eq!(log_safe_page_url_for_site(own_asset, site), own_asset);

        let own_reset = "https://sitecmd.com/account/reset/abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            log_safe_page_url_for_site(own_reset, site),
            "https://sitecmd.com/account/reset/[redacted]"
        );

        // A filename ending in a static-asset extension is build output on
        // any host: SRI, image, and asset-weight evidence named every bundle
        // on github.githubassets.com and static.files.bbci.co.uk `[redacted]`
        // until this exemption existed.
        let foreign = "https://cdn.example.com/images/screenshots/problem/dashboard-health-score-before-fix-2026.png";
        assert_eq!(log_safe_page_url_for_site(foreign, site), foreign);
        assert_eq!(log_safe_page_url_for_site(own_asset, None), own_asset);

        // An extension-less long segment on a foreign host is still opaque.
        let signed = "https://cdn.example.com/image/upload/s--abcdef0123456789abcdef0123456789--/v1/logo.png";
        assert_eq!(
            log_safe_page_url_for_site(signed, site),
            "https://cdn.example.com/image/upload/[redacted]/v1/logo.png"
        );
    }

    #[test]
    fn log_safe_page_url_for_site_handles_origin_edge_cases() {
        let site = Some("https://sitecmd.com");

        // (a) A different subdomain is never the scanned site's origin, so it
        // gets exactly the treatment the non-site-aware sanitizer already gave
        // it (nothing here is long enough to redact either way).
        let subdomain_url = "https://cdn.sitecmd.com/a/b.js";
        assert_eq!(
            log_safe_page_url_for_site(subdomain_url, site),
            log_safe_page_url(subdomain_url),
            "a different subdomain must not receive the same-origin exemption"
        );
        assert_eq!(
            log_safe_page_url_for_site(subdomain_url, site),
            "https://cdn.sitecmd.com/a/b.js"
        );

        // (b) An explicit default port on either side folds away, because
        // `site_origin` is reparsed and re-serialized the same way as the URL.
        let long_name = "https://sitecmd.com:443/assets/dashboard-health-score-a1b2c3d4e5f67890.js";
        let bare_long_name =
            "https://sitecmd.com/assets/dashboard-health-score-a1b2c3d4e5f67890.js";
        assert_eq!(log_safe_page_url_for_site(long_name, site), bare_long_name);
        // The reverse also folds: an explicit default port embedded in
        // `site_origin` itself normalizes away before the comparison.
        assert_eq!(
            log_safe_page_url_for_site(
                "https://sitecmd.com/assets/app.js",
                Some("https://sitecmd.com:443"),
            ),
            "https://sitecmd.com/assets/app.js"
        );
        assert_eq!(
            log_safe_page_url_for_site(bare_long_name, Some("https://sitecmd.com:443")),
            bare_long_name
        );

        // An unparsable site_origin can never be same-origin, so it behaves
        // exactly like passing None.
        assert_eq!(
            log_safe_page_url_for_site(bare_long_name, Some("not a url")),
            log_safe_page_url_for_site(bare_long_name, None)
        );

        // (c) Userinfo, query, and fragment are stripped even for a
        // same-origin URL; only the path survives.
        assert_eq!(
            log_safe_page_url_for_site(
                "https://user:pw@sitecmd.com/assets/app.js?token=abc#frag",
                site,
            ),
            "https://sitecmd.com/assets/app.js?token"
        );

        // (d) Scheme and host compare case-insensitively (URL parsing
        // lowercases both), but the retained path keeps its original case.
        assert_eq!(
            log_safe_page_url_for_site("HTTPS://SITECMD.COM/Assets/App.js", site),
            "https://sitecmd.com/Assets/App.js"
        );
    }

    #[test]
    fn url_reference_sanitizer_handles_relative_protocol_and_opaque_values() {
        assert_eq!(
            log_safe_url_reference("/account/reset/short-token?token=secret#part"),
            "/account/reset/[redacted]"
        );
        assert_eq!(
            log_safe_url_reference("//cdn.example.com/app.js?key=secret"),
            "//cdn.example.com/app.js"
        );
        assert_eq!(
            log_safe_url_reference("data:image/png;base64,private"),
            "data:[redacted]"
        );
        assert_eq!(
            log_safe_url_reference("assets/card-1.png?token=secret"),
            "assets/card-1.png",
            "relative evidence should remain grep-compatible with source markup"
        );
    }

    #[test]
    fn the_sites_own_failing_request_keeps_its_parameter_names_but_no_values() {
        let site = Some("https://astro.build");
        // The asset sampler reported `https://astro.build/_image` for a URL
        // whose 400 came entirely from the query it dropped, so the failing
        // request could not be reproduced from the evidence.
        assert_eq!(
            log_safe_page_url_for_site(
                "https://astro.build/_image?href=%2F_astro%2Fhero.png&w=256&f=webp",
                site
            ),
            "https://astro.build/_image?href&w&f"
        );
        // Values never survive, on the site's own origin or anywhere else.
        assert_eq!(
            log_safe_page_url_for_site(
                "https://astro.build/checkout?session=secret-value&email=person@example.com",
                site
            ),
            "https://astro.build/checkout?session&email"
        );
        // A foreign host keeps the strict policy, query and all.
        assert_eq!(
            log_safe_page_url_for_site("https://cdn.example.net/w.js?key=secret", site),
            "https://cdn.example.net/w.js"
        );
    }

    #[test]
    fn a_bare_token_in_the_query_is_not_kept_as_a_parameter_name() {
        assert_eq!(
            log_safe_page_url_for_site(
                "https://sitecmd.com/callback?abcdef0123456789abcdef0123456789abc",
                Some("https://sitecmd.com")
            ),
            "https://sitecmd.com/callback?[redacted]"
        );
    }

    #[test]
    fn a_long_query_contributes_a_bounded_number_of_names() {
        let query: String = (0..20)
            .map(|index| format!("p{index}=value{index}&"))
            .collect();
        let safe = log_safe_page_url_for_site(
            &format!("https://sitecmd.com/search?{query}"),
            Some("https://sitecmd.com"),
        );
        assert_eq!(safe, "https://sitecmd.com/search?p0&p1&p2&p3&p4&p5&p6&p7&…");
        assert!(!safe.contains("value"), "{safe}");
    }

    #[test]
    fn package_coordinates_survive_the_email_redaction_rule() {
        for url in [
            "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js",
            "https://cdn.jsdelivr.net/npm/normalize.css@8.0.1/normalize.css",
            "https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js",
            "https://cdn.jsdelivr.net/npm/vue@3.4.0-beta.2/dist/vue.js",
            "https://cdn.jsdelivr.net/npm/preact@latest/dist/preact.min.js",
            "https://cdn.jsdelivr.net/npm/@scope/pkg@2.1.0/index.js",
        ] {
            assert_eq!(
                log_safe_url_reference(url),
                url,
                "SRI and vulnerable-library evidence promise the exact URL"
            );
        }
    }

    #[test]
    fn an_address_in_a_path_segment_is_still_redacted() {
        assert_eq!(
            log_safe_url_reference("https://example.com/u/jane@example.com"),
            "https://example.com/u/[redacted]"
        );
        assert_eq!(
            log_safe_url_reference("https://example.com/u/jane@example.com/profile"),
            "https://example.com/u/[redacted]/profile"
        );
    }
}

#[cfg(test)]
mod route_token_tests;
