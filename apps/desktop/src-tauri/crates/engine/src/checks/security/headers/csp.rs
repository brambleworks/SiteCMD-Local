//! Parses and grades Content-Security-Policy headers.

use crate::vocab::{CheckStatus, Severity};
use std::collections::HashMap;

pub(super) struct CspEvaluation {
    pub(super) status: CheckStatus,
    pub(super) severity: Severity,
    pub(super) title: &'static str,
    pub(super) description: String,
    pub(super) fix_prompt: Option<String>,
    pub(super) manual_fix: Option<String>,
    pub(super) why_it_matters: Option<String>,
    pub(super) issues: Vec<String>,
}

/// Every enforced policy the response declares, following CSP Level 3's
/// serialized policy list parse: commas separate policies, and a token with
/// no directives is ignored on both lanes.
pub(super) fn enforced_policies(headers: &http::HeaderMap) -> Vec<String> {
    crate::header_lines::field_value(headers, "content-security-policy")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|policy| !parse_csp_directives(policy).is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn parse_csp_directives(value: &str) -> HashMap<String, Vec<String>> {
    let mut directives: HashMap<String, Vec<String>> = HashMap::new();
    for directive in value.split(';') {
        let mut parts = directive.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let name = name.to_ascii_lowercase();
        let values: Vec<String> = parts.map(|part| part.to_ascii_lowercase()).collect();
        // Browsers honor the first CSP directive occurrence and ignore duplicates.
        directives.entry(name).or_insert(values);
    }
    directives
}

fn valid_nonce_or_hash_source(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    else {
        return false;
    };
    let encoded = inner
        .strip_prefix("nonce-")
        .or_else(|| inner.strip_prefix("sha256-"))
        .or_else(|| inner.strip_prefix("sha384-"))
        .or_else(|| inner.strip_prefix("sha512-"));
    encoded.is_some_and(|encoded| {
        !encoded.is_empty()
            && encoded.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
            })
    })
}

fn csp_has_constrained_script_source(sources: Option<&Vec<String>>) -> bool {
    sources
        .map(|values| {
            !values.is_empty()
                && values.iter().any(|value| {
                    value == "'self'"
                        || (value == "'none'" && values.len() == 1)
                        || valid_nonce_or_hash_source(value)
                })
        })
        .unwrap_or(false)
}

/// Return whether `frame-ancestors` excludes broad wildcard or scheme sources.
/// An empty list blocks all embedding.
pub(super) fn frame_ancestors_restrict(sources: &[String]) -> bool {
    !sources.iter().any(|source| {
        source == "*"
            || source.ends_with("://*")
            || (source.ends_with(':') && !source.starts_with('\''))
    })
}

fn csp_sources_include_any(sources: Option<&Vec<String>>, needles: &[&str]) -> bool {
    sources
        .map(|values| {
            values
                .iter()
                .any(|value| needles.iter().any(|needle| value == needle))
        })
        .unwrap_or(false)
}

pub(super) fn evaluate_csp(
    value: Option<&str>,
    clickjacking_covered_elsewhere: bool,
) -> CspEvaluation {
    let Some(value) = value else {
        return CspEvaluation {
            status: CheckStatus::Fail,
            severity: Severity::Medium,
            title: "No enforced Content-Security-Policy",
            description: "No enforced Content-Security-Policy (CSP) was observed for this response. The browser therefore applies no CSP-specific resource or script restrictions. CSP is defense in depth: a well-designed policy can limit some consequences of an injection flaw, but it does not remove the underlying flaw and other browser/application controls may still apply.".into(),
            fix_prompt: Some("Design a Content-Security-Policy for the resources this site actually needs. Evaluate it with Content-Security-Policy-Report-Only first, then deploy an enforced policy after representative routes and integrations pass testing.".into()),
            manual_fix: Some("Set a CSP where your app already manages headers, such as your CDN, reverse proxy, framework headers config, or server middleware. Start in report-only mode, list the script, style, image, and connect sources the site actually needs, then switch to an enforced policy once the allowed sources are clean.".into()),
            why_it_matters: Some("If a separate HTML/script injection vulnerability exists, an enforced CSP can restrict which resources or inline scripts the browser accepts and reduce some exploit paths. Its absence does not by itself prove XSS.".into()),
            issues: Vec::new(),
        };
    };

    let directives = parse_csp_directives(value);
    let script_sources = directives
        .get("script-src")
        .or_else(|| directives.get("default-src"));
    let connect_sources = directives
        .get("connect-src")
        .or_else(|| directives.get("default-src"));
    // object-src falls back to default-src in every CSP level, so
    // `default-src 'none'` already blocks plugin content.
    let object_sources = directives
        .get("object-src")
        .or_else(|| directives.get("default-src"));
    let base_sources = directives.get("base-uri");
    let frame_ancestors = directives.get("frame-ancestors");
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    // CSP3 browsers ignore `unsafe-inline` when a nonce or hash source is present.
    let script_has_nonce_or_hash = script_sources
        .map(|values| values.iter().any(|value| valid_nonce_or_hash_source(value)))
        .unwrap_or(false);

    if !csp_has_constrained_script_source(script_sources) {
        // Distinguish a host allowlist from a policy with no script restriction.
        let has_host_allowlist = script_sources
            .map(|values| {
                values.iter().any(|value| {
                    // A real host source: not a 'keyword'/nonce/hash, and not
                    // a broad wildcard or scheme source (those get their own
                    // dedicated blocker messages).
                    !value.starts_with('\'')
                        && !matches!(
                            value.as_str(),
                            "*" | "http:" | "https:" | "data:" | "blob:" | "filesystem:"
                        )
                })
            })
            .unwrap_or(false);
        if has_host_allowlist {
            warnings.push("the script policy relies on a host allowlist alone, with no 'self', nonce, or hash source; verify that every allowed origin is controlled and cannot serve attacker-selected executable responses such as JSONP".into());
        } else {
            blockers.push(
                "the policy does not include a constrained script source ('self', 'none', a nonce, or a hash) in script-src or default-src".into(),
            );
        }
    }
    if csp_sources_include_any(script_sources, &["'unsafe-eval'"]) {
        blockers.push("script-src allows unsafe eval script execution".into());
    }
    if csp_sources_include_any(script_sources, &["'unsafe-inline'"]) {
        if script_has_nonce_or_hash {
            // CSP3 browsers ignore 'unsafe-inline' when a nonce/hash is
            // present, so the token is the documented CSP2 fallback rather
            // than a policy weakness.
            warnings.push(
                "script-src lists 'unsafe-inline' alongside a nonce/hash - CSP3 browsers ignore it, and it still applies in CSP2-only browsers, so keeping it is a deliberate fallback rather than a defect".into(),
            );
        } else {
            blockers.push("script-src allows unsafe inline script execution".into());
        }
    }
    if csp_sources_include_any(script_sources, &["*", "http:", "https:"]) {
        blockers.push("script-src allows broad script sources".into());
    }
    // blob: is commonly legitimate, while data: and filesystem: remain blockers.
    if csp_sources_include_any(script_sources, &["data:", "filesystem:"]) {
        blockers.push("script-src allows executable data: or filesystem: URLs".into());
    }
    if csp_sources_include_any(script_sources, &["blob:"]) {
        warnings.push(
            "script-src allows blob: - fine for workers / MediaSource / bundler chunks, but make sure you don't load blobs built from untrusted uploads".into(),
        );
    }
    if csp_sources_include_any(connect_sources, &["*"]) {
        blockers.push("connect-src allows any network destination".into());
    }
    if !object_sources
        .map(|values| values.iter().any(|value| value == "'none'"))
        .unwrap_or(false)
    {
        warnings.push("object-src 'none' is missing".into());
    }
    if !base_sources
        .map(|values| {
            values
                .iter()
                .any(|value| value == "'self'" || value == "'none'")
        })
        .unwrap_or(false)
    {
        warnings.push("base-uri is missing".into());
    }
    if !clickjacking_covered_elsewhere && frame_ancestors.is_none() {
        warnings.push("frame-ancestors is missing".into());
    }

    if !blockers.is_empty() {
        return CspEvaluation {
            status: CheckStatus::Fail,
            severity: Severity::Medium,
            title: "Content-Security-Policy provides limited script containment",
            description: format!(
                "Content-Security-Policy is present, but these directives materially reduce the policy's ability to constrain injected script or outbound connections: {}. This is a policy-strength finding, not proof that an injection vulnerability exists.",
                blockers.join("; ")
            ),
            fix_prompt: Some("Tighten the CSP based on the site's real resource inventory. Remove unnecessary unsafe or broad script sources, prefer nonces or hashes for inline scripts, and test changes in Report-Only mode before enforcement.".into()),
            manual_fix: Some("Use report-only mode while tightening the policy, but keep the target policy strict: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`. Add only the specific third-party domains your app actually needs, and use nonces or hashes instead of allowing unsafe inline scripts.".into()),
            why_it_matters: Some("If an attacker first obtains an injection primitive, broad or unsafe CSP sources can leave more payload options available. Tightening the policy improves containment; it does not replace output encoding, sanitization, or safe DOM APIs.".into()),
            issues: blockers,
        };
    }

    if !warnings.is_empty() {
        return CspEvaluation {
            status: CheckStatus::Warn,
            severity: Severity::Low,
            title: "Content-Security-Policy hardening opportunities",
            description: format!(
                "Content-Security-Policy has a constrained script source, with these additional hardening opportunities: {}. Some items may be intentional for the site's embedding or runtime requirements.",
                warnings.join("; ")
            ),
            fix_prompt: Some("Review each CSP hardening opportunity against the site's actual embedding and runtime requirements, then add or remove directives where compatible.".into()),
            manual_fix: Some("Keep your existing allowed sources, then add `object-src 'none'` and `base-uri 'self'`. If you do not already use X-Frame-Options, also add a `frame-ancestors` rule that matches your embedding needs.".into()),
            why_it_matters: Some("`object-src`, `base-uri`, and framing controls close specific browser behaviors that a script policy alone does not cover. Their relevance depends on the application and any equivalent headers already present.".into()),
            issues: warnings,
        };
    }

    CspEvaluation {
        status: CheckStatus::Pass,
        severity: Severity::Medium,
        title: "Content-Security-Policy header",
        description: "Content-Security-Policy header is set with a useful script policy and key hardening directives.".to_string(),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        issues: Vec::new(),
    }
}
