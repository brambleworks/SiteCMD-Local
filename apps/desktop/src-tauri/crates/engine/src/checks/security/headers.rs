//! Grades browser security policies by syntax and scope.

use crate::checks::Check;
use crate::page::PageContext;
use crate::vocab::{CheckResult, CheckStatus, ScanCategory, Severity};
use std::sync::LazyLock;

mod csp;
use csp::{enforced_policies, evaluate_csp, frame_ancestors_restrict, parse_csp_directives};
mod hsts;
#[cfg(test)]
use hsts::parse_hsts_max_age;
use hsts::parse_hsts_policy;

pub struct SecurityHeadersCheck;

/// A `<meta...>` tag and its attribute run.
static META_TAG_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<meta\b[^>]*>").expect("static meta tag regex"));
// allow-expect: compile-time literal regex

/// `http-equiv="content-security-policy"` (the enforced form only; browsers
/// ignore a meta-delivered Report-Only policy). The boundary class keeps
/// `content-security-policy-report-only` from matching.
static META_CSP_EQUIV_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)["'\s]http-equiv\s*=\s*["']?content-security-policy["'\s/>]"#)
        .expect("static meta csp equiv regex")
});
// allow-expect: compile-time literal regex

/// `name="referrer"` - the meta form of Referrer-Policy.
static META_REFERRER_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)["'\s]name\s*=\s*["']?referrer["'\s/>]"#)
        .expect("static meta referrer regex")
});
// allow-expect: compile-time literal regex

/// HTML comments, including an unclosed one running to end of input (a
/// truncated probe body can end mid-comment). Matches browser parsing: a
/// `<meta>` inside a comment is inert.
static HTML_COMMENT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?s)<!--.*?(?:-->|\z)").expect("static HTML comment regex")
});
// allow-expect: compile-time literal regex

/// The quoted content attribute value of a meta tag.
static META_CONTENT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)["'\s]content\s*=\s*(?:"([^"]*)"|'([^']*)')"#)
        .expect("static meta content regex")
});
// allow-expect: compile-time literal regex

/// Nonces and hashes are valuable to the browser but not to persisted issue
/// evidence. Mask their per-response payloads while retaining the source kind.
static CSP_VOLATILE_SOURCE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)'(?P<kind>nonce|sha256|sha384|sha512)-[^'\s;]+'")
        .expect("static CSP volatile-source regex")
});
// allow-expect: compile-time literal regex

fn header_evidence_value(value: &str) -> String {
    crate::log_sanitizer::bounded_issue_evidence(value)
}

fn csp_evidence_value(value: &str) -> String {
    let masked = CSP_VOLATILE_SOURCE_RE.replace_all(value, |captures: &regex::Captures<'_>| {
        format!("'{}-[redacted]'", captures["kind"].to_ascii_lowercase())
    });
    header_evidence_value(&masked)
}

/// Content of the first matching browser-enforced policy meta tag.
fn meta_delivered_policy(body: &str, matcher: &regex::Regex) -> Option<String> {
    // A commented-out <meta> (e.g. a disabled CSP left in the source) is not
    // honored by the browser, so it must not suppress a "missing header"
    // finding.
    let body = HTML_COMMENT_RE.replace_all(body, " ");
    for tag_match in META_TAG_RE.find_iter(&body) {
        let tag = tag_match.as_str();
        if !matcher.is_match(tag) {
            continue;
        }
        if let Some(caps) = META_CONTENT_RE.captures(tag) {
            let value = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

impl Check for SecurityHeadersCheck {
    fn id(&self) -> &str {
        "security.headers"
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn emitted_ids(&self) -> Vec<String> {
        [
            "csp",
            "hsts",
            "permissions_policy",
            "referrer_policy",
            "x_content_type_options",
            "x_frame_options",
        ]
        .iter()
        .map(|suffix| format!("security.headers.{suffix}"))
        .collect()
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if ctx.is_localhost {
            let preview_note = "Skipped on localhost preview. Security headers are often controlled by the deployed edge or reverse proxy, so verify them on a real deployment target.".to_string();
            return vec![
                ("security.headers.csp", "Content-Security-Policy header"),
                ("security.headers.hsts", "Strict-Transport-Security (HSTS)"),
                (
                    "security.headers.x_frame_options",
                    "Clickjacking protection",
                ),
                (
                    "security.headers.x_content_type_options",
                    "X-Content-Type-Options",
                ),
                ("security.headers.referrer_policy", "Referrer-Policy header"),
                (
                    "security.headers.permissions_policy",
                    "Permissions-Policy header",
                ),
            ]
            .into_iter()
            .map(|(check_id, title)| CheckResult {
                check_id: check_id.into(),
                category: ScanCategory::Security,
                title: title.into(),
                description: preview_note.clone(),
                status: CheckStatus::Skipped,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: Some(serde_json::json!({"reason": "localhost_preview_server"})),
                confidence: crate::vocab::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            })
            .collect();
        }

        let headers = &ctx.response_headers;
        let mut results = Vec::new();

        // Collect all header names for raw_data
        let header_names: Vec<String> = headers.keys().map(|k| k.to_string()).collect();

        let csp_values = enforced_policies(headers);
        let csp_policy_count = csp_values.len();
        let csp_value = csp_values.first().cloned();
        let csp_report_only_value =
            crate::header_lines::field_value(headers, "content-security-policy-report-only");
        let xfo_value = headers
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        // Current major browsers recognize DENY and SAMEORIGIN. ALLOW-FROM
        // and unrecognized values do not provide a portable framing rule.
        let xfo_protects = xfo_value
            .as_deref()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "deny" | "sameorigin"
                )
            })
            .unwrap_or(false);
        let csp_frame_policy_sources: Vec<Vec<String>> = csp_values
            .iter()
            .filter_map(|value| parse_csp_directives(value).remove("frame-ancestors"))
            .collect();
        let has_csp_frame_directive = !csp_frame_policy_sources.is_empty();
        // Multiple enforced CSP fields are all applied. A restrictive
        // frame-ancestors list in any one policy therefore restricts the
        // effective intersection even if another policy is broad.
        let has_csp_frame = csp_frame_policy_sources
            .iter()
            .any(|sources| frame_ancestors_restrict(sources));
        let csp_frame_sources = csp_frame_policy_sources
            .iter()
            .find(|sources| frame_ancestors_restrict(sources))
            .or_else(|| csp_frame_policy_sources.first())
            .cloned();
        let csp_frame_evidence_sources = csp_frame_sources.as_ref().map(|sources| {
            sources
                .iter()
                .map(|source| header_evidence_value(source))
                .collect::<Vec<_>>()
        });
        let csp_frame_evidence_policies = csp_frame_policy_sources
            .iter()
            .map(|sources| {
                sources
                    .iter()
                    .map(|source| header_evidence_value(source))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // An enforced response-header frame-ancestors directive takes
        // precedence over X-Frame-Options in supporting browsers. A broad
        // frame-ancestors rule therefore cannot be rescued by XFO: DENY.
        let response_frame_restricted = if has_csp_frame_directive {
            has_csp_frame
        } else {
            xfo_protects
        };
        // Browsers honor a CSP delivered via <meta http-equiv>, so a page
        // shipping one must not be reported as "no CSP" - but frame-ancestors
        // is ignored in the meta form, so it never counts for clickjacking.
        let meta_csp_value = if csp_value.is_none() {
            meta_delivered_policy(&ctx.body, &META_CSP_EQUIV_RE)
        } else {
            None
        };
        let csp_evidence_values: Vec<String> = csp_values
            .iter()
            .map(|value| csp_evidence_value(value))
            .collect();
        let csp_primary_evidence_value = csp_evidence_values.first().cloned();
        let meta_csp_evidence_value = meta_csp_value.as_deref().map(csp_evidence_value);
        let csp_report_only_evidence_value =
            csp_report_only_value.as_deref().map(csp_evidence_value);
        let enforced_csp = csp_value.as_deref().or(meta_csp_value.as_deref());
        // For a meta-delivered policy, suppress the frame-ancestors warning:
        // the meta form cannot express it, and the clickjacking check
        // reports the gap on its own.
        let mut csp_evaluation = evaluate_csp(
            enforced_csp,
            response_frame_restricted || meta_csp_value.is_some(),
        );
        if csp_policy_count > 1 {
            csp_evaluation.status = CheckStatus::Warn;
            csp_evaluation.severity = Severity::Low;
            csp_evaluation.title = "Multiple enforced CSP fields need combined review";
            csp_evaluation.description = format!("This response contains {} enforced Content-Security-Policy fields. Supporting browsers enforce all of them, so their restrictions intersect; a broad source in one field does not necessarily weaken a stricter field. SiteCMD does not collapse the complete multi-policy intersection into a definitive strength grade.", csp_policy_count);
            csp_evaluation.fix_prompt = Some("Review the enforced CSP fields as a combined policy set. Confirm the effective intersection in target browsers, then merge them into one reviewable policy when practical without weakening the restrictions.".into());
            csp_evaluation.manual_fix = Some("Inventory which origin, framework, proxy, and CDN layer emits each Content-Security-Policy field. Test the combined result with browser developer tools and CSP reports across representative routes. If the split is unintentional, consolidate to one enforced field; if intentional, document the intersection and keep each field syntactically valid.".into());
            csp_evaluation.why_it_matters = Some("Multiple CSP fields strengthen by intersection, but they can also create non-obvious breakage or make operator review inaccurate. Presence of multiple fields is not itself a vulnerability.".into());
            csp_evaluation.issues =
                vec!["multiple enforced CSP fields require combined evaluation".into()];
        }
        if meta_csp_value.is_some() {
            csp_evaluation.description.push_str(
                " The policy is delivered via a <meta http-equiv> tag: browsers enforce it, but frame-ancestors, report-uri, and sandbox directives are ignored in that form, and the policy only applies once the tag is parsed. Moving it to a response header closes those gaps.",
            );
        }
        // Report-Only without an enforced policy is monitoring, not
        // enforcement. It may be an intentional rollout; do not call it
        // stalled from one response.
        if enforced_csp.is_none() && csp_report_only_value.is_some() {
            csp_evaluation.status = CheckStatus::Warn;
            csp_evaluation.severity = Severity::Medium;
            csp_evaluation.title = "No enforced CSP; Report-Only policy is monitored";
            csp_evaluation.description = "A Content-Security-Policy-Report-Only header is present, but this response has no enforced Content-Security-Policy. Per CSP semantics, Report-Only monitors violations but does not enforce its restrictions: resources that would violate that policy are still allowed to load. This may be an intentional rollout or telemetry policy; the scan cannot determine rollout status or whether another control mitigates script injection.".to_string();
            csp_evaluation.fix_prompt = Some("Confirm the intended CSP rollout. If enforcement is ready, deploy a tested Content-Security-Policy header while retaining a separate Report-Only policy for proposed changes if useful.".into());
            csp_evaluation.manual_fix = Some("Review representative Report-Only telemetry, remove unsafe source allowances where practical, and test critical routes, third-party integrations, workers, frames, nonces/hashes, and reporting. Then deploy an enforced Content-Security-Policy header with a staged rollback plan; a separate stricter Report-Only policy can continue evaluating future changes.".into());
            csp_evaluation.why_it_matters = Some("A Report-Only policy supplies telemetry but does not enforce its restrictions; only an enforced policy provides CSP blocking for the covered response.".into());
        }
        results.push(CheckResult {
            check_id: "security.headers.csp".into(),
            category: ScanCategory::Security,
            title: csp_evaluation.title.into(),
            description: csp_evaluation.description,
            status: csp_evaluation.status,
            severity: csp_evaluation.severity,
            fix_prompt: csp_evaluation.fix_prompt,
            manual_fix: csp_evaluation.manual_fix,
            raw_data: if csp_value.is_some() {
                Some(serde_json::json!({
                    "current_value": csp_primary_evidence_value,
                    "current_values": csp_evidence_values,
                    "policy_count": csp_policy_count,
                    "policy_issues": csp_evaluation.issues,
                }))
            } else if meta_csp_value.is_some() {
                Some(serde_json::json!({
                    "current_value": meta_csp_evidence_value,
                    "delivered_via": "meta",
                    "policy_issues": csp_evaluation.issues,
                }))
            } else if csp_report_only_value.is_some() {
                Some(serde_json::json!({
                    "report_only_value": csp_report_only_evidence_value,
                }))
            } else {
                None
            },
            confidence: if csp_evaluation.status == CheckStatus::Warn {
                crate::vocab::IssueConfidence::NeedsReview
            } else {
                crate::vocab::IssueConfidence::High
            },
            confidence_reason: (csp_evaluation.status == CheckStatus::Warn).then(|| "The policy tokens are directly observed, but hardening recommendations depend on the site's resource, embedding, and compatibility requirements.".into()),
            why_it_matters: csp_evaluation.why_it_matters,
        });

        // Grade the parsed max-age against a one-year hardening baseline.
        let has_hsts = headers.contains_key("strict-transport-security");
        let hsts_header_count = headers.get_all("strict-transport-security").iter().count();
        let hsts_received_securely = ctx.url.scheme() == "https";
        let hsts_value = headers
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let hsts_evidence_value = hsts_value.as_deref().map(header_evidence_value);
        let hsts_policy = hsts_value.as_deref().map(parse_hsts_policy);
        let hsts_max_age = hsts_policy
            .as_ref()
            .and_then(|policy| policy.as_ref().ok())
            .map(|policy| policy.max_age);
        let hsts_include_subdomains = hsts_policy
            .as_ref()
            .and_then(|policy| policy.as_ref().ok())
            .map(|policy| policy.include_subdomains)
            .unwrap_or(false);
        let hsts_parse_error = if has_hsts {
            hsts_policy
                .as_ref()
                .and_then(|policy| policy.as_ref().err())
                .cloned()
                .or_else(|| {
                    hsts_value
                        .is_none()
                        .then(|| "the header value could not be represented as visible text".into())
                })
        } else {
            None
        };
        let hsts_parse_error_evidence = hsts_parse_error.as_deref().map(header_evidence_value);
        const HSTS_MIN_RECOMMENDED_SECS: u64 = 31_536_000; // 1 year
        let (
            hsts_status,
            hsts_severity,
            hsts_title,
            hsts_description,
            hsts_manual_fix,
            hsts_why_matters,
        ) = match (has_hsts, hsts_received_securely, hsts_max_age) {
                (false, false, _) => (
                    CheckStatus::Skipped,
                    Severity::Low,
                    "HSTS not evaluated on an insecure response",
                    "The fetched response used HTTP. User agents ignore Strict-Transport-Security received over insecure transport, so a missing HSTS field on this response is not graded separately; the HTTPS-enforcement finding covers the prerequisite transport problem.".to_string(),
                    None,
                    None,
                ),
                (false, true, _) => (
                    CheckStatus::Fail,
                    Severity::Medium,
                    "No Strict-Transport-Security header",
                    "No HSTS header was observed. A browser that follows an explicit `http://` URL before it has a cached HSTS policy can make a plaintext request before an HTTPS redirect, where an on-path attacker could interfere. Direct `https://` navigation remains encrypted. HSTS upgrades later HTTP attempts after the browser receives the policy; preload is a separate operational commitment that can cover first contact.".to_string(),
                    Some("Add HSTS at the deployed edge or server after you have confirmed every public route and subdomain already works over HTTPS. A common baseline is `max-age=31536000; includeSubDomains` (1 year). Skip the `preload` directive until you have audited every subdomain and intentionally submitted to hstspreload.org - removal takes months.".to_string()),
                    Some("HSTS removes the HTTP-to-HTTPS downgrade window for browsers that have cached the policy. Without it, users arriving through an HTTP URL can still be exposed to that first plaintext hop.".to_string()),
                ),
                (true, false, _) => (
                    CheckStatus::Warn,
                    Severity::Medium,
                    "Strict-Transport-Security was delivered over HTTP",
                    format!("Strict-Transport-Security is present on an HTTP response ({}), but conforming user agents ignore STS fields received over insecure transport. This does not establish an HSTS policy for the host.", hsts_evidence_value.as_deref().unwrap_or("unreadable value")),
                    Some("Serve the canonical response over HTTPS and emit the validated HSTS policy there. Redirect or disable HTTP separately, then verify the final HTTPS response and the cleartext-to-HTTPS path.".to_string()),
                    Some("An STS field on HTTP does not create the browser's cached HTTPS-only policy; transport enforcement must be established from an error-free secure response.".to_string()),
                ),
                (true, true, Some(0)) => (
                    // `max-age=0` is the directive used to TURN OFF HSTS.
                    // Browsers will forget the policy on next visit.
                    CheckStatus::Fail,
                    Severity::Medium,
                    "Strict-Transport-Security set to max-age=0",
                    format!("HSTS is set with `max-age=0` ({}), which instructs a conforming browser that receives it over HTTPS to remove the cached policy for this host. This may be an intentional rollback; otherwise it disables HSTS protection for later HTTP navigations.", hsts_evidence_value.as_deref().unwrap_or("")),
                    Some("If you meant to disable HSTS (mid-rollback), this header is correct and you can ignore the warning. Otherwise set a real max-age (e.g. `max-age=31536000; includeSubDomains`) after confirming every subdomain works over HTTPS.".to_string()),
                    Some("After the cached policy is removed, an explicit HTTP navigation can again reach plaintext before a redirect. The header may still be correct during a deliberate rollback.".to_string()),
                ),
                (true, true, None) => (
                    // RFC 6797 makes max-age required; browsers ignore an
                    // STS header without a parseable one, so this header is
                    // doing nothing.
                    CheckStatus::Fail,
                    Severity::Medium,
                    "Strict-Transport-Security has no usable max-age",
                    format!("HSTS is set ({}), but the field is not a usable RFC 6797 policy: {}. Conforming user agents ignore a syntactically invalid policy. HTTPS itself may still be enforced by redirects or other controls.", hsts_evidence_value.as_deref().unwrap_or("unreadable value"), hsts_parse_error_evidence.as_deref().unwrap_or("the required max-age directive was not parsed")),
                    Some("Set a real max-age (e.g. `Strict-Transport-Security: max-age=31536000; includeSubDomains`) after confirming every subdomain works over HTTPS.".to_string()),
                    Some("A header without a valid max-age does not provide the cached HTTP-upgrade behavior HSTS is intended to supply.".to_string()),
                ),
                (true, true, Some(secs)) if secs < HSTS_MIN_RECOMMENDED_SECS => (
                    CheckStatus::Warn,
                    Severity::Low,
                    "Strict-Transport-Security max-age below one year",
                    format!(
                        "HSTS is set with max-age={} (about {} {}). That policy is valid, but it expires sooner than the common one-year hardening baseline, so browsers that do not revisit before expiry can lose the cached upgrade rule.",
                        secs,
                        secs / 86_400,
                        if secs / 86_400 == 1 { "day" } else { "days" },
                    ),
                    Some(format!(
                        "Once you're confident every subdomain works over HTTPS, raise max-age to at least 31536000 (1 year): `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Keep `preload` off unless you've audited subdomains and submitted to hstspreload.org. Current value: max-age={}.",
                        secs,
                    )),
                    Some("After a cached HSTS policy expires, a later explicit HTTP navigation can again make a plaintext request before an HTTPS redirect unless another active policy or preload entry covers the host.".to_string()),
                ),
                (true, true, _) if hsts_header_count > 1 => (
                    CheckStatus::Warn,
                    Severity::Low,
                    "Multiple Strict-Transport-Security fields observed",
                    format!("This response contains {} Strict-Transport-Security fields. RFC 6797 user agents process only the first field, which parsed as max-age={}{}; later fields do not combine with it. Multiple fields make intermediary and operator behavior harder to review even when the first policy is usable.", hsts_header_count, hsts_max_age.unwrap_or_default(), if hsts_include_subdomains { " with includeSubDomains" } else { " without includeSubDomains" }),
                    Some("Configure the origin, proxy, and CDN to emit exactly one Strict-Transport-Security field containing the intended max-age and optional includeSubDomains/preload directives. Verify the field order and final HTTPS response at each public edge.".to_string()),
                    Some("Only the first STS field controls conforming RFC 6797 processing; a later field cannot repair or extend it.".to_string()),
                ),
                (true, true, _)
                    if !hsts_include_subdomains =>
                (
                    // Contextual: sibling hosts may carry their own policy,
                    // and includeSubDomains is unsafe until every host supports
                    // HTTPS. One response cannot inventory that estate.
                    CheckStatus::Warn,
                    Severity::Low,
                    "Strict-Transport-Security missing includeSubDomains",
                    format!(
                        "HSTS is set with a solid max-age ({}), but without `includeSubDomains` this policy applies only to the current host. Sibling subdomains may have their own HSTS policies or may intentionally lack HTTPS; this response cannot determine that. Enable `includeSubDomains` only after every current and future subdomain is HTTPS-ready.",
                        hsts_evidence_value.as_deref().unwrap_or(""),
                    ),
                    Some("Once every existing subdomain works over HTTPS, extend the policy: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.".to_string()),
                    Some("Without `includeSubDomains`, this host's policy does not automatically upgrade HTTP navigations to sibling subdomains. Whether that is a material gap depends on the subdomain inventory and each host's own HTTPS/HSTS configuration.".to_string()),
                ),
                (true, true, _) => (
                    CheckStatus::Pass,
                    Severity::Low,
                    "Strict-Transport-Security (HSTS)",
                    format!(
                        "HSTS header is set ({}). When a conforming browser receives this header over HTTPS, it caches the policy and upgrades later HTTP navigations to this host for the specified duration.",
                        hsts_evidence_value.as_deref().unwrap_or(""),
                    ),
                    None,
                    None,
                ),
            };
        results.push(CheckResult {
            check_id: "security.headers.hsts".into(),
            category: ScanCategory::Security,
            title: hsts_title.into(),
            description: hsts_description,
            status: hsts_status,
            severity: hsts_severity,
            fix_prompt: None,
            manual_fix: hsts_manual_fix,
            raw_data: has_hsts.then(|| serde_json::json!({
                "current_value": hsts_evidence_value,
                "max_age_secs": hsts_max_age,
                "include_subdomains": hsts_include_subdomains,
                "parse_error": hsts_parse_error_evidence,
                "header_count": hsts_header_count,
                "received_over_https": hsts_received_securely,
            })),
            confidence: if hsts_title.contains("includeSubDomains") {
                crate::vocab::IssueConfidence::NeedsReview
            } else {
                crate::vocab::IssueConfidence::High
            },
            confidence_reason: if hsts_title.contains("includeSubDomains") {
                Some("The directive is observably absent on this response, but the scan does not inventory sibling subdomains, their own HSTS policies, or whether all of them can safely support inherited HTTPS enforcement.".into())
            } else {
                None
            },
            why_it_matters: hsts_why_matters,
        });

        // X-Frame-Options
        let frame_protected = response_frame_restricted;
        let xfo_ignored_value = xfo_value
            .as_deref()
            .filter(|_| !xfo_protects && !has_csp_frame_directive);
        results.push(CheckResult {
            check_id: "security.headers.x_frame_options".into(),
            category: ScanCategory::Security,
            title: if frame_protected {
                "Clickjacking protection".into()
            } else if xfo_ignored_value.is_some() {
                "X-Frame-Options value is ignored by browsers".into()
            } else if has_csp_frame_directive {
                "CSP frame-ancestors does not restrict cross-origin framing".into()
            } else {
                "No response-level framing restriction observed".into()
            },
            description: if frame_protected {
                if has_csp_frame_directive {
                    let sources = csp_frame_sources.as_deref().unwrap_or_default();
                    if csp_frame_policy_sources.len() > 1 {
                        format!("This response has {} enforced CSP frame-ancestors directives. Supporting browsers enforce all policy fields, so a framing ancestor must satisfy their intersection; at least one observed list is restrictive. Review the complete lists in the evidence rather than treating any single field as the effective policy.", csp_frame_policy_sources.len())
                    } else if sources.is_empty() || sources.iter().all(|source| source == "'none'") {
                        "The enforced response-header CSP contains frame-ancestors 'none', which instructs supporting browsers to reject every framing ancestor for this response.".to_string()
                    } else {
                        format!(
                            "The enforced response-header CSP restricts framing with frame-ancestors. Supporting browsers compare the full ancestor chain with this source list: {}.",
                            sources.iter().map(|source| header_evidence_value(source)).collect::<Vec<_>>().join(" ")
                        )
                    }
                } else if xfo_value
                    .as_deref()
                    .is_some_and(|value| value.trim().eq_ignore_ascii_case("deny"))
                {
                    "X-Frame-Options: DENY instructs supporting browsers not to render this response in a frame. This header check does not test legacy/non-browser clients or application-level framing behavior.".to_string()
                } else {
                    "X-Frame-Options: SAMEORIGIN instructs supporting browsers to allow framing only when every relevant framing ancestor is same-origin. This header check does not test legacy/non-browser clients or application-level controls.".to_string()
                }
            } else if let Some(value) = xfo_ignored_value {
                let allow_from_note = if value.trim().to_ascii_lowercase().starts_with("allow-from") {
                    " ALLOW-FROM is not part of the X-Frame-Options processing supported by current major browsers; use CSP frame-ancestors for origin-specific framing rules."
                } else {
                    ""
                };
                format!("X-Frame-Options is set to \"{}\", but modern browsers honor only DENY and SAMEORIGIN and ignore this value, so this header does not restrict framing.{} If this page exposes authenticated, sensitive actions without an independent confirmation, cross-origin framing can enable clickjacking.", header_evidence_value(value), allow_from_note)
            } else if has_csp_frame_directive {
                if csp_frame_policy_sources.len() > 1 {
                    format!("This response has {} enforced CSP frame-ancestors directives, but none of their source lists restricts cross-origin framing. Supporting browsers enforce all CSP policy fields and give frame-ancestors precedence over X-Frame-Options, so XFO does not restore a tighter response rule. Impact depends on whether this route exposes consequential authenticated actions.", csp_frame_policy_sources.len())
                } else { format!(
                    "An enforced response-header CSP frame-ancestors directive is present, but its source list ({}) does not restrict cross-origin framing. In supporting browsers, that directive takes precedence over X-Frame-Options{}, so XFO does not restore a tighter rule. This is consequential when the response exposes authenticated actions without an independent confirmation or equivalent defense.",
                    csp_frame_evidence_sources.as_deref().unwrap_or_default().join(" "),
                    if xfo_protects { " on this response" } else { "" },
                ) }
            } else {
                "No recognized X-Frame-Options value or restrictive response-header CSP frame-ancestors policy was observed. Other origins can attempt to frame this response, but that becomes a clickjacking risk only when the framed route exposes consequential actions without an independent confirmation or equivalent defense.".into()
            },
            status: if frame_protected { CheckStatus::Pass } else { CheckStatus::Warn },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if frame_protected { None } else {
                Some("Block framing at the layer that already owns your headers. Use `X-Frame-Options: DENY` or `SAMEORIGIN`, or set the equivalent `frame-ancestors` rule in CSP if that is how your stack manages clickjacking protection.".into())
            },
            raw_data: if xfo_value.is_some() || has_csp_frame_directive {
                Some(serde_json::json!({
                    "x_frame_options": xfo_value.as_deref().map(header_evidence_value),
                    "csp_frame_ancestors": csp_frame_evidence_sources,
                    "csp_frame_ancestor_policies": csp_frame_evidence_policies,
                    "effective_response_restriction": frame_protected,
                    "csp_takes_precedence": has_csp_frame_directive,
                }))
            } else {
                None
            },
                confidence: if frame_protected { crate::vocab::IssueConfidence::High } else { crate::vocab::IssueConfidence::NeedsReview },
                confidence_reason: if frame_protected { None } else { Some("The response-level framing policy is directly observed, but SiteCMD cannot determine whether this route exposes consequential authenticated actions or has an equivalent application-level confirmation defense.".into()) },
                why_it_matters: if frame_protected { None } else {
                    Some("On a sensitive authenticated page, hostile framing can visually disguise controls and induce a user to activate an action they did not intend. The impact depends on which routes are frameable and their transaction safeguards.".into())
                },
        });

        // X-Content-Type-Options
        let xcto_value = headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok())
            .map(|value| value.trim().to_string());
        let xcto_evidence_value = xcto_value.as_deref().map(header_evidence_value);
        let has_xcto = xcto_value
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("nosniff"))
            .unwrap_or(false);
        results.push(CheckResult {
            check_id: "security.headers.x_content_type_options".into(),
            category: ScanCategory::Security,
            title: if has_xcto {
                "X-Content-Type-Options".into()
            } else if xcto_value.is_some() {
                "X-Content-Type-Options has an unrecognized value".into()
            } else {
                "No X-Content-Type-Options header".into()
            },
            description: if has_xcto {
                "`X-Content-Type-Options: nosniff` is set. In the contexts where browsers apply this header, they rely on the declared Content-Type instead of MIME-sniffing a different type.".into()
            } else if let Some(value) = xcto_evidence_value.as_deref() {
                format!("X-Content-Type-Options is set to '{}', not the recognized `nosniff` value, so this response does not establish MIME-sniffing protection. Exploitation still requires attacker-influenced content to be served with an unsafe or incorrect type/context.", value)
            } else {
                "No `X-Content-Type-Options: nosniff` header was observed. In applicable request contexts, browsers may infer a response type instead of relying only on the declared Content-Type. Exploitation also requires attacker-influenced content to be served with an unsafe or incorrect type/context; the missing header alone does not make an upload executable.".into()
            },
            status: if has_xcto { CheckStatus::Pass } else { CheckStatus::Warn },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if has_xcto { None } else {
                Some("Return `X-Content-Type-Options: nosniff` from the server or edge layer that owns response headers, and also serve every asset/upload with the correct Content-Type. Verify representative scripts, styles, downloads, and user-uploaded files after enabling it.".into())
            },
            raw_data: xcto_evidence_value.as_ref().map(|value| serde_json::json!({"current_value": value, "recognized": has_xcto})),
                confidence: if has_xcto { crate::vocab::IssueConfidence::High } else { crate::vocab::IssueConfidence::NeedsReview },
                confidence_reason: if has_xcto { None } else { Some("The header posture is directly observed, but exploitability depends on the response types, upload/content controls, and browser request contexts used by the application.".into()) },
                why_it_matters: if has_xcto { None } else {
                    Some("`nosniff` reduces content-type confusion. It is most relevant when untrusted files or generated responses could be served with an incorrect MIME type in a script or style context.".into())
                },
        });

        // Grade policy values from the header or browser-supported meta form.
        let header_referrer = crate::header_lines::field_value(headers, "referrer-policy");
        let meta_referrer = if header_referrer.is_none() {
            meta_delivered_policy(&ctx.body, &META_REFERRER_NAME_RE)
        } else {
            None
        };
        let referrer_from_meta = meta_referrer.is_some();
        let referrer_value = header_referrer.or(meta_referrer);
        let has_referrer = referrer_value.is_some();
        let referrer_evidence_value = referrer_value.as_deref().map(header_evidence_value);
        let referrer_normalized = referrer_value
            .as_deref()
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_default();
        let recognized_referrer_policy = |policy: &str| {
            matches!(
                policy,
                "no-referrer"
                    | "no-referrer-when-downgrade"
                    | "origin"
                    | "origin-when-cross-origin"
                    | "same-origin"
                    | "strict-origin"
                    | "strict-origin-when-cross-origin"
                    | "unsafe-url"
            )
        };
        // A header list uses the last token the browser understands. The meta
        // form accepts one policy keyword rather than a comma fallback list.
        let referrer_last = if referrer_from_meta {
            let policy = referrer_normalized.trim();
            recognized_referrer_policy(policy).then(|| policy.to_string())
        } else {
            referrer_normalized
                .split(',')
                .map(str::trim)
                .rfind(|policy| recognized_referrer_policy(policy))
                .map(str::to_string)
        };
        let is_leaky_referrer = matches!(
            referrer_last.as_deref(),
            Some("unsafe-url" | "no-referrer-when-downgrade")
        );
        let (
            referrer_status,
            referrer_severity,
            referrer_title,
            referrer_desc,
            referrer_fix,
            referrer_why,
        ) = match (has_referrer, is_leaky_referrer, referrer_last.as_deref()) {
                (false, _, _) => (
                    CheckStatus::Warn,
                    Severity::Low,
                    "No Referrer-Policy header",
                    "No Referrer-Policy header or meta policy was observed. Modern browsers generally default to strict-origin-when-cross-origin, which keeps paths and query strings out of ordinary cross-origin Referer headers. An explicit policy makes the page's intended default reviewable and lets you choose something stricter, although individual links and requests can define their own referrer policy.".to_string(),
                    Some("Set a referrer policy in your server or edge headers, usually `strict-origin-when-cross-origin` unless you have a stronger privacy requirement. An explicit policy pins the referrer behavior instead of leaving it to browser defaults.".to_string()),
                    Some("Without an explicit policy, the URL information sent with navigations and subresource requests depends on browser defaults and any per-element or per-request overrides.".to_string()),
                ),
                (true, _, None) => (
                    CheckStatus::Warn,
                    Severity::Low,
                    "Referrer-Policy has no recognized policy",
                    format!("A Referrer-Policy value is present ('{}'), but SiteCMD found no currently recognized policy keyword in the applicable position. Supporting browsers fall back to their default behavior rather than treating an unknown token as a new restriction.", referrer_evidence_value.as_deref().unwrap_or("unreadable value")),
                    Some("Replace the value with a recognized policy chosen for the site's privacy and analytics requirements, commonly `strict-origin-when-cross-origin`, and test representative navigation and subresource requests. If using header fallbacks, list older recognized policies first and the preferred recognized policy last.".to_string()),
                    Some("An unrecognized value does not pin referrer behavior; the browser default and request-specific overrides remain in effect.".to_string()),
                ),
                (true, true, _) => (
                    CheckStatus::Warn,
                    Severity::Medium,
                    "Referrer-Policy permits path and query cross-origin",
                    format!(
                        "The effective Referrer-Policy is '{}' (from '{}'). This policy can send the page's path and query in same-security cross-origin Referer headers for navigations and subresource requests; URL fragments are not sent as referrers.",
                        referrer_last.as_deref().unwrap_or(""),
                        referrer_evidence_value.as_deref().unwrap_or(""),
                    ),
                    Some("Use `strict-origin-when-cross-origin` unless the site has a documented reason to send path/query detail cross-origin, or choose a stricter recognized policy. Remove secrets from URLs independently: referrer policy is defense in depth, and request-specific overrides can differ.".to_string()),
                    Some("A path or query can contain private identifiers or state. These policies permit more cross-origin referrer detail than origin-only policies, although actual disclosure depends on the destination, downgrade rules, and request-specific overrides.".to_string()),
                ),
                (true, false, _) => (
                    CheckStatus::Pass,
                    Severity::Low,
                    "Referrer-Policy header",
                    format!(
                        "The recognized effective Referrer-Policy is '{}'{} (declared value: '{}'). This establishes the response-level default; individual elements and requests can override it, and the check does not inspect resulting network traffic.",
                        referrer_last.as_deref().unwrap_or("set"),
                        if referrer_from_meta {
                            " via a <meta name=\"referrer\"> tag"
                        } else {
                            ""
                        },
                        referrer_evidence_value.as_deref().unwrap_or("set"),
                    ),
                    None,
                    None,
                ),
            };
        results.push(CheckResult {
            check_id: "security.headers.referrer_policy".into(),
            category: ScanCategory::Security,
            title: referrer_title.into(),
            description: referrer_desc,
            status: referrer_status,
            severity: referrer_severity,
            fix_prompt: None,
            manual_fix: referrer_fix,
            raw_data: referrer_evidence_value.as_ref().map(|v| {
                serde_json::json!({
                    "current_value": v,
                    "effective_policy": referrer_last,
                    "delivered_via": if referrer_from_meta { "meta" } else { "header" },
                })
            }),
            confidence: if has_referrer && referrer_last.is_none() {
                crate::vocab::IssueConfidence::NeedsReview
            } else {
                crate::vocab::IssueConfidence::High
            },
            confidence_reason: if has_referrer && referrer_last.is_none() {
                Some("The supplied token is directly observed, but a future policy could become supported after this scanner version; verify it against current target-browser documentation.".into())
            } else {
                None
            },
            why_it_matters: referrer_why,
        });

        // Permissions-Policy
        let has_permissions = headers.contains_key("permissions-policy");
        let perms_value = crate::header_lines::field_value(headers, "permissions-policy");
        let perms_evidence_value = perms_value.as_deref().map(header_evidence_value);
        results.push(CheckResult {
            check_id: "security.headers.permissions_policy".into(),
            category: ScanCategory::Security,
            title: if has_permissions {
                "Permissions-Policy header".into()
            } else {
                "No Permissions-Policy header".into()
            },
            description: if has_permissions {
                "A Permissions-Policy header is present. This is a presence check only: SiteCMD does not fully parse the Structured Fields grammar, validate each feature name or allowlist, or determine which browser features the page actually uses.".into()
            } else {
                "No Permissions-Policy header. Embedded third-party code may be able to request or use powerful browser features when the page or user permissions allow it. Permissions-Policy lets you disable features your site does not need.".into()
            },
            status: if has_permissions { CheckStatus::Pass } else { CheckStatus::Warn },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if has_permissions { None } else {
                Some("Declare a Permissions-Policy at the server or CDN layer that disables browser features your site does not need, then open specific features back up only if the app truly uses them. Camera, microphone, and geolocation are good defaults to deny first.".into())
            },
            raw_data: if has_permissions {
                perms_evidence_value.as_ref().map(|v| serde_json::json!({"current_value": v}))
            } else {
                Some(serde_json::json!({"security_headers_present": header_names.iter().filter(|h| {
                    let hl = h.to_lowercase();
                    hl.starts_with("x-") || hl.starts_with("content-security") || hl.starts_with("strict-") || hl == "referrer-policy" || hl == "permissions-policy"
                }).collect::<Vec<_>>()}))
            },
                confidence: if has_permissions { crate::vocab::IssueConfidence::NeedsReview } else { crate::vocab::IssueConfidence::High },
                confidence_reason: if has_permissions { Some("Header presence is direct evidence, but this check does not yet validate the complete policy grammar, feature support, or effective behavior in target browsers.".into()) } else { None },
                why_it_matters: if has_permissions { None } else {
                    Some("Permissions-Policy limits which embedded third-party code may even request powerful features like camera, microphone, or location (users still see a permission prompt either way).".into())
                },
        });

        results
    }

    fn skip_in_predeploy(&self) -> bool {
        false // Headers can still be checked on localhost
    }
}

#[cfg(test)]
mod tests;
