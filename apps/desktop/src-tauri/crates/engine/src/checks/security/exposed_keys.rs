//! Detects credential-shaped values delivered in page HTML or JavaScript.
//!
//! Matches prove public text delivery, not validity, ownership, or privilege.

use super::key_patterns::{KeyClass, KEY_PATTERNS};
use crate::checks::{
    Check, CheckResult, CheckStatus, IssueConfidence, PageContext, ScanCategory, Severity,
};

pub struct ExposedApiKeysCheck;

fn mask_key(key: &str) -> String {
    let prefix_end = crate::checks::floor_char_boundary(key, key.len().min(4));
    format!("{}***", &key[..prefix_end])
}

impl Check for ExposedApiKeysCheck {
    fn id(&self) -> &str {
        "security.vibe.exposed_keys"
    }
    fn emitted_ids(&self) -> Vec<String> {
        vec![
            "security.vibe.exposed_keys".to_string(),
            "security.vibe.exposed_keys.public".to_string(),
        ]
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let mut secret_found: Vec<(String, String)> = Vec::new();
        let mut public_found: Vec<(String, String)> = Vec::new();

        for pattern in KEY_PATTERNS.iter() {
            for caps in pattern.regex.captures_iter(&ctx.body) {
                let Some(mat) = caps.get(pattern.key_group) else {
                    continue;
                };
                let entry = (pattern.service.to_string(), mask_key(mat.as_str()));
                match pattern.class {
                    KeyClass::Secret => secret_found.push(entry),
                    KeyClass::Public => public_found.push(entry),
                }
            }
        }

        // Report each service at most once per class.
        secret_found.dedup_by(|a, b| a.0 == b.0);
        public_found.dedup_by(|a, b| a.0 == b.0);

        let mut results = Vec::new();

        // Secret-key-format literals in client source. Static matching does
        // not validate them at a provider or establish account ownership.
        if !secret_found.is_empty() {
            let services = secret_found
                .iter()
                .map(|(s, _)| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let listed = secret_found
                .iter()
                .map(|(s, k)| format!("{} ({})", s, k))
                .collect::<Vec<_>>()
                .join(", ");
            // The count is per service (each service is reported once even if
            // several of its keys leaked), and test-mode keys must not get
            // the live-key "privileged access" framing.
            let service_count = secret_found.len();
            let has_non_test_key_shape =
                secret_found.iter().any(|(s, _)| !s.contains("(test mode)"));
            let has_test_key = secret_found.iter().any(|(s, _)| s.contains("(test mode)"));
            let mut description = format!(
                "Credential-shaped text matching secret-key formats for {} service{} was found in page source: {}. Pattern matching confirms the text is publicly delivered, but it does not establish that a credential is genuine, active, belongs to this site's operator, or has any particular privileges.",
                service_count,
                if service_count == 1 { "" } else { "s" },
                listed
            );
            if has_test_key {
                description.push_str(
                    " The Stripe `sk_test_` format is limited to test-mode resources and test data if the value is genuine; it cannot access live-mode data.",
                );
            }
            let fix_prompt = if has_non_test_key_shape {
                format!(
                    "Review credential-format values for {} service{} that are present in public client code: {}. \
                     Inspect the original values only in the local source tree or the relevant provider console; do not paste them into third-party tools. \
                     If a value is an active secret, revoke or rotate it first, remove it from browser-delivered code and build artifacts, and move the privileged operation behind an authenticated server-side boundary. \
                     If it is a fixture, placeholder, or revoked value, remove or clearly replace it so it cannot be mistaken for an active credential.",
                    service_count,
                    if service_count == 1 { "" } else { "s" },
                    services
                )
            } else {
                format!(
                    "Review the Stripe test-mode secret-key-shaped value present in public client code ({}). \
                     Confirm it in the Stripe Dashboard without copying it to a third-party tool. If genuine, rotate it, remove it from browser-delivered code and build artifacts, and perform secret-key operations behind a server-side boundary. \
                     Although a genuine `sk_test_` value cannot access live-mode data, it should still be handled as a secret.",
                    services,
                )
            };
            results.push(CheckResult {
                check_id: "security.vibe.exposed_keys".into(),
                category: ScanCategory::Security,
                title: "Credential-format key visible in page source".into(),
                description,
                status: CheckStatus::Fail,
                severity: if has_non_test_key_shape {
                    Severity::High
                } else {
                    Severity::Medium
                },
                fix_prompt: Some(fix_prompt),
                manual_fix: Some(
                    "1. Locate the original value in the local source/build pipeline; do not reveal it in tickets, chat, screenshots, or third-party decoders.\n\
                     2. Use the named provider's console or CLI to determine whether it is genuine, active, and associated with your account.\n\
                     3. If active, revoke or rotate it before relying on a code change, then review provider logs and privileges for unexpected use.\n\
                     4. Remove it from source, generated assets, caches, and deployment configuration; put privileged provider calls behind an authenticated server-side endpoint.\n\
                     5. Rebuild and re-scan the deployed site. If the value entered version history, follow the provider's incident guidance; deleting the current line does not erase history.".into()
                ),
                raw_data: Some(serde_json::json!({
                    "exposed_keys": secret_found.iter().map(|(s, k)| format!("{}: {}", s, k)).collect::<Vec<_>>(),
                    "key_class": "secret",
                })),
                confidence: IssueConfidence::NeedsReview,
                confidence_reason: Some(
                    "The scanner verified a public text match to a provider-style credential format, but it does not contact the provider or prove the value is genuine, active, owned by this site, or privileged.".into(),
                ),
                why_it_matters: Some(
                    "If any matched value is an active secret, anyone who can retrieve the page can copy it and exercise whatever permissions the provider assigned, potentially affecting data, services, or billing. A fixture, placeholder, revoked value, or unrelated format collision has no such access, which is why provider-side verification is required.".into(),
                ),
            });
        }

        // Client-visible key/token patterns. Stripe publishable and many AIza
        // keys are designed for browser delivery with suitable restrictions;
        // the generic HS256 JWT pattern is not attributable or classifiable
        // without inspecting its source and claims locally.
        if !public_found.is_empty() {
            let listed = public_found
                .iter()
                .map(|(s, k)| format!("{} ({})", s, k))
                .collect::<Vec<_>>()
                .join(", ");
            let has_ambiguous_jwt = public_found
                .iter()
                .any(|(service, _)| service.starts_with("JWT"));
            let has_stripe_publishable = public_found
                .iter()
                .any(|(service, _)| service == "Stripe Publishable");
            let has_google_api = public_found
                .iter()
                .any(|(service, _)| service == "Google API / Firebase");

            let mut classification_notes = Vec::new();
            let mut review_steps = Vec::new();
            let mut manual_steps = vec![
                "Identify each matched value in the local source and its provider's own console. Do not paste a potentially sensitive value into a public or third-party inspection tool.".to_string(),
            ];
            let mut impact_notes = Vec::new();

            if has_stripe_publishable {
                classification_notes.push("Stripe `pk_` publishable keys are designed to be public client identifiers and cannot authorize secret-key API operations; confirm only that the key's mode and account are the ones this site intends.");
                review_steps.push("For the Stripe `pk_` value, which is designed to be public, confirm the expected test/live mode and account and verify that no `sk_` or `rk_` credential is shipped.");
                manual_steps.push("Stripe `pk_live_` / `pk_test_`: confirm the key belongs to the intended account and mode. Its presence in browser code is expected; keep `sk_` and `rk_` credentials server-side.".to_string());
                impact_notes.push("A Stripe publishable key is not a secret; the relevant review is whether the site uses the intended account and mode and whether a separate secret credential was accidentally shipped.");
            }
            if has_google_api {
                classification_notes.push("A Google/Firebase `AIza` key is commonly delivered to browser apps; its effective scope depends on provider-side API and application restrictions that this scan cannot query.");
                review_steps.push("For the Google/Firebase `AIza` value, verify the required API and supported application restrictions in Google Cloud Console; the correct restriction type depends on the API.");
                manual_steps.push("Google / Firebase `AIza...`: in Google Cloud Console, confirm the key is restricted to the APIs and supported application boundary the site actually needs. Some APIs support different restriction types, so follow that API's current provider guidance.".to_string());
                impact_notes.push("A Google API key identifier is not treated as a password, but absent or overly broad provider restrictions can permit use outside the intended application within the APIs enabled for that key.");
            }
            if has_ambiguous_jwt {
                classification_notes.push("An HS256 JWT is not inherently publishable: it can be a Supabase anon key, a privileged Supabase service-role key, an application session, or another vendor token, and this source scan cannot distinguish those cases.");
                review_steps.push("For the JWT, identify its source and inspect it only with trusted local tooling or first-party provider controls. If it is a Supabase token, verify its role and Row Level Security; if it is a user session or privileged service token, investigate the exposure and revoke or rotate it as appropriate.");
                manual_steps.push("JWT: inspect its header and claims with trusted local tooling. If it is a Supabase token, verify the role and test Row Level Security for every client-accessible table. If it is a session or privileged token, determine how it reached static page source and revoke or rotate it if exposure was unintended.".to_string());
                impact_notes.push("A JWT can be an intentionally public role token or a credential with materially greater access; impact depends on its issuer, claims, expiry, role, and server-side authorization controls.");
            }
            manual_steps.push(
                "After any provider-side or code change, rebuild and re-scan the deployed page and verify expected client behavior.".to_string(),
            );
            let manual_fix = manual_steps
                .iter()
                .enumerate()
                .map(|(index, step)| format!("{}. {}", index + 1, step))
                .collect::<Vec<_>>()
                .join("\n");
            results.push(CheckResult {
                check_id: "security.vibe.exposed_keys.public".into(),
                category: ScanCategory::Security,
                title: if has_ambiguous_jwt {
                    "Client-visible JWT or publishable-key pattern".into()
                } else {
                    "Publishable / browser-key pattern detected".into()
                },
                description: format!(
                    "Client-visible key or token patterns for {} service{} were detected: {}. {}",
                    public_found.len(),
                    if public_found.len() == 1 { "" } else { "s" },
                    listed,
                    classification_notes.join(" ")
                ),
                status: CheckStatus::Warn,
                severity: if has_ambiguous_jwt {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                fix_prompt: Some(format!(
                    "Review the client-visible key/token patterns for {} service{}: {}. {}",
                    public_found.len(),
                    if public_found.len() == 1 { "" } else { "s" },
                    listed,
                    review_steps.join(" ")
                )),
                manual_fix: Some(manual_fix),
                raw_data: Some(serde_json::json!({
                    "exposed_keys": public_found.iter().map(|(s, k)| format!("{}: {}", s, k)).collect::<Vec<_>>(),
                    "key_class": "public",
                })),
                confidence: IssueConfidence::NeedsReview,
                confidence_reason: Some(
                    "The scanner can identify the text format, but it cannot determine provider ownership, configured restrictions, token claims, expiry, revocation state, or whether client delivery was intentional.".into(),
                ),
                why_it_matters: Some(impact_notes.join(" ")),
            });
        }

        // Clean: single Pass result.
        if results.is_empty() {
            results.push(CheckResult {
                check_id: "security.vibe.exposed_keys".into(),
                category: ScanCategory::Security,
                title: "Client-visible credential patterns".into(),
                description: "No supported API key or token patterns were found in the fetched page source. This pattern check does not inspect unfetched bundles, runtime network responses, or server-side storage.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            });
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderMap;

    fn ctx(body: &str) -> PageContext {
        PageContext {
            evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: HeaderMap::new(),
            status_code: 200,
            body: body.to_string(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: Some("HTTP/2.0".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn clean_page_passes() {
        let html = "<html><body><p>Hello world</p></body></html>";
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Pass);
        assert_eq!(results[0].title, "Client-visible credential patterns");
        assert!(results[0].description.contains("supported"));
        assert!(results[0].description.contains("does not inspect"));
    }

    #[test]
    fn detects_openai_key_as_high_needs_review_secret_shape() {
        let html = r#"<script>const key = "sk-proj1234567890abcdefghij";</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert_eq!(results[0].severity, Severity::High);
        assert_eq!(results[0].confidence, IssueConfidence::NeedsReview);
        assert!(results[0].description.contains("does not establish"));
        assert!(results[0].description.contains("OpenAI"));
    }

    #[test]
    fn detects_modern_openai_project_key_as_high_needs_review() {
        let html = r#"<script>const key = "sk-proj-T3BlbkFJabcdefghijklmnop1234567890";</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert_eq!(results[0].severity, Severity::High);
        assert!(results[0].description.contains("OpenAI"));
    }

    #[test]
    fn anthropic_key_is_not_misreported_as_openai() {
        // The broadened OpenAI pattern must not steal `sk-ant-` keys.
        let html = r#"<script>const key = "sk-ant-abcdefghijklmnopqrstuvwxyz0123";</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert!(results[0].description.contains("Anthropic"));
        assert!(!results[0].description.contains("OpenAI"));
    }

    #[test]
    fn detects_stripe_live_secret_shape_as_high_needs_review() {
        let html = r#"<script>Stripe("sk_live_1234567890abcdefghijklmn");</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert_eq!(results[0].severity, Severity::High);
        assert!(results[0].description.contains("Stripe"));
    }

    #[test]
    fn detects_aws_key_shape_as_high_needs_review() {
        let html = r#"<script>const aws = "AKIAIOSFODNN7EXAMPLE";</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert_eq!(results[0].severity, Severity::High);
        assert!(results[0].description.contains("AWS"));
    }

    #[test]
    fn detects_github_token_shape_as_high_needs_review() {
        let html =
            r#"<script>const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert_eq!(results[0].severity, Severity::High);
        assert!(results[0].description.contains("GitHub"));
    }

    #[test]
    fn no_false_positive_on_short_sk_prefix() {
        let html = r#"<script>const x = "sk-short";</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Pass);
    }

    #[test]
    fn sk_inside_larger_words_is_not_an_openai_key() {
        let html = r#"<div id="risk-assessmentquestionnaire2024" data-job="task-38f2a91c4b7d4e219a03bc45"></div>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(
            results[0].status,
            CheckStatus::Pass,
            "{}",
            results[0].description
        );
    }

    #[test]
    fn cache_key_hash_is_not_a_mailgun_key() {
        let html = r#"<script>const k = "cache-key-0123456789abcdef0123456789abcdef";</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(
            results[0].status,
            CheckStatus::Pass,
            "{}",
            results[0].description
        );
    }

    #[test]
    fn standalone_mailgun_key_is_still_detected() {
        let html = r#"<script>const mg = "key-0123456789abcdef0123456789abcdef";</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert!(results[0].description.contains("Mailgun"));
    }

    #[test]
    fn hs256_jwt_is_labeled_possibly_supabase_not_asserted_supabase() {
        // The pattern is just the base64 of {"alg":"HS256","typ":"JWT"}, so
        // it matches ANY HS256 JWT; the label must not assert the service.
        let html = r#"<script>const t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InRlc3QifQ.abcdefghijklmnopqrstuv";</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert_eq!(results[0].severity, Severity::Medium);
        assert!(
            results[0].description.contains("JWT (possibly Supabase)"),
            "{}",
            results[0].description
        );
        assert!(!results[0].description.contains("Supabase Key"));
    }

    #[test]
    fn stripe_test_key_gets_test_mode_copy_not_privileged_access() {
        let html = r#"<script>Stripe("sk_test_1234567890abcdefghijklmn");</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert_eq!(results[0].severity, Severity::Medium);
        assert!(results[0].description.contains("test mode"));
        assert!(results[0].description.contains("test data"));
        assert!(!results[0].description.contains("privileged access"));
        let prompt = results[0].fix_prompt.as_deref().unwrap();
        assert!(!prompt.starts_with("URGENT"), "{}", prompt);
    }

    #[test]
    fn secret_count_says_services_not_keys() {
        // Two different keys for the same service dedup to one service; the
        // copy must count services, not claim a key count it cannot know.
        let html = r#"<script>
            const a = "sk-proj-T3BlbkFJabcdefghijklmnop1234567890";
            const b = "sk-proj-QW5vdGhlcktleUZha2UxMjM0NTY3ODkw";
        </script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert!(
            results[0]
                .description
                .contains("secret-key formats for 1 service"),
            "{}",
            results[0].description
        );
        assert!(!results[0].description.contains("key(s)")); // allow-lazy-plural
    }

    #[test]
    fn publishable_key_advice_does_not_conflate_restricted_keys_or_webhooks() {
        let html = r#"<script>Stripe("pk_live_1234567890abcdefghijklmn");</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        let prompt = results[0].fix_prompt.as_deref().unwrap();
        assert!(!prompt.contains("restricted-account settings"));
        assert!(!prompt.contains("webhook signature"));
        assert!(prompt.contains("designed to be public"), "{}", prompt);
        assert!(!prompt.contains("Google/Firebase"), "{}", prompt);
        assert!(!prompt.contains("For the JWT"), "{}", prompt);
        let manual = results[0].manual_fix.as_deref().unwrap();
        assert!(!manual.contains("Google / Firebase"), "{}", manual);
        assert!(!manual.contains("JWT:"), "{}", manual);
    }

    #[test]
    fn keys_are_masked_in_output() {
        let html = r#"<script>const key = "sk_live_1234567890abcdefghijklmn";</script>"#; // gitleaks:allow
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert!(!results[0]
            .description
            .contains("sk_live_1234567890abcdefghijklmn")); // gitleaks:allow
        let raw = results[0].raw_data.as_ref().unwrap().to_string();
        assert!(
            !raw.contains("klmn"),
            "masked suffix must not be persisted: {raw}"
        );
    }

    #[test]
    fn stripe_publishable_key_is_low_advisory_not_critical() {
        let html = r#"<script>Stripe("pk_live_1234567890abcdefghijklmn");</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert_eq!(results[0].severity, Severity::Low);
        assert!(results[0].title.contains("Publishable"));
        assert!(results[0].description.contains("Stripe Publishable"));
    }

    #[test]
    fn firebase_or_google_maps_aiza_key_is_low_advisory_not_critical() {
        let html = r#"<script>const config = { apiKey: "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" };</script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert_eq!(results[0].severity, Severity::Low);
        assert!(results[0].description.contains("Google API / Firebase"));
    }

    #[test]
    fn an_identifier_ending_in_a_hex_hash_is_not_a_twilio_key() {
        let hex = "0123456789abcdef".repeat(2);
        // Built at runtime: a literal of this shape in the tree trips GitHub's
        // own push protection, which cannot be allowlisted per line.
        let html = format!(r#"<script>const taskId = "TA{}{}";</script>"#, "SK", hex);
        let html = html.as_str();
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].status,
            CheckStatus::Pass,
            "{}",
            results[0].description
        );
    }

    #[test]
    fn a_standalone_twilio_key_is_still_detected() {
        let hex = "0123456789abcdef".repeat(2);
        let html = format!(r#"<script>const sid = "{}{}";</script>"#, "SK", hex);
        let html = html.as_str();
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert!(results[0].description.contains("Twilio"));
    }

    #[test]
    fn boundary_groups_do_not_hide_aws_or_slack_credentials() {
        let aws = ExposedApiKeysCheck.run(&ctx(
            r#"<script>const aws = "AKIAIOSFODNN7EXAMPLE";</script>"#,
        ));
        assert_eq!(aws[0].status, CheckStatus::Fail);
        assert!(aws[0].description.contains("AWS"));

        let slack = ExposedApiKeysCheck.run(&ctx(
            r#"<script>const hook = "xoxb-1234567890-abcdefghijkl";</script>"#,
        ));
        assert_eq!(slack[0].status, CheckStatus::Fail);
        assert!(slack[0].description.contains("Slack"));

        // The same shapes embedded in a longer identifier are not credentials.
        let embedded = ExposedApiKeysCheck.run(&ctx(
            r#"<script>const id = "REPLICAKIAIOSFODNN7EXAMPLE0";</script>"#,
        ));
        assert_eq!(embedded[0].status, CheckStatus::Pass);
    }

    #[test]
    fn secret_and_public_keys_appearing_together_emit_two_findings() {
        let html = r#"<script>
            const secret = "sk_live_1234567890abcdefghijklmn"; // gitleaks:allow
            Stripe("pk_live_1234567890abcdefghijklmn");
        </script>"#;
        let results = ExposedApiKeysCheck.run(&ctx(html));
        assert_eq!(results.len(), 2);
        let secret = results
            .iter()
            .find(|r| r.severity == Severity::High)
            .expect("high finding for secret-shaped key");
        assert!(secret.description.contains("Stripe Secret"));
        let advisory = results
            .iter()
            .find(|r| r.severity == Severity::Low)
            .expect("advisory finding for publishable key");
        assert!(advisory.description.contains("Stripe Publishable"));
    }
}
