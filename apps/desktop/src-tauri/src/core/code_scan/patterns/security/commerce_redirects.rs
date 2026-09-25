use std::sync::LazyLock;

pub(in crate::core::code_scan) static PAYMENT_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bstripe\b").unwrap(),
            regex::Regex::new(r"\bcheckout\b").unwrap(),
            regex::Regex::new(r"\bpayment\b").unwrap(),
            regex::Regex::new(r"\bsubscription\b").unwrap(),
            regex::Regex::new(r"\binvoice\b").unwrap(),
            regex::Regex::new(r"\bbilling\b").unwrap(),
        ]
    });

pub(in crate::core::code_scan) static STRIPE_CHECKOUT_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"checkout\.sessions\.create").unwrap(),
            regex::Regex::new(r"paymentLinks?\.create").unwrap(),
        ]
    });

pub(in crate::core::code_scan) static USER_CONTROLLED_STRIPE_PRICE_PATTERNS: LazyLock<
    Vec<regex::Regex>,
> = LazyLock::new(|| {
    vec![
        regex::Regex::new(
            r#"(?is)(?:price|priceId|price_id)\s*:\s*(?:body|input|payload|params|query|data)\.[A-Za-z0-9_]+"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)(?:price|priceId|price_id)\s*:\s*.*searchParams\.get\(\s*["'`](?:price|priceId|price_id)["'`]\s*\)"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)(?:formData|data|input|values)\.get\s*\(\s*["'`](?:price|priceId|price_id|plan)["'`]\s*\)"#,
        )
        .unwrap(),
    ]
});

pub(in crate::core::code_scan) static REDIRECT_SINK_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bredirect\s*\(").unwrap(),
            regex::Regex::new(r"\bpermanentRedirect\s*\(").unwrap(),
            regex::Regex::new(r"\bNextResponse\.redirect\s*\(").unwrap(),
            regex::Regex::new(r"\bResponse\.redirect\s*\(").unwrap(),
            // PHP: the raw Location header and WordPress's unvalidated
            // redirect (wp_safe_redirect is an allowlist guard, not a sink).
            regex::Regex::new(r#"(?i)\bheader\s*\(\s*["']\s*location\s*:"#)
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bwp_redirect\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

/// A redirect-style property name. Bare `success` and `cancel` are flags, such
/// as a zod `safeParse` result, so they count only with a destination word.
const REDIRECT_FIELD_NAME: &str = r"[A-Za-z0-9_]*(?:redirect|return|callback|next|(?:success|cancel)[A-Za-z0-9_]*?(?:url|uri|href|path|page|dest|target|location|redirect))[A-Za-z0-9_]*";

pub(in crate::core::code_scan) static USER_CONTROLLED_REDIRECT_PATTERNS: LazyLock<
    Vec<regex::Regex>,
> = LazyLock::new(|| {
    vec![
        regex::Regex::new(&format!(
            r"(?is)(?:body|input|payload|params|query|data)\.{REDIRECT_FIELD_NAME}"
        ))
        .unwrap(),
        regex::Regex::new(&format!(r"(?is)\breq\.(?:query|body)\.{REDIRECT_FIELD_NAME}")).unwrap(),
        regex::Regex::new(
            r#"(?is)searchParams\.get\(\s*["'`](?:redirectTo|returnTo|callbackUrl|callbackURL|returnUrl|next|nextUrl|redirect|successUrl|cancelUrl|success_url|cancel_url)["'`]\s*\)"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)(?:formData|data|input|values)\.get\s*\(\s*["'`](?:redirectTo|returnTo|callbackUrl|callbackURL|returnUrl|next|nextUrl|redirect|successUrl|cancelUrl|success_url|cancel_url)["'`]\s*\)"#,
        )
        .unwrap(),
        // PHP: a request superglobal reaching a Location header or redirect
        // call (interpolated or concatenated - [^;] spans both), and Laravel
        // redirects fed straight from request input.
        regex::Regex::new(
            r#"(?is)\bheader\s*\(\s*["']\s*location\s*:[^;]{0,220}\$_(?:GET|POST|REQUEST)"#,
        )
        .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        regex::Regex::new(r"(?s)\bwp_redirect\s*\(\s*[^;)]{0,160}\$_(?:GET|POST|REQUEST)").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        regex::Regex::new(r"(?s)\bredirect\s*\(\s*\$request->(?:input|get|query)\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
    ]
});

pub(in crate::core::code_scan) static USER_CONTROLLED_STRIPE_REDIRECT_PATTERNS: LazyLock<
    Vec<regex::Regex>,
> = LazyLock::new(|| {
    vec![
        regex::Regex::new(
            r#"(?is)(?:success_url|cancel_url)\s*:\s*(?:body|input|payload|params|query|data)\.[A-Za-z0-9_]*(?:redirect|return|callback|next|success|cancel)[A-Za-z0-9_]*"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)(?:success_url|cancel_url)\s*:\s*.*searchParams\.get\(\s*["'`](?:redirectTo|returnTo|callbackUrl|callbackURL|returnUrl|next|nextUrl|redirect|successUrl|cancelUrl|success_url|cancel_url)["'`]\s*\)"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)(?:success_url|cancel_url)\s*:\s*(?:formData|data|input|values)\.get\s*\(\s*["'`](?:redirectTo|returnTo|callbackUrl|callbackURL|returnUrl|next|nextUrl|redirect|successUrl|cancelUrl|success_url|cancel_url)["'`]\s*\)"#,
        )
        .unwrap(),
    ]
});

pub(in crate::core::code_scan) static REDIRECT_ALLOWLIST_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bisSafeRedirect\b").unwrap(),
            regex::Regex::new(r"\bsafeRedirect\b").unwrap(),
            regex::Regex::new(r"\bsanitizeRedirect\b").unwrap(),
            regex::Regex::new(r"\bassertSafeRedirect\b").unwrap(),
            regex::Regex::new(r"\bvalidateRedirect\b").unwrap(),
            // Project-local guard naming: `isValidReturnTo`, `isSafeUrl`,
            // `isAllowedOrigin`, and the named helpers real callbacks use.
            regex::Regex::new(
                r"\bis(?:Valid|Safe|Allowed)\w*(?:Url|URL|Redirect|ReturnTo|Origin)s?\b",
            )
            .expect("static named redirect guard regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bgetSafeRedirectUrl\b")
                .expect("static safe redirect helper regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bisOriginAllowed\b").expect("static origin allowlist regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bnormalizeReturnTo\b").expect("static return-to normalizer regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\ballowedRedirect").unwrap(),
            regex::Regex::new(r"\btrustedRedirect").unwrap(),
            regex::Regex::new(r"\ballowedOrigins?\b").unwrap(),
            regex::Regex::new(r"\btrustedOrigins?\b").unwrap(),
            // WordPress's allowlist-validating redirect helpers.
            regex::Regex::new(r"\bwp_safe_redirect\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bwp_validate_redirect\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static STRIPE_PRICE_ALLOWLIST_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
        regex::Regex::new(r"\bPRICE_IDS\b").unwrap(),
        regex::Regex::new(r"\bALLOWED_PRICE").unwrap(),
        regex::Regex::new(r"\blookup_key\b").unwrap(),
        regex::Regex::new(r"\blookupKey\b").unwrap(),
        regex::Regex::new(r"\bpriceMap\b").unwrap(),
        regex::Regex::new(r"\bPRICE_MAP\b").unwrap(),
        regex::Regex::new(r"\bincludes\s*\(\s*(?:body|input|payload|params|query|data)\.(?:price|priceId|price_id)").unwrap(),
        regex::Regex::new(r"\bz\.enum\s*\(").unwrap(),
    ]
    });

pub(in crate::core::code_scan) static EMAIL_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bnodemailer\b").unwrap(),
            regex::Regex::new(r"\bresend\b").unwrap(),
            regex::Regex::new(r"\bsendgrid\b").unwrap(),
            regex::Regex::new(r"\bpostmark\b").unwrap(),
            regex::Regex::new(r"\bmailgun\b").unwrap(),
            regex::Regex::new(r"\bSESClient\b").unwrap(),
        ]
    });

#[cfg(test)]
mod tests {
    use super::{REDIRECT_ALLOWLIST_PATTERNS, USER_CONTROLLED_REDIRECT_PATTERNS};

    fn request_redirect_field(source: &str) -> bool {
        USER_CONTROLLED_REDIRECT_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(source))
    }

    #[test]
    fn success_and_cancel_fields_need_a_destination_name() {
        for field in [
            "body.successUrl",
            "body.success_url",
            "input.cancelUrl",
            "payload.onSuccessRedirect",
            "req.body.cancel_url",
            "query.redirectTo",
        ] {
            assert!(request_redirect_field(field), "{field} should count");
        }
        for flag in [
            "if (!parsedBody.success) return;",
            "data.success",
            "req.body.cancel",
            "params.cancelToken",
        ] {
            assert!(!request_redirect_field(flag), "{flag} should not count");
        }
    }

    fn allowlisted(source: &str) -> bool {
        REDIRECT_ALLOWLIST_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(source))
    }

    #[test]
    fn project_named_return_to_guards_count_as_an_allowlist() {
        assert!(allowlisted("isValidReturnTo(returnTo)"));
        assert!(allowlisted("normalizeReturnTo(returnTo)"));
        assert!(allowlisted("getSafeRedirectUrl(state)"));
        assert!(allowlisted(
            "if (!isOriginAllowed(body.redirectUri, client.redirectUris))"
        ));
        assert!(allowlisted("isSafeUrl(target)"));
        assert!(allowlisted(
            "isAllowedOrigin(request.headers.get(\"origin\"))"
        ));
    }

    #[test]
    fn an_unguarded_redirect_target_is_not_allowlisted() {
        assert!(!allowlisted("return Response.redirect(returnTo);"));
        assert!(!allowlisted("const next = searchParams.get(\"next\");"));
        // A validator for something other than a destination does not count.
        assert!(!allowlisted("isValidEmail(input.email)"));
    }
}
