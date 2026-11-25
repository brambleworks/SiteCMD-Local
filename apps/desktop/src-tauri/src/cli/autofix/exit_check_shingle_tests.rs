use super::*;

#[test]
fn partial_quotes_share_a_shingle() {
    // Editing or excerpting a source line can defeat whole-line matching.
    let cases = [
        (
            "method chain",
            "const completion = await openai.chat.completions.create({",
            "Use `openai.chat.completions.create` for the call.",
        ),
        (
            "right-hand side",
            "const lookup = readUntrustedAccountIdentifierFromContext();",
            "The value is readUntrustedAccountIdentifierFromContext().",
        ),
        (
            "dropped semicolon",
            "const setting = 'unchanged';",
            "const setting = 'unchanged'",
        ),
        (
            "exactly 24 within a longer line",
            "/// source:abcd efgh ijkl nopq uvwx!declaration",
            "prefix/abcd efgh ijkl nopq uvwx?suffix",
        ),
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, source, body)| quote_escapes(source, body).then_some(name))
        .collect();
    assert!(failures.is_empty(), "quotes that escaped: {failures:?}");
}

#[test]
fn case_folded_confusables_match_on_both_sides() {
    // Case folding can separate an ASCII confusable from its skeleton.
    let cases = [
        ("if (x) { return null; }", "if (x) { return nuII; }"),
        ("items[0]", "items[O]"),
        (
            "const total = order.amount + shippingCost;",
            "c0nst t0tal = 0rder.am0unt + shippingC0st;",
        ),
        (
            "const isAllowed = allowList.includes(id);",
            "const isAIIowed = aIIowList.incIudes(id);",
        ),
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter_map(|(source, body)| {
            (quote_escapes(source, body) || quote_escapes(body, source)).then_some(body)
        })
        .collect();
    assert!(failures.is_empty(), "quotes that escaped: {failures:?}");
}

#[test]
fn uppercase_confusables_match_on_both_sides() {
    // Lowercasing first can separate uppercase confusables from their ASCII skeletons.
    let declaration = "export const MAX_TOKEN_BUDGET = readLimit(HEADERS);";
    let query = "SELECT * FROM BANK_ACCOUNTS WHERE OWNER_ID = $1 LIMIT 1;";
    let header = "const HEADER_NAME_FOR_THE_REQUEST_TOKEN = 1;";
    let cyrillic_header = header.replace('T', "\u{0422}");
    let cases = [
        (
            "Cyrillic declaration",
            declaration,
            "export const МАХ_ТОКЕN_ВUDGЕТ = readLimit(НЕАDЕRS);",
        ),
        (
            "Greek declaration",
            declaration,
            "export const ΜΑΧ_ΤΟΚΕΝ_ΒUDGΕΤ = readLimit(ΗΕΑDΕRS);",
        ),
        (
            "Cyrillic query",
            query,
            "SЕLЕСТ * FRОМ ВАNК_АССОUNТS WНЕRЕ ОWNЕR_ID = $1 LIМIТ 1;",
        ),
        (
            "Greek query",
            query,
            "SΕLΕCΤ * FRΟΜ ΒΑΝΚ_ΑCCΟUΝΤS WΗΕRΕ ΟWΝΕR_ID = $1 LIΜIΤ 1;",
        ),
        ("repeated Cyrillic T", header, &cyrillic_header),
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, source, quote)| {
            let brief_escapes = quote_escapes(source, quote);
            let handed_escapes = quote_escapes(quote, source);
            (brief_escapes || handed_escapes).then_some((name, brief_escapes, handed_escapes))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "quotes that escaped (case, brief, handed): {failures:?}"
    );
}

#[test]
fn confusables_changed_by_nfkd_match_on_both_sides() {
    // NFKD can change a confusable before its skeleton is taken.
    let cases = [
        (
            "lowercase lunate sigma",
            "const accessControl = checkAccess(request, policy);",
            "ϲonst aϲϲessControl = ϲheϲkAϲϲess(request, poliϲy);",
        ),
        (
            "uppercase lunate sigma",
            "SELECT * FROM CUSTOMER_CREDIT_CARDS WHERE ACCOUNT_ID = $1;",
            "SELEϹT * FROM ϹUSTOMER_ϹREDIT_ϹARDS WHERE AϹϹOUNT_ID = $1;",
        ),
        (
            "long s",
            "function fetchProfile(fields) { return fields; }",
            "ſunction ſetchProſile(ſields) { return ſields; }",
        ),
        (
            "single uppercase lunate sigma",
            "SELECT BALANCE FROM ACCOUNTS;",
            "SELECT BALANCE FROM AϹCOUNTS;",
        ),
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, source, quote)| {
            let brief_escapes = quote_escapes(source, quote);
            let handed_escapes = quote_escapes(quote, source);
            (brief_escapes || handed_escapes).then_some((name, brief_escapes, handed_escapes))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "quotes that escaped (case, brief, handed): {failures:?}"
    );
}

#[test]
fn a_whole_line_with_the_site_url_is_refused() {
    // An inline metadata mask can split a copied source line into short fragments.
    let target = sitecmd_protocol::engine_abi::BriefTarget {
        agent: "claude".into(),
        attempt: 1,
        check_id: "security.headers.x_content_type_options".into(),
        description: "The site is missing a response header.".into(),
        detected_stack: None,
        likely_fix: None,
        locations: Vec::new(),
        severity: sitecmd_protocol::vocab::Severity::Medium,
        site_url: "https://www.example-shop.com".into(),
        title: "Missing response header".into(),
        why_now: None,
    };
    let cases = [
        r#"fetch("https://www.example-shop.com/api/" + orderId + key)"#,
        "redirect(`https://www.example-shop.com/${locale}/${slug}`);",
        "siteUrl: 'https://www.example-shop.com', // prod domain",
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter(|line| {
            let mut handed = HandedLines::default();
            handed.record_lines(line.as_bytes());
            check_hosted_brief(issue(line), &handed, &target) != Err(ExitRefusal::HandedLine)
        })
        .collect();
    assert!(failures.is_empty(), "quotes that escaped: {failures:?}");
}

#[test]
fn an_oversized_brief_is_refused() {
    // A large brief can exhaust the shingle matcher's construction capacity.
    let oversized = "x".repeat(128 * 1024);
    assert_eq!(
        check_brief(issue(&oversized), &HandedLines::default(), &[]),
        Err(ExitRefusal::BriefTooLarge)
    );
}

#[test]
fn inline_markup_and_encodings_normalize_on_both_sides() {
    // Inline formatting and character encodings can break every matching window.
    let plain = "const setting = 'unchanged';";
    let cases = [
        ("case", plain, "CONST SETTING = 'UNCHANGED';"),
        (
            "named HTML5 entity",
            plain,
            "const &Sscr;etting = 'unchanged';",
        ),
        (
            "legacy HTML5 entity",
            plain,
            "const s&eacutetting = &apos;unchanged&apos;;",
        ),
        (
            "combining marks",
            plain,
            "const sét\u{0327}ting = 'unchanged';",
        ),
        (
            "HTML5 multi-scalar entity",
            "const flag = ≂̸ + client.active;",
            "const flag = &NotEqualTilde; + client.active;",
        ),
        (
            "HTML attributes",
            plain,
            r#"const <CODE data-x=">">setting</cOdE> = 'unchanged';"#,
        ),
        (
            "HTML inline comment",
            plain,
            "const set<!-- note -->ting = 'unchanged';",
        ),
        ("inline code", plain, "const `setting` = 'unchanged';"),
        (
            "inline link",
            plain,
            "const [setting](https://example.com/a_(b)) = 'unchanged';",
        ),
        ("single tilde", plain, "const ~setting~ = 'unchanged';"),
        (
            "URL encoding",
            plain,
            "const%20set%74ing%20%3D%20%27unchanged%27%3B",
        ),
        (
            "ignorable in a tag",
            plain,
            "const <co\u{200b}de>setting</co\u{200b}de> = 'unchanged';",
        ),
    ];
    let failures: Vec<_> = cases
        .into_iter()
        .filter_map(|(name, source, body)| {
            (quote_escapes(source, body) || quote_escapes(body, source)).then_some(name)
        })
        .collect();
    assert!(failures.is_empty(), "formats that escaped: {failures:?}");
}

#[test]
fn a_provider_only_masked_quote_is_refused() {
    // Preparing issue evidence can mask an assignment before the provider mask runs.
    let source = format!("TWILIO=SK{}", "0123456789abcdef".repeat(2));
    assert!(!quote_escapes(&source, "TWILIO=SK***"));
}

fn quote_escapes(source: &str, body: &str) -> bool {
    let mut handed = HandedLines::default();
    handed.record_lines(source.as_bytes());
    check_brief(issue(body), &handed, &[]) != Err(ExitRefusal::HandedLine)
}

#[test]
fn permits_verified_issue_metadata_but_refuses_a_source_quote() {
    // A fixed issue can be blocked by checked-in references, or admit a quote beside them.
    use sitecmd_protocol::engine_abi::{BriefTarget, BriefTargetLocation, Done, Task};
    let path = "src/app/routes/fixture-findings.txt";
    let quoted = "The internal checkout annotation must remain private.";
    let mut handed = HandedLines::default();
    handed.record_lines(format!("Reference: `{path}`\n{quoted}\n").as_bytes());
    let target: BriefTarget = serde_json::from_value(serde_json::json!({
        "agent":"claude", "attempt":1, "check_id":"code_scan.standin.rule",
        "description":"Fixture", "detected_stack":null, "likely_fix":null,
        "locations":[BriefTargetLocation { path:path.into(), line:8 }],
        "severity":"low", "site_url":"https://example.com", "title":"Sample finding", "why_now":null
    }))
    .unwrap();
    let Done::Brief(mut brief) = crate::core::fixes::request(
        Task::Brief {
            target: target.clone(),
        },
        None,
    )
    .unwrap() else {
        panic!("expected a rendered issue");
    };
    assert!(brief.body.contains(&format!("`{path}:8`")));
    assert!(check_hosted_brief(brief.clone(), &handed, &target).is_ok());
    brief.body.push_str(&format!("\n{quoted}"));
    assert_eq!(
        check_hosted_brief(brief, &handed, &target),
        Err(ExitRefusal::HandedLine)
    );
}
