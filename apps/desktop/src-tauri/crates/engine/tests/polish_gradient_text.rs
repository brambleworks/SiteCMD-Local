use sitecmd_engine::checks::polish::{
    css_signal_counts, grade_stylesheet_signals, polish_check_result, polish_signal_confidence,
    run_all_signals, run_page_signals, CssTextKind, PolishContext, PolishResult,
};
use sitecmd_engine::evaluation::{PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::manifest::{capability_manifest, CheckScope, HostedLane};
use sitecmd_engine::probe::BodyLimit;
use sitecmd_engine::severity_policy::{web_policy_severity, WebSeverityInput};
use sitecmd_engine::{CheckStatus, IssueConfidence, Severity};

fn context(page: &str, sheets: &[&str]) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse("https://example.com/").unwrap(),
        page.to_string().into(),
        sheets.iter().fold(Default::default(), |counts, sheet| {
            counts + css_signal_counts(sheet, CssTextKind::Stylesheet)
        }),
    )
}

fn signal(page: &str, sheets: &[&str]) -> PolishResult {
    run_all_signals(&context(page, sheets))
        .into_iter()
        .find(|result| result.id == "gradient-text")
        .expect("missing gradient-text")
}

#[test]
fn a_gradient_clipped_to_transparent_text_fires() {
    // A gradient clipped to headline text goes unreported, or a transparent border is read as a text fill.
    let result = signal("", &["h1{background:linear-gradient(red,blue);-webkit-background-clip:text;color:transparent}"]);
    assert!(result.fired);
    assert_eq!(result.name, "Gradient Text");
    assert_eq!(
        result.detail,
        "A gradient is clipped to text with a transparent fill"
    );
    assert_eq!(
        result.data,
        serde_json::json!({"text_clip":true,"transparent_fill":true,"any_gradient":true})
    );
}

#[test]
fn transparent_non_text_properties_do_not_supply_the_fill() {
    // A transparent border, outline, decoration or custom property is not a transparent text fill.
    for declaration in [
        "",
        "border-color:transparent",
        "outline-color:transparent",
        "text-decoration-color:transparent",
        "--color:transparent",
        "notcolor:transparent",
        "color:transparentish",
    ] {
        let css = format!(
            "h1{{background:linear-gradient(red,blue);background-clip:text;{declaration}}}"
        );
        let result = signal("", &[&css]);
        assert!(!result.fired, "{declaration}");
        assert_eq!(result.data["transparent_fill"], false, "{declaration}");
    }
}

#[test]
fn each_fact_is_required_and_fill_declaration_boundaries_are_respected() {
    // A missing clip, fill or gradient must not be inferred from either of the other facts.
    for css in [
        "h1{background:linear-gradient(red,blue);color:transparent}",
        "h1{background-clip:text;color:transparent}",
        "h1{background:linear-gradient(red,blue);background-clip:text}",
    ] {
        assert!(!signal("", &[css]).fired, "{css}");
    }
    for fill in [
        "color:transparent",
        "-webkit-text-fill-color:transparent",
        "COLOR : TRANSPARENT !important",
    ] {
        let declarations =
            format!("{fill};background-clip:text;background:linear-gradient(blue,lightblue)");
        for page in [
            format!("<h1 style=\"{declarations}\">Title</h1>"),
            format!("<h1 style='{declarations}'>Title</h1>"),
            format!("<style>h1{{{declarations}}}</style>"),
        ] {
            assert!(signal(&page, &[]).fired, "{page}");
        }
    }
}

#[test]
fn tailwind_classes_are_read_only_from_real_page_class_attributes() {
    // Gradient text utilities must come from a page class attribute rather than prose, scripts or compiled selectors.
    let classes = "bg-gradient-to-r from-blue-600 to-violet-600 bg-clip-text text-transparent";
    assert!(signal(&format!("<h1 class=\"{classes}\">Title</h1>"), &[]).fired);
    assert!(
        signal(
            &format!("<h1 class=\"[&>svg]:size-4 {classes}\">Title</h1>"),
            &[]
        )
        .fired
    );
    for page in [
        format!("<p>{classes}</p>"),
        format!("<h1 data-class='{classes}'>Title</h1>"),
        format!("<!-- <h1 class='{classes}'>Title</h1> -->"),
        format!("<script>const html = \"<h1 class='{classes}'>Title</h1>\";</script>"),
    ] {
        assert!(!signal(&page, &[]).fired, "{page}");
    }
    assert!(
        !signal(
            "",
            &[".bg-gradient-to-r{}.from-blue-600{}.bg-clip-text{}.text-transparent{}"]
        )
        .fired
    );
    for gradient in [
        "bg-linear-to-r",
        "from-blue-600",
        "from-blue-50",
        "from-gray-50",
        "from-[#123456]",
    ] {
        assert!(
            signal(
                &format!("<h1 class='{gradient} bg-clip-text text-transparent'>Title</h1>"),
                &[]
            )
            .fired,
            "{gradient}"
        );
    }
    assert!(
        !signal(
            "<h1 class='from-notacolor-600 bg-clip-text text-transparent'>Title</h1>",
            &[]
        )
        .fired
    );
}

#[test]
fn independent_files_or_facts_without_joining_declarations() {
    // Facts from separate files must combine, while fragments of one declaration must not.
    assert!(
        signal(
            "<style>h1{background:radial-gradient(blue,lightblue)}</style>",
            &["h1{background-clip:text}", "h1{color:transparent}"]
        )
        .fired
    );
    let result = signal(
        "<style>h1{background:conic-gradient(red,red);background-clip:text}</style>",
        &["h1{color:", "transparent}"],
    );
    assert!(!result.fired);
    assert_eq!(result.data["transparent_fill"], false);
}

#[test]
fn an_unanswered_stylesheet_skips_a_clear_row_but_keeps_a_finding() {
    // Missing stylesheet coverage cannot establish that gradient text is absent.
    let ctx = context(
        "<link rel='stylesheet' href='/a.css'><link rel='stylesheet' href='/b.css'>",
        &[""],
    );
    let rows = grade_stylesheet_signals(&ctx, 2, 1);
    let row = rows
        .iter()
        .find(|r| r.check_id == "polish.gradient-text")
        .expect("stylesheet row");
    assert_eq!(row.status, CheckStatus::Skipped);
    assert!(row.description.contains("1 of 2 linked stylesheets"));
    let ctx = context(
        "",
        &["h1{background:linear-gradient(red,blue);background-clip:text;color:transparent}"],
    );
    assert_eq!(
        grade_stylesheet_signals(&ctx, 2, 1)
            .iter()
            .find(|r| r.check_id == "polish.gradient-text")
            .unwrap()
            .status,
        CheckStatus::Fail
    );
}

#[test]
fn the_stylesheet_probe_is_origin_scoped_and_followup_pages_claim_no_pair() {
    // Page-scoping gradient text would repeat a stylesheet finding on a session's second route.
    let manifest = capability_manifest();
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.check == "polish.gradient-text")
        .expect("manifest row");
    assert_eq!(entry.scope, CheckScope::Origin);
    assert_eq!(entry.hosted, HostedLane::ProbeAdapter);
    let route = RouteSession::open(serde_json::from_value::<PageArtifact>(serde_json::json!({"url":"https://example.com/", "status_code":200,"headers":[],"body":"<link rel='stylesheet' href='/site.css'>", "evaluation_time":"2026-11-05T00:00:00Z"})).unwrap()).unwrap();
    let plan = route.plan();
    assert!(plan
        .planned
        .iter()
        .any(|row| row.check == "polish.gradient-text" && row.scope == CheckScope::Origin));
    assert!(plan
        .probes
        .iter()
        .any(|probe| probe.request.limit == BodyLimit::Stylesheet
            && probe.checks.iter().any(|id| id == "polish.gradient-text")));
    let followup = context(
        "<h1 class='bg-linear-to-r bg-clip-text text-transparent'>Title</h1>",
        &[],
    );
    let pairs: Vec<_> = run_page_signals(&followup)
        .iter()
        .map(polish_check_result)
        .map(|row| row.check_id)
        .collect();
    assert!(!pairs.iter().any(|id| id == "polish.gradient-text"));
    assert!(!route
        .evaluate(&RouteFacts::default())
        .results
        .iter()
        .any(|row| row.check_id == "polish.gradient-text" && row.status == CheckStatus::Pass));
}

#[test]
fn gradient_text_uses_the_signed_words_and_low_review_policy() {
    // The new signal must carry its signed wording, review confidence and normalized Low severity.
    let result = signal(
        "<h1 class='bg-linear-to-r bg-clip-text text-transparent'>Title</h1>",
        &[],
    );
    let row = polish_check_result(&result);
    assert_eq!(row.severity, Severity::Medium);
    assert_eq!(row.title, "Gradient fill clipped to text");
    assert_eq!(row.why_it_matters.as_deref(), Some("Text filled with a gradient changes color across its letters, so part of it can fall below readable contrast against the background."));
    assert_eq!(row.fix_prompt.as_deref(), Some("Check the text's contrast where its gradient is lightest and darkest, and use one solid color wherever part of it is hard to read."));
    let (confidence, reason) = polish_signal_confidence("gradient-text");
    assert_eq!(confidence, IssueConfidence::NeedsReview);
    assert_eq!(
        reason,
        Some("Subjective aesthetic signal; legitimate modern designs often match.")
    );
    assert_eq!(
        web_policy_severity(&WebSeverityInput::of(&row)),
        Some(Severity::Low)
    );
}

#[test]
fn neutral_keyword_stops_still_supply_any_gradient() {
    // A valid neutral Tailwind stop must not disappear because gradient text does not require chromatic hues.
    for stop in ["from-black", "from-white", "from-transparent"] {
        assert!(
            signal(
                &format!("<h1 class='{stop} bg-clip-text text-transparent'>Title</h1>"),
                &[]
            )
            .fired,
            "{stop}"
        );
    }
}

#[test]
fn arbitrary_tailwind_values_supply_each_fact() {
    // Gradient text written with arbitrary values goes unreported.
    for classes in [
        "bg-[linear-gradient(90deg,#f00,#00f)] bg-clip-text text-transparent",
        "bg-[image:linear-gradient(90deg,#f00,#00f)] bg-clip-text text-transparent",
        "bg-gradient-to-r [background-clip:text] text-transparent",
        "bg-gradient-to-r [-webkit-background-clip:text] text-transparent",
        "bg-gradient-to-r bg-clip-text [-webkit-text-fill-color:transparent]",
        "bg-gradient-to-r bg-clip-text [color:transparent]",
        "hover:bg-[linear-gradient(red,blue)] hover:[background-clip:text] hover:[color:transparent]",
    ] {
        assert!(signal(&format!("<h1 class=\"{classes}\">Title</h1>"), &[]).fired, "{classes}");
    }
    let result = signal("<style>h1{background-clip:text;color:transparent}</style><p class=\"[color:red] [background:url(x)] bg-[url(a.png)]\">Copy</p>", &[]);
    assert!(!result.fired);
    assert_eq!(result.data["any_gradient"], false);
}

#[test]
fn comments_flags_and_line_breaks_do_not_change_the_facts() {
    // Commented-out declarations must not supply facts, while comments, clip flags and line breaks must not hide real ones.
    for css in [
        "h1{background:linear-gradient(red,blue);background-clip:text}/* color:transparent */",
        "h1{background:linear-gradient(red,blue);background-clip:text;/*;color:transparent;*/}",
    ] {
        assert!(!signal("", &[css]).fired, "{css}");
    }
    for css in [
        "h1{background:linear-gradient(red,blue);background-clip:text;/* x */color:transparent}",
        "h1{background:linear-gradient(red,blue);background-clip:text!important;color:transparent}",
        "h1{background:linear-gradient(red,blue);-webkit-background-clip:text!important;color:transparent}",
        "h1{background:linear-gradient(red,blue);background-clip:\n  text;color:transparent}",
        "h1{background:linear-gradient(red,blue);background-clip:text;color:\n  transparent}",
    ] {
        assert!(signal("", &[css]).fired, "{css}");
    }
}

#[test]
fn strings_and_urls_do_not_supply_declaration_facts() {
    // Declarations inside CSS strings and URLs must not be read as text clipping or a transparent fill.
    for fake in [
        r#"h2:before{content:"x;color:transparent;"}"#,
        "h2{background:url(data:image/svg+xml;color:transparent;base64,AA)}",
        r#"[style*="{color:transparent;"]{display:block}"#,
    ] {
        let css = format!("h1{{background:linear-gradient(red,blue);background-clip:text}}{fake}");
        let result = signal("", &[&css]);
        assert!(!result.fired, "{fake}");
        assert_eq!(result.data["transparent_fill"], false, "{fake}");
    }
    for fake in [
        r#"h2:before{content:'x;background-clip:text;'}"#,
        "h2{background:url(data:image/svg+xml;background-clip:text;base64,AA)}",
    ] {
        let css = format!("h1{{background:linear-gradient(red,blue);color:transparent}}{fake}");
        assert!(!signal("", &[&css]).fired, "{fake}");
    }
    assert!(
        signal(
            "",
            &[r#"h1{background-clip:text;color:transparent;content:"linear-gradient("}"#]
        )
        .fired
    );
}

#[test]
fn fully_transparent_color_values_supply_the_fill() {
    // Fully transparent colors must count as a text fill, while a partially transparent color must not.
    for property in ["color", "-webkit-text-fill-color"] {
        for color in ["rgba(0,0,0,0)", "hsla(220,50%,50%,0)", "#0000", "#00000000"] {
            let css = format!("h1{{background:linear-gradient(red,blue);background-clip:text;{property}:{color}}}");
            let result = signal("", &[&css]);
            assert!(result.fired, "{property}:{color}");
            assert_eq!(result.data["transparent_fill"], true);
            let page = format!("<h1 style=\"background:linear-gradient(red,blue);background-clip:text;{property}:{color}!important\">Title</h1>");
            assert!(signal(&page, &[]).fired, "{page}");
        }
        for color in [
            "rgba(0,0,0,0.5)",
            "hsla(220,50%,50%,0.5)",
            "#0008",
            "#00000080",
        ] {
            let css = format!("h1{{background:linear-gradient(red,blue);background-clip:text;{property}:{color}}}");
            let result = signal("", &[&css]);
            assert!(!result.fired, "{property}:{color}");
            assert_eq!(result.data["transparent_fill"], false);
        }
    }
}
