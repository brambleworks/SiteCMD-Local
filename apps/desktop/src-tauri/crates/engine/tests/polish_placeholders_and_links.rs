use sitecmd_engine::checks::polish::word_lists::{word_lists, PlaceholderShape};
use sitecmd_engine::checks::polish::{
    polish_check_result, polish_signal_confidence, run_all_signals, PolishContext, PolishResult,
};
use sitecmd_engine::severity_policy::{web_policy_severity, WebSeverityInput};
use sitecmd_engine::{CheckStatus, IssueConfidence, Severity};

fn signal(id: &str, html: &str) -> PolishResult {
    run_all_signals(&PolishContext::new(
        url::Url::parse("https://example.com/").unwrap(),
        html.into(),
        Default::default(),
    ))
    .into_iter()
    .find(|row| row.id == id)
    .unwrap_or_else(|| panic!("missing {id}"))
}

fn filler() -> &'static str {
    &word_lists()
        .placeholder_phrases
        .iter()
        .find(|entry| matches!(entry.shape, PlaceholderShape::Filler))
        .unwrap()
        .value
}

#[test]
fn every_recorded_placeholder_phrase_fires_on_page_copy() {
    // Placeholder copy left on a page goes unreported, or ordinary copy is reported as a placeholder.
    for phrase in &word_lists().placeholder_phrases {
        let result = signal("placeholder-text", &format!("<p>{}</p>", phrase.value));
        assert!(result.fired, "{}", phrase.value);
        assert!(result.data["matches"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(phrase.value)));
    }
}

#[test]
fn placeholder_entities_are_decoded_before_matching() {
    // Encoded copyright and nonbreaking spaces can hide a recorded placeholder from text matching.
    let copyright = &word_lists()
        .placeholder_phrases
        .iter()
        .find(|entry| matches!(entry.shape, PlaceholderShape::CopyrightPlaceholder))
        .unwrap()
        .value;
    for encoded in [
        copyright.replace('©', "&copy;"),
        copyright.replace('©', "&#169;"),
        copyright.replace('©', "&#xA9;"),
    ] {
        assert!(signal("placeholder-text", &format!("<p>{encoded}</p>")).fired);
    }
    assert!(
        signal(
            "placeholder-text",
            &format!("<p>{}</p>", filler().replace(' ', "&nbsp;"))
        )
        .fired
    );
}

#[test]
fn attributes_code_comments_and_noncontent_do_not_supply_placeholder_copy() {
    // Hints, examples, scripts, styles, and comments must not be classified as visitor copy.
    for html in [
        format!("<input placeholder=\"{}\">", filler()),
        format!("<input title='>' placeholder=\"{}\">", filler()),
        format!("<pre><code>{}</code></pre>", filler()),
        format!("<code>{}</code>", filler()),
        format!("<kbd>{}</kbd>", filler()),
        format!("<samp>{}</samp>", filler()),
        format!(
            "<!-- {} --><script>{}</script><style>{}</style>",
            filler(),
            filler(),
            filler()
        ),
    ] {
        assert!(!signal("placeholder-text", &html).fired, "{html}");
    }
    let address = &word_lists()
        .placeholder_phrases
        .iter()
        .find(|p| matches!(p.shape, PlaceholderShape::ReservedAddress))
        .unwrap()
        .value;
    assert!(
        !signal(
            "placeholder-text",
            &format!("<input placeholder=\"{address}\">")
        )
        .fired
    );
}

#[test]
fn ordinary_product_and_domain_copy_stays_clear() {
    // Ordinary uses of company, name, and reserved-domain words must not match partial shapes.
    for copy in [
        "Every request SiteCMD's service sends your site names itself",
        "Uptime example.com, last hour",
        "example.com SPF record Passed",
        "holds your name, your email address",
        "Grow your company",
    ] {
        assert!(
            !signal("placeholder-text", &format!("<p>{copy}</p>")).fired,
            "{copy}"
        );
    }
    for phrase in &word_lists().placeholder_phrases {
        let prefixed = format!("<p>α{}</p>", phrase.value);
        assert_eq!(
            signal("placeholder-text", &prefixed).fired,
            matches!(phrase.shape, PlaceholderShape::CopyrightPlaceholder),
            "{prefixed}"
        );
        let suffixed = format!("<p>{}7</p>", phrase.value);
        assert!(!signal("placeholder-text", &suffixed).fired, "{suffixed}");
        assert!(
            signal(
                "placeholder-text",
                &format!("<p>({})</p>", phrase.value.to_uppercase())
            )
            .fired
        );
    }
}

#[test]
fn social_names_use_only_visible_and_accessible_labels() {
    // Class names, data, link targets, and partial or lowercase X labels are not social names.
    for anchor in [
        "<a href='#' class='icon-twitter'><svg></svg></a>",
        "<a href='#' data-network='twitter'><svg></svg></a>",
        "<a href='#' id='github'><svg></svg></a>",
        "<a href='#'><svg><use xlink:href='#icon-x'/></svg></a>",
        "<a href='#'><svg><use href='#icon-x'/></svg></a>",
        "<a href='#'><svg class='lucide lucide-x'></svg></a>",
        "<a href='#' class='close'>x</a>",
        "<a href='#'>Model X</a>",
        "<a href='#' aria-label='Model X'></a>",
    ] {
        assert_eq!(
            signal("dead-social-links", &anchor.repeat(2)).data["count"],
            0,
            "{anchor}"
        );
    }
    let x = &word_lists()
        .social_platforms
        .iter()
        .find(|p| p.names.iter().any(|n| n == "X"))
        .unwrap()
        .names[0];
    let github = &word_lists()
        .social_platforms
        .iter()
        .find(|p| p.names.iter().any(|n| n == "GitHub"))
        .unwrap()
        .names[0];
    for anchor in [
        format!("<a href='#'>{x}</a>"),
        format!("<a href='#' aria-label='{x}'></a>"),
        format!("<a href='#' title='{github}'></a>"),
        format!("<a href='#'><img alt='{github}'></a>"),
        format!("<a href='#'><svg><title>{github}</title></svg></a>"),
    ] {
        assert!(
            signal("dead-social-links", &anchor.repeat(2)).fired,
            "{anchor}"
        );
    }
}

#[test]
fn framework_share_bindings_are_event_handlers() {
    // Framework share handlers must not be mistaken for dead hash-only social links.
    let twitter = word_lists()
        .social_platforms
        .iter()
        .flat_map(|p| &p.names)
        .find(|n| n.as_str() == "Twitter")
        .unwrap();
    let html = format!("<a href='#' @click.prevent='share()'>{twitter}</a><a href='#' x-on:click.prevent='share()'>{twitter}</a><a href='#' v-on:click='share()'>{twitter}</a><a href='#' hx-post='/share'>{twitter}</a>");
    assert_eq!(signal("dead-social-links", &html).data["count"], 0);
}

#[test]
fn marker_looking_classes_do_not_suppress_template_braces() {
    // Ordinary class values containing directive names must not hide unfinished template braces.
    for class in ["nav-text", "dev-only"] {
        assert!(
            signal(
                "placeholder-text",
                &format!("<div class='{class}'>{{{{ name }}}}</div>")
            )
            .fired
        );
    }
    let marker = &word_lists()
        .client_template_markers
        .iter()
        .find(|m| m.value == "v-cloak")
        .unwrap()
        .value;
    assert!(
        !signal(
            "placeholder-text",
            &format!("<div {marker}>{{{{ name }}}}</div>")
        )
        .fired
    );
}

#[test]
fn inert_template_contents_do_not_supply_template_braces() {
    // Inert template markup must not be reported as unfinished rendered copy.
    assert!(
        !signal(
            "placeholder-text",
            "<template id=\"row\"><li>{{ name }}</li></template>"
        )
        .fired
    );
}

#[test]
fn hard_wrapped_placeholder_phrases_still_match() {
    // Source-line wrapping must not hide full placeholder phrases from text matching.
    for phrase in &word_lists().placeholder_phrases {
        let html = format!("<p>{}</p>", phrase.value.replace(' ', "\n"));
        assert!(signal("placeholder-text", &html).fired, "{}", phrase.value);
    }
    let copyright = &word_lists()
        .placeholder_phrases
        .iter()
        .find(|p| matches!(p.shape, PlaceholderShape::CopyrightPlaceholder))
        .unwrap()
        .value;
    assert!(
        signal(
            "placeholder-text",
            &copyright.replace('©', "&copy;").replace(' ', "\n")
        )
        .fired
    );
}

#[test]
fn a_copyright_sign_needs_no_leading_word_boundary() {
    // A copyright prefix directly beside the sign must not hide a recorded company placeholder.
    let copyright = &word_lists()
        .placeholder_phrases
        .iter()
        .find(|p| matches!(p.shape, PlaceholderShape::CopyrightPlaceholder))
        .unwrap()
        .value;
    assert!(
        signal(
            "placeholder-text",
            &copyright.replace('©', "Copyright&copy;")
        )
        .fired
    );
}

#[test]
fn every_image_host_and_its_subdomains_match_without_suffix_lookalikes() {
    // Placeholder images can be missed on subdomains or falsely found in another host's name.
    for host in &word_lists().placeholder_image_hosts {
        for authority in [host.value.clone(), format!("i.{}", host.value)] {
            let result = signal(
                "placeholder-text",
                &format!("<img src=\"https://{authority}/image.png\">"),
            );
            assert!(result.fired, "{authority}");
            assert!(result.data["matches"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(host.value)));
            assert!(!result.detail.contains("image.png"));
        }
        let html = format!(
            "<img src=\"https://not{}/image.png\"><img src=\"https://{}.example.org/image.png\">",
            host.value, host.value
        );
        assert!(!signal("placeholder-text", &html).fired);
    }
}

#[test]
fn template_braces_are_line_bounded_and_suppressed_by_recorded_client_markers() {
    // Raw template braces must be distinguished from client-side bindings and unfinished lines.
    let result = signal("placeholder-text", "<p>{{ name }}</p>");
    assert!(result.fired);
    assert_eq!(
        result.data,
        serde_json::json!({"matches":["template braces"], "count":1})
    );
    for marker in &word_lists().client_template_markers {
        assert!(
            !signal(
                "placeholder-text",
                &format!("<div {}>{{{{ name }}}}</div>", marker.value)
            )
            .fired,
            "{}",
            marker.value
        );
    }
    assert!(!signal("placeholder-text", "<p>{{ name\n}}</p>").fired);
}

#[test]
fn the_recorded_jekyll_leftover_can_contribute_to_both_signals() {
    // The Jekyll description intentionally qualifies as both scaffold content and placeholder copy.
    let phrase = &word_lists()
        .placeholder_phrases
        .iter()
        .find(|p| {
            word_lists()
                .scaffold_markers
                .iter()
                .any(|m| m.value.trim_end_matches('.') == p.value)
        })
        .unwrap()
        .value;
    let other = &word_lists()
        .scaffold_markers
        .iter()
        .find(|m| !m.value.contains(phrase))
        .unwrap()
        .value;
    let html = format!("<p>{phrase}.</p><p>{other}</p>");
    assert!(signal("placeholder-text", &html).fired);
    assert!(signal("boilerplate-html", &html).fired);
}

#[test]
fn blank_social_links_are_local_to_their_anchor_and_skip_real_event_handlers() {
    // A social icon that goes nowhere is not reported, or a share button is.
    let platform = &word_lists().social_platforms[0];
    let label = &platform.names[0];
    let domain = &platform.domain;
    let icon = format!("<a href='#' aria-label='{label}'><svg></svg></a>");
    assert!(!signal("dead-social-links", &icon).fired);
    assert_eq!(signal("dead-social-links", &icon).data["count"], 1);
    let twitter = word_lists()
        .social_platforms
        .iter()
        .find(|p| p.names.iter().any(|name| name == "Twitter"))
        .unwrap();
    let twitter_name = twitter
        .names
        .iter()
        .find(|name| name.as_str() == "Twitter")
        .unwrap();
    let github = word_lists()
        .social_platforms
        .iter()
        .find(|p| p.names.iter().any(|name| name == "GitHub"))
        .unwrap();
    let result = signal(
        "dead-social-links",
        &format!("<a href='#' aria-label='{twitter_name}'><svg></svg></a><a href='#' aria-label='{}'><svg></svg></a><a href='https://{}'>Profile</a>", github.names[0], twitter.domain),
    );
    assert!(result.fired);
    assert_eq!(result.data["count"], 3);
    for platform in &word_lists().social_platforms {
        for name in &platform.names {
            let html = format!("<a href='#'><svg aria-label='{name}'></svg></a>").repeat(2);
            assert!(signal("dead-social-links", &html).fired, "{name}");
            let html = format!("<p>{name}</p><a href='#'>Logo</a>").repeat(2);
            assert_eq!(
                signal("dead-social-links", &html).data["count"],
                0,
                "{name}"
            );
        }
    }
    for attr in ["onclick='share()'", "ONKEYDOWN='share()'", "onpointerup"] {
        let html = format!("<a href='#' aria-label='{label}' {attr}><svg></svg></a>").repeat(2);
        assert_eq!(signal("dead-social-links", &html).data["count"], 0);
    }
    let html = format!("<p>{label}</p><a href='#'>Logo</a><a href='#{domain}'>Profile</a>");
    assert_eq!(signal("dead-social-links", &html).data["count"], 0);
    let html = format!(
        "<a href='' title=\"onclick=share\" data-onclick='example' aria-label='{label}'></a>"
    )
    .repeat(2);
    assert!(signal("dead-social-links", &html).fired);
}

#[test]
fn every_platforms_bare_domain_is_dead_but_profile_and_share_paths_are_not() {
    // Bare platform home pages, including query variants, must not be treated as profile links.
    for platform in &word_lists().social_platforms {
        for href in [
            format!("https://{}/", platform.domain),
            format!("https://www.{}/?lang=en", platform.domain),
            format!("HTTPS://{}", platform.domain.to_uppercase()),
        ] {
            let result = signal(
                "dead-social-links",
                &format!("<a href=\"{href}\">Profile</a>").repeat(2),
            );
            assert!(result.fired, "{href}");
            assert_eq!(result.data, serde_json::json!({"count":2}));
            assert!(!result.detail.contains(&href));
        }
        let html = format!("<a href=\"https://{}/sitecmd\">Profile</a><a href=\"https://{}/intent/post?text=hi\">Share</a><a href=\"mailto:hi@{}\">Mail</a><a href=\"/{}\">Local</a>", platform.domain, platform.domain, platform.domain, platform.domain);
        assert_eq!(signal("dead-social-links", &html).data["count"], 0);
    }
    assert_eq!(
        signal(
            "dead-social-links",
            "<a href='https://twitter.com?lang=en'>Legacy</a>"
        )
        .data["count"],
        0
    );
}

#[test]
fn unclosed_anchors_do_not_borrow_another_links_platform_label() {
    // An unclosed anchor can steal another anchor's label or rescan the remaining page.
    let platform = &word_lists().social_platforms[0];
    let html = format!(
        "<a href='#'><a href='https://{}/profile'>{}</a>",
        platform.domain, platform.names[0]
    )
    .repeat(2);
    assert_eq!(signal("dead-social-links", &html).data["count"], 0);
}

#[test]
fn hostile_unclosed_templates_and_anchors_return_verdicts() {
    // Repeated unclosed tokens must not rescan each remaining tail or hide ordinary clear text.
    let mut anchors = "<a href=\"#\">".repeat(1024 * 1024 / "<a href=\"#\">".len());
    anchors.extend(std::iter::repeat_n(' ', 1024 * 1024 - anchors.len()));
    for html in ["{{".repeat(1024 * 1024 / 2), anchors] {
        assert_eq!(html.len(), 1024 * 1024);
        assert!(!signal("placeholder-text", &html).fired);
        let result = signal("dead-social-links", &html);
        assert!(!result.fired);
        assert_eq!(result.data["count"], 0);
    }
}

#[test]
fn page_leftovers_use_low_policy_severity_and_the_signed_review_reasons() {
    // New heuristic findings must normalize from Medium to Low and carry their specific review reason.
    let platform = &word_lists().social_platforms[0];
    for (id,html,reason) in [
        ("placeholder-text",format!("<p>{}</p>",filler()),"A text pattern match; confirm each placeholder on the page before you change it."),
        ("dead-social-links",format!("<a href='https://{}'>Profile</a>",platform.domain).repeat(2),"A link pattern match; a script can change where a link goes, so click each one before you change it."),
    ] {
        let row=polish_check_result(&signal(id,&html));
        assert_eq!(row.status,CheckStatus::Fail);
        assert_eq!(row.severity,Severity::Medium);
        assert_eq!(web_policy_severity(&WebSeverityInput::of(&row)),Some(Severity::Low));
        assert_eq!(polish_signal_confidence(id),(IssueConfidence::NeedsReview,Some(reason)));
    }
}
