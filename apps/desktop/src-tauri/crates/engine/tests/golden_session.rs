//! Exact cross-runtime fixtures for keyed page facts and their comparison.

use sitecmd_engine::checks::seo::sitemap_walk::SITEMAP_URL_LIMIT;
use sitecmd_engine::evaluation::{SessionSitemapCause, ELSEWHERE};
use sitecmd_engine::CheckStatus;

#[path = "support/session_corpus.rs"]
mod corpus;
use corpus::{assert_native_matches, assert_orphan_skip_reason, run_case, Case, Corpus};

const CORPUS: &str = include_str!("../fixtures/session/golden.json");

#[test]
fn golden_cases_reproduce_their_verdicts() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus parses");
    assert!(!corpus.cases.is_empty());
    for case in &corpus.cases {
        let expected = case.expected.as_ref().unwrap_or_else(|| {
            panic!(
                "{}: no expected block; run the ignored regenerate test",
                case.name
            )
        });
        assert_eq!(
            serde_json::to_value(run_case(case)).expect("actual serializes"),
            serde_json::to_value(expected).expect("expected serializes"),
            "{}",
            case.name
        );
    }
}

#[test]
fn a_discovering_case_is_keyed_against_the_plan_its_discovery_leaves() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus parses");
    let mut discovering = 0;
    for case in &corpus.cases {
        let Some(discover) = &case.discover else {
            continue;
        };
        discovering += 1;
        let origin = url::Url::parse(&case.routes[0])
            .expect("entry route")
            .origin()
            .ascii_serialization();
        // A null answer, or an empty one with planned routes, keeps the existing plan.
        let after_entry = run_case(case)
            .discovered
            .and_then(|answer| answer.routes)
            .filter(|routes| !routes.is_empty() || discover.planned.is_empty())
            .unwrap_or_else(|| discover.planned.clone());
        let plan: Vec<String> = std::iter::once(case.routes[0].clone())
            .chain(after_entry.iter().map(|route| format!("{origin}{route}")))
            .collect();
        assert_eq!(case.routes, plan, "{}", case.name);
    }
    assert!(discovering > 0, "the corpus holds no discovering case");
}

#[test]
fn headline_verdicts_match_each_cases_pages() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus parses");
    for case in &corpus.cases {
        let actual = run_case(case);
        let facts = |position: usize| actual.facts[position].as_ref().expect("named page");
        let verdict = |id: &str| {
            actual
                .response
                .verdicts
                .iter()
                .find(|v| v.check_id == id)
                .expect("verdict")
        };
        let discovered = || {
            actual
                .discovered
                .as_ref()
                .expect("discovered")
                .routes
                .clone()
        };
        let shared_title = "seo.duplicate_title_across_pages";
        match case.name.as_str() {
            "one_page_has_nothing_to_compare" => {
                assert!(actual.response.verdicts.is_empty());
                assert_eq!(actual.response.compared, [0]);
            }
            "two_pages_share_a_title_and_an_h1" => {
                for id in [shared_title, "seo.duplicate_h1"] {
                    assert_eq!(verdict(id).status, CheckStatus::Warn);
                    assert_eq!(verdict(id).pages, [0, 1]);
                }
            }
            "two_long_titles_that_differ_at_the_end_are_not_shared" => {
                assert!(facts(0).title.is_some() && facts(1).title.is_some());
                assert_ne!(facts(0).title, facts(1).title);
                assert_eq!(verdict(shared_title).status, CheckStatus::Pass);
            }
            "pages_without_titles_share_none" => {
                assert!(actual
                    .facts
                    .iter()
                    .all(|f| f.as_ref().expect("named").title.is_none()));
                assert_eq!(verdict(shared_title).status, CheckStatus::Pass);
            }
            "a_canonical_off_the_host_ends_a_chain" => {
                assert_eq!(facts(1).canonical.as_deref(), Some(ELSEWHERE));
                assert_eq!(verdict("seo.canonical_loop").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.canonical_loop").pages, [0, 1]);
            }
            "a_canonical_loop_between_two_routes" => {
                assert_eq!(verdict("seo.canonical_loop").status, CheckStatus::Fail);
                assert_eq!(verdict("seo.canonical_loop").pages, [1, 2]);
            }
            "a_one_way_hreflang_pair" => {
                assert_eq!(facts(0).hreflang, ["r1"]);
                assert_eq!(
                    verdict("seo.hreflang_reciprocity").status,
                    CheckStatus::Warn
                );
                assert_eq!(verdict("seo.hreflang_reciprocity").pages, [0, 1]);
            }
            "a_redirect_to_an_unplanned_path_compares_by_path_key" => {
                assert!(facts(1).page.starts_with('p'));
                assert_eq!(facts(1).requested, "r1");
                assert_eq!(verdict(shared_title).status, CheckStatus::Warn);
                assert_eq!(verdict(shared_title).pages, [0, 1]);
            }
            "a_redirect_to_an_address_with_a_query_keeps_no_facts" => {
                assert!(actual.facts[1].is_none());
            }
            "an_error_page_is_left_out" => {
                assert_eq!(actual.response.compared, [0, 2]);
                let error = facts(1);
                assert!(error.title.is_none() && error.description.is_none() && error.h1.is_none());
                assert!(error.canonical.is_none() && error.noindex == Some(false));
                assert!(error.links.is_empty() && error.hreflang.is_empty());
            }
            "five_pages_with_one_unlinked" => {
                assert_eq!(verdict("seo.orphan_pages").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.orphan_pages").pages, [4]);
            }
            "a_sitemap_page_left_out_withholds_orphan_grading" => {
                assert_eq!(verdict("seo.orphan_pages").status, CheckStatus::Skipped);
                assert!(verdict("seo.orphan_pages").pages.is_empty());
                assert_orphan_skip_reason(case);
            }
            "apex_routes_landing_on_www_leave_unread_sitemap_pages_uncompared" => {
                assert_eq!(facts(0).requested, ELSEWHERE);
                assert_eq!(verdict("seo.orphan_pages").status, CheckStatus::Skipped);
                assert_native_matches(case, &actual);
            }
            "a_www_listed_sitemap_matches_apex_pages" => {
                assert_eq!(verdict("seo.orphan_pages").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.orphan_pages").pages, [4]);
                assert_eq!(verdict("seo.noindex_in_sitemap").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.noindex_in_sitemap").pages, [4]);
                assert_native_matches(case, &actual);
            }
            "a_noindex_page_listed_in_the_sitemap" => {
                assert_eq!(facts(0).sitemap.as_ref().expect("sitemap").entries, ["r1"]);
                assert_eq!(verdict("seo.noindex_in_sitemap").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.noindex_in_sitemap").pages, [1]);
            }
            "unread_declared_sitemaps_withhold_a_clean_noindex_verdict"
            | "a_foreign_sitemap_declaration_keeps_the_set_partial" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert_eq!(
                    sitemap.partial_causes,
                    [SessionSitemapCause::UnreadDeclarations { count: 1 }]
                );
                assert_eq!(
                    sitemap.partial_because().as_deref(),
                    Some("robots.txt declares 1 further sitemap that was not read")
                );
                assert_eq!(
                    verdict("seo.noindex_in_sitemap").status,
                    CheckStatus::Skipped
                );
            }
            "an_index_sitemap_keeps_an_explicit_partial_cause" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert!(sitemap.entries.is_empty());
                assert_eq!(
                    sitemap.partial_causes,
                    [SessionSitemapCause::Index { listed: 1, read: 0 }]
                );
                assert_eq!(
                    sitemap.partial_because().as_deref(),
                    Some("the sitemap index lists 1 child sitemaps and SiteCMD read the first 0")
                );
                assert_eq!(
                    verdict("seo.noindex_in_sitemap").status,
                    CheckStatus::Skipped
                );
            }
            "a_sitemap_url_cut_keeps_an_explicit_partial_cause" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert_eq!(sitemap.entries.len(), SITEMAP_URL_LIMIT);
                assert_eq!(
                    sitemap.partial_causes,
                    [SessionSitemapCause::UrlLimit {
                        listed: SITEMAP_URL_LIMIT + 1
                    }]
                );
                assert_eq!(
                    verdict("seo.noindex_in_sitemap").status,
                    CheckStatus::Skipped
                );
            }
            "a_username_alone_is_elsewhere" | "a_password_alone_is_elsewhere" => {
                assert_eq!(facts(0).canonical.as_deref(), Some(ELSEWHERE));
                assert!(facts(0).links.is_empty());
            }
            "a_redirect_response_keeps_no_body_facts" => {
                let redirected = facts(1);
                assert!(
                    redirected.title.is_none()
                        && redirected.description.is_none()
                        && redirected.h1.is_none()
                );
                assert!(redirected.canonical.is_none() && redirected.noindex == Some(false));
                assert!(redirected.links.is_empty() && redirected.hreflang.is_empty());
            }
            "an_error_entry_page_keeps_its_sitemap" => {
                assert_eq!(facts(0).sitemap.as_ref().expect("sitemap").entries, ["r1"]);
            }
            "a_sitemap_at_the_url_limit_is_complete"
            | "an_apex_declaration_names_the_www_sitemap_that_was_read" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert!(sitemap.partial_causes.is_empty());
                assert!(sitemap.partial_because().is_none());
                if case.name == "a_sitemap_at_the_url_limit_is_complete" {
                    assert_eq!(sitemap.entries.len(), SITEMAP_URL_LIMIT);
                    assert_eq!(sitemap.entries.last().map(String::as_str), Some("r1"));
                } else {
                    assert_eq!(sitemap.entries, ["r1"]);
                }
                assert_eq!(verdict("seo.noindex_in_sitemap").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.noindex_in_sitemap").pages, [1]);
            }
            "an_index_sitemaps_children_supply_its_pages" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert_eq!(sitemap.entries.len(), 2);
                assert_eq!(sitemap.entries[0], "r1");
                assert!(sitemap.partial_causes.is_empty());
                assert_eq!(verdict("seo.noindex_in_sitemap").status, CheckStatus::Warn);
                assert_eq!(verdict("seo.noindex_in_sitemap").pages, [1]);
            }
            "an_index_past_the_child_limit_keeps_a_partial_cause" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert_eq!(
                    sitemap.partial_causes,
                    [SessionSitemapCause::Index { listed: 3, read: 2 }]
                );
                assert_eq!(
                    sitemap.partial_because().as_deref(),
                    Some("the sitemap index lists 3 child sitemaps and SiteCMD read the first 2")
                );
                assert_eq!(
                    verdict("seo.noindex_in_sitemap").status,
                    CheckStatus::Skipped
                );
            }
            "a_child_sitemap_that_did_not_answer_keeps_the_set_partial" => {
                let sitemap = facts(0).sitemap.as_ref().expect("sitemap");
                assert_eq!(sitemap.entries, ["r1"]);
                assert_eq!(
                    sitemap.partial_causes,
                    [SessionSitemapCause::Index { listed: 2, read: 0 }]
                );
                assert_eq!(
                    verdict("seo.noindex_in_sitemap").status,
                    CheckStatus::Skipped
                );
            }
            "discovery_adds_the_home_links_then_the_sitemap_pages" => {
                assert_eq!(discovered(), Some(vec!["/pricing".into(), "/about".into()]));
                assert!(facts(0).links.contains(&"r1".to_string()));
                assert_eq!(
                    facts(0).sitemap.as_ref().expect("sitemap").entries,
                    ["r2", "r1"]
                );
            }
            "discovery_keeps_the_planned_routes_when_the_sitemap_did_not_answer" => {
                assert_eq!(
                    discovered(),
                    Some(vec!["/pricing".into(), "/listed".into()])
                );
                assert_eq!(facts(1).page, "r2");
            }
            "discovery_keeps_planned_stand_ins_after_pages_read_when_robots_did_not_answer" => {
                assert_eq!(
                    discovered(),
                    Some(vec!["/pricing".into(), "/about".into(), "/listed".into()])
                );
                assert_eq!(
                    facts(0).sitemap.as_ref().expect("sitemap").partial_causes,
                    [SessionSitemapCause::UnfinishedWalk]
                );
            }
            "discovery_keeps_no_planned_stand_ins_when_the_sitemap_is_missing" => {
                assert_eq!(discovered(), Some(vec!["/pricing".into()]));
                assert!(facts(0).sitemap.is_none());
                assert_eq!(facts(1).page, "r1");
            }
            "discovery_reads_nothing_from_an_error_entry_page" => {
                assert_eq!(discovered(), None);
                assert_eq!(facts(1).page, "r1");
            }
            "discovery_reads_an_indexs_children" => {
                assert_eq!(
                    discovered(),
                    Some(vec![
                        "/pricing".into(),
                        "/posts/first".into(),
                        "/about".into()
                    ])
                );
                assert_eq!(
                    facts(0).sitemap.as_ref().expect("sitemap").entries,
                    ["r2", "r3"]
                );
            }
            "discovery_omits_a_robots_disallowed_home_link" => {
                assert_eq!(discovered(), Some(vec!["/public".into()]));
            }
            other => panic!("no headline assertion for {other}"),
        }
    }
}

#[test]
#[ignore = "regenerates the comparison corpus; run deliberately"]
fn regenerate() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
    for slot in value["cases"].as_array_mut().expect("cases") {
        slot["expected"] = serde_json::Value::Null;
    }
    let cases: Vec<Case> = serde_json::from_value(value["cases"].clone()).expect("cases parse");
    for (slot, case) in value["cases"]
        .as_array_mut()
        .expect("cases")
        .iter_mut()
        .zip(&cases)
    {
        slot["expected"] = serde_json::to_value(run_case(case)).expect("answer serializes");
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/session/golden.json");
    std::fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&value).expect("corpus serializes")
        ),
    )
    .expect("write corpus");
    println!("regenerated {path}");
}
