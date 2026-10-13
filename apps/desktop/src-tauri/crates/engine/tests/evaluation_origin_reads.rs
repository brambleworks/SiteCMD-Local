//! The origin reads: what each round asks for, on
//! which host and under which body limit, and the verdicts graded from the
//! answers.

use sitecmd_engine::evaluation::{
    evaluate, probe_key, probe_plan, EvaluationRequest, ExecutedProbe, NotEvaluatedReason,
    PageArtifact,
};
use sitecmd_engine::probe::{
    decode_probe_body, BodyLimit, BodyPolicy, ProbeOutcome, ProbeRequest, ProbeResponse,
};
use sitecmd_engine::CheckStatus;

const ORIGIN: &str = "https://example.com";
const PAGE: &str = concat!(
    "<html><head><title>Example home page for the scan</title>",
    "<meta property=\"og:image\" content=\"https://cdn.example.net/card.png\">",
    "</head><body></body></html>"
);
const URLSET: &str = concat!(
    "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
    "<url><loc>https://example.com/</loc><lastmod>2026-08-01</lastmod></url></urlset>"
);

fn request(outcomes: Option<Vec<ExecutedProbe>>) -> EvaluationRequest {
    EvaluationRequest {
        page: PageArtifact {
            url: format!("{ORIGIN}/"),
            requested_url: Some(format!("{ORIGIN}/")),
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: PAGE.into(),
            evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
        },
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: outcomes,
        browser_facts: None,
    }
}

fn answered(url: &str, status: u16, content_type: &str, body: &str) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: url.into(),
        content_type: Some(content_type.into()),
        content_length: None,
        headers: Vec::new(),
        body: Some(decode_probe_body(body.as_bytes().to_vec())),
    })
}

/// Answer every requested probe, round by round, and keep each
/// round's requests.
fn drive(
    answer: impl Fn(&ProbeRequest) -> ProbeOutcome,
) -> (Vec<ExecutedProbe>, Vec<Vec<ProbeRequest>>) {
    let mut outcomes = Vec::new();
    let mut rounds = Vec::new();
    for _ in 0..40 {
        let plan = probe_plan(&request(Some(outcomes.clone()))).expect("plan builds");
        if plan.probes.is_empty() {
            return (outcomes, rounds);
        }
        rounds.push(
            plan.probes
                .iter()
                .map(|probe| probe.request.clone())
                .collect(),
        );
        for probe in plan.probes {
            outcomes.push(ExecutedProbe {
                outcome: answer(&probe.request),
                key: probe.key,
            });
        }
    }
    panic!("the evaluation never reached a fixpoint");
}

fn site<'a>(declared: &'a [&str]) -> impl Fn(&ProbeRequest) -> ProbeOutcome + 'a {
    move |probe| {
        let url = probe.url.as_str();
        if url == format!("{ORIGIN}/robots.txt") {
            let lines: String = declared
                .iter()
                .map(|path| format!("Sitemap: {path}\n"))
                .collect();
            answered(
                url,
                200,
                "text/plain",
                &format!("User-agent: *\nAllow: /\n{lines}"),
            )
        } else if declared.first() == Some(&url) || url == "https://example.com/sitemap.xml" {
            answered(url, 200, "application/xml", URLSET)
        } else if url == "https://cdn.example.net/card.png" {
            answered(url, 200, "image/png", "")
        } else {
            answered(url, 404, "text/html", "")
        }
    }
}

#[test]
fn the_first_round_asks_for_robots_txt_the_conventional_sitemaps_llms_txt_and_the_og_image() {
    let plan = probe_plan(&request(Some(Vec::new()))).expect("plan builds");
    let asked: Vec<&ProbeRequest> = plan.probes.iter().map(|probe| &probe.request).collect();
    let find = |url: &str| asked.iter().find(|request| request.url == url).copied();
    assert_eq!(
        find("https://example.com/robots.txt")
            .expect("robots.txt")
            .limit,
        BodyLimit::Probe
    );
    for path in [
        "/sitemap.xml",
        "/sitemap-index.xml",
        "/sitemap_index.xml",
        "/wp-sitemap.xml",
        "/sitemap.php",
        "/sitemap.txt",
    ] {
        assert_eq!(
            find(&format!("{ORIGIN}{path}")).expect(path).limit,
            BodyLimit::Sitemap
        );
    }
    assert_eq!(
        find("https://example.com/llms.txt")
            .expect("llms.txt")
            .limit,
        BodyLimit::Probe
    );
    let image = find("https://cdn.example.net/card.png").expect("the og:image");
    assert_eq!(image.body, BodyPolicy::None);
}

#[test]
fn a_declared_sitemap_is_read_once_robots_txt_names_it_and_wins() {
    let declared = ["https://example.com/sitemaps/main.xml"];
    let (outcomes, rounds) = drive(site(&declared));
    let round_of = |url: &str| {
        rounds
            .iter()
            .position(|round| round.iter().any(|request| request.url == url))
    };
    assert_eq!(round_of("https://example.com/robots.txt"), Some(0));
    assert_eq!(round_of(declared[0]), Some(1));
    let response = evaluate(&request(Some(outcomes))).expect("evaluates");
    let status = |id: &str| {
        response
            .results
            .iter()
            .find(|row| row.check_id == id)
            .unwrap_or_else(|| panic!("{id} is graded"))
            .status
    };
    assert_eq!(status("seo.sitemap"), CheckStatus::Pass);
    assert_eq!(status("config.sitemap_in_robots"), CheckStatus::Pass);
    assert_eq!(status("seo.ai_crawler_blocking"), CheckStatus::Pass);
    assert_eq!(status("seo.robots_txt"), CheckStatus::Pass);
    assert_eq!(status("seo.sitemap_freshness"), CheckStatus::Pass);
    assert_eq!(status("seo.llms_txt"), CheckStatus::Skipped);
    assert_eq!(status("seo.og_image_status"), CheckStatus::Pass);
    let sitemap = response
        .results
        .iter()
        .find(|result| result.check_id == "seo.sitemap")
        .expect("sitemap verdict");
    assert_eq!(
        sitemap.raw_data.as_ref().expect("sitemap evidence")["url"],
        declared[0]
    );
    for url in ["https://example.com/robots.txt", declared[0]] {
        assert_eq!(
            rounds
                .iter()
                .flatten()
                .filter(|request| request.url == url)
                .count(),
            1,
            "{url} is requested once"
        );
    }
    for id in [
        "config.sitemap_in_robots",
        "seo.ai_crawler_blocking",
        "seo.llms_txt",
        "seo.og_image_status",
        "seo.robots_txt",
        "seo.sitemap",
        "seo.sitemap_freshness",
    ] {
        assert!(
            !response
                .not_evaluated
                .iter()
                .any(|row| row.check == id && row.reason == NotEvaluatedReason::NoRunner),
            "{id} has a producer"
        );
    }
}

#[test]
fn a_declaration_on_another_origin_is_never_requested() {
    let (_, rounds) = drive(site(&["https://cdn.example.net/sitemap.xml"]));
    assert!(rounds
        .iter()
        .flatten()
        .all(|request| request.url != "https://cdn.example.net/sitemap.xml"));
}

#[test]
fn twenty_failing_declarations_need_at_most_twenty_one_rounds() {
    let declared: Vec<String> = (0..21)
        .map(|index| format!("{ORIGIN}/s{index}.xml"))
        .collect();
    let lines: String = declared
        .iter()
        .map(|url| format!("Sitemap: {url}\n"))
        .collect();
    let (_, rounds) = drive(|probe| {
        if probe.url == format!("{ORIGIN}/robots.txt") {
            answered(
                &probe.url,
                200,
                "text/plain",
                &format!("User-agent: *\nAllow: /\n{lines}"),
            )
        } else {
            answered(&probe.url, 404, "text/html", "")
        }
    });
    // robots.txt and the conventional paths in the first round, then one
    // declaration per round: 21 rounds at most.
    assert!(rounds.len() <= 21, "{} rounds", rounds.len());
    let asked = rounds
        .iter()
        .flatten()
        .filter(|request| declared.contains(&request.url))
        .count();
    assert_eq!(asked, 20, "the twenty-first declaration is past the limit");
}

#[test]
fn a_sitemap_read_keys_apart_from_the_same_address_read_as_a_probe() {
    let probe = ProbeRequest::get("https://example.com/sitemap.xml");
    let wire = serde_json::to_string(&probe).expect("request serializes");
    assert!(!wire.contains("\"limit\""));
    assert_eq!(
        probe_key(&probe),
        "get\u{1f}https://example.com/sitemap.xml\u{1f}body=success_only\u{1f}redirects=follow"
    );
    assert_ne!(
        probe_key(&probe.clone().limit(BodyLimit::Sitemap)),
        probe_key(&probe)
    );
}

#[test]
fn missing_origin_documents_leave_crawler_policy_and_sitemap_freshness_unstated() {
    let (outcomes, _) = drive(|probe| answered(&probe.url, 404, "text/html", ""));
    let response = evaluate(&request(Some(outcomes))).expect("evaluates");
    for id in ["seo.ai_crawler_blocking", "seo.sitemap_freshness"] {
        assert!(
            response.planned.iter().any(|check| check.check == id),
            "{id} is covered by a producer"
        );
        assert!(
            response.results.iter().all(|result| result.check_id != id),
            "{id} has no usable input"
        );
    }
}
