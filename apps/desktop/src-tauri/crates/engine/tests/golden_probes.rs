//! Exact cross-runtime fixtures for probe verdicts.
//!
//! Regenerate with `cargo test -p sitecmd-engine --test golden_probes -- --ignored regenerate`.

use serde::Deserialize;
use sitecmd_engine::checks::compliance::legal_documents;
use sitecmd_engine::checks::config::{alt_host, favicon, missing_page, web_manifest};
use sitecmd_engine::checks::performance::redirects::{
    evaluate_redirect_chain, RedirectWalkStep, RedirectWalker,
};
use sitecmd_engine::checks::performance::{assets as perf_assets, compression, page_weight, ttfb};
use sitecmd_engine::checks::security::dns_email::{
    dangling_cname, dkim, dmarc, domain_expiry, records as dns_records, spf,
};
use sitecmd_engine::checks::security::{
    cors, directory_listing, exposed_files, https_enforcement, open_redirect, security_txt, tls,
    vulnerable_libraries,
};
use sitecmd_engine::checks::seo::redirects::evaluate_temporary_redirect;
use sitecmd_engine::checks::seo::robots::RobotsTxtFetch;
use sitecmd_engine::checks::seo::robots_directives::evaluate_sitemap_in_robots;
use sitecmd_engine::checks::seo::sitemap::{SitemapFetch, SitemapProbe, SitemapProbeObservation};
use sitecmd_engine::checks::seo::{geo, links, og_image, robots, sitemap};
use sitecmd_engine::dns::{CaaRecord, DnsOutcome, MxRecord};
use sitecmd_engine::probe::{ProbeOutcome, ProbeResponse};
use sitecmd_engine::{CheckResult, CheckStatus, IssueConfidence, PageContext, Severity};

const CORPUS: &str = include_str!("../fixtures/checks/golden_probes.json");

#[derive(Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    comment: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    check: String,
    input: serde_json::Value,
    expected: Option<Vec<CheckResult>>,
}

#[derive(Deserialize)]
struct SecurityTxtInput {
    base: String,
    evaluation_time: String,
    well_known: security_txt::SecurityTxtFetch,
    legacy: Option<security_txt::SecurityTxtFetch>,
}

#[derive(Deserialize)]
struct DirectoryListingInput {
    outcomes: Vec<(String, ProbeOutcome)>,
}

#[derive(Deserialize)]
struct LinkObservationInput {
    url: String,
    head: ProbeOutcome,
    #[serde(default)]
    get: Option<ProbeOutcome>,
}

#[derive(Deserialize)]
struct BrokenLinksInput {
    scope: String,
    page_body: String,
    observations: Vec<LinkObservationInput>,
}

#[derive(Deserialize)]
struct FaviconInput {
    kind: String,
    #[serde(default)]
    safe_href: String,
    #[serde(default)]
    probed_url: String,
    outcome: serde_json::Value,
}

#[derive(Deserialize)]
struct OutcomeInput {
    outcome: ProbeOutcome,
}

#[derive(Deserialize)]
struct AltHostInput {
    alt_host: String,
    outcome: ProbeOutcome,
}

#[derive(Deserialize)]
struct RobotsInput {
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    status: Option<u16>,
}

#[derive(Deserialize)]
struct ExposedFilesInput {
    page_body: String,
    // Either the literal string "all_404" (every path 404s) or a map of
    // path -> the classified outcome for that probe (unlisted paths 404).
    probes: serde_json::Value,
}

#[derive(Deserialize)]
struct RobotsBodyInput {
    body: String,
}

#[derive(Deserialize)]
struct SitemapDocumentInput {
    url: String,
    xml: String,
}

#[derive(Deserialize)]
struct SitemapProbeInput {
    // "found" (with url + xml), "missing", or "inconclusive" (with
    // observations as [url, outcome] pairs).
    kind: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    xml: String,
    #[serde(default)]
    observations: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct SitemapCaseInput {
    #[serde(default)]
    page_body: String,
    robots: RobotsInput,
    probe: SitemapProbeInput,
}

#[derive(Deserialize)]
struct TlsInput {
    host: String,
    evaluation_time: String,
    // Captured facts, or absent with a `unavailable` reason instead.
    #[serde(default)]
    facts: Option<tls::TlsFacts>,
    // One of "not_https", "no_host", "transport", "probe_failed".
    #[serde(default)]
    unavailable: Option<String>,
}

#[derive(Deserialize)]
struct AdvisoryInput {
    package_name: String,
    current_version: String,
    advisory_id: String,
    severity: String,
    #[serde(default)]
    advisory_url: Option<String>,
    #[serde(default)]
    fixed_version: Option<String>,
}

#[derive(Deserialize)]
struct VulnerableLibrariesInput {
    page_body: String,
    // Absent means the advisory database was unreachable; present (even
    // empty) means it answered.
    #[serde(default)]
    advisories: Option<Vec<AdvisoryInput>>,
}

#[derive(Deserialize)]
struct WebManifestInput {
    page_body: String,
    // A classified outcome, the literal "disallowed" for a target the
    // runner's network policy refused, or absent when the plan completes
    // without a probe.
    #[serde(default)]
    outcome: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct LegalDocumentInput {
    // Which document: "privacy" or "terms".
    kind: String,
    page_body: String,
    // One outcome per candidate path, in probe order. The driver stops at
    // the first success exactly as the runtime shell does.
    #[serde(default)]
    path_outcomes: Vec<ProbeOutcome>,
}

#[derive(Deserialize)]
struct HttpsEnforcementInput {
    page_url: String,
    // The runtime's own local-environment verdict for the page, the same flag
    // `PageContext::is_localhost` carries. Absent means a public site.
    #[serde(default)]
    page_is_local: bool,
    // A classified outcome for the planned probe, or absent when the plan
    // completes without one.
    #[serde(default)]
    outcome: Option<ProbeOutcome>,
}

#[derive(Deserialize)]
struct OpenRedirectInput {
    // Per-label probe outcomes; every unlisted probe of the full plan takes
    // `unlisted_outcome`.
    outcomes: std::collections::HashMap<String, ProbeOutcome>,
    // Default for unlisted probes. Absent means a same-origin 302 without a canary.
    #[serde(default)]
    unlisted_outcome: Option<ProbeOutcome>,
}

#[derive(Deserialize)]
struct RedirectWalkInput {
    start_url: String,
    // One classified outcome per walker probe; the walk must terminate on
    // the final entry, so every fixture outcome is consumed.
    outcomes: Vec<ProbeOutcome>,
}

// Drive the engine walker through the recorded outcomes.
fn walk_through(
    case_name: &str,
    input: &RedirectWalkInput,
) -> sitecmd_engine::checks::performance::redirects::RedirectWalk {
    let start = url::Url::parse(&input.start_url).expect("fixture start url");
    let mut walker = Some(RedirectWalker::new(&start));
    for (index, outcome) in input.outcomes.iter().enumerate() {
        let live = walker.take().unwrap_or_else(|| {
            panic!("{case_name}: walk terminated before consuming every fixture outcome")
        });
        match live.observe(outcome) {
            RedirectWalkStep::Continue(next) => walker = Some(next),
            RedirectWalkStep::Done(walk) => {
                assert_eq!(
                    index + 1,
                    input.outcomes.len(),
                    "{case_name}: walk terminated with unconsumed fixture outcomes"
                );
                return walk;
            }
        }
    }
    panic!("{case_name}: fixture outcomes did not terminate the walk");
}

#[derive(Deserialize)]
struct PageWeightInput {
    html_size_bytes: usize,
}

#[derive(Deserialize)]
struct TtfbInput {
    // The runtime-supplied sample; absent when the measurement failed.
    #[serde(default)]
    ttfb_ms: Option<u64>,
    #[serde(default)]
    unavailable: Option<String>,
    #[serde(default = "default_measurement_source")]
    measurement_source: String,
}

fn default_measurement_source() -> String {
    "http_probe".into()
}

#[derive(Deserialize)]
struct CompressionInput {
    // Absent when the HEAD request itself failed.
    #[serde(default)]
    head: Option<compression::EncodingProbe>,
    // Absent when the GET request itself failed (or was never needed).
    #[serde(default)]
    get: Option<compression::EncodingProbe>,
    // Content-Encoding on the page response, for the failed-probe fallback.
    #[serde(default)]
    page_content_encoding: Option<String>,
}

#[derive(Deserialize)]
struct AssetSampleInput {
    page_body: String,
    // Targets the fixture's network policy refuses, by absolute URL.
    #[serde(default)]
    blocked_urls: Vec<String>,
    #[serde(default = "default_sample_limit")]
    sample_limit: usize,
    measured: Vec<perf_assets::MeasuredAsset>,
}

fn default_sample_limit() -> usize {
    30
}

// Shared by the SPF and DMARC cases: a TXT answer plus the apex MX answer
// their verdicts' MX gate reads. `mx` is present exactly when the TXT
// verdict does not complete on its own.
#[derive(Deserialize)]
struct DnsTxtWithMxInput {
    domain: String,
    txt: DnsOutcome<Vec<String>>,
    #[serde(default)]
    mx: Option<DnsOutcome<Vec<MxRecord>>>,
}

#[derive(Deserialize)]
struct DkimInput {
    domain: String,
    mx: DnsOutcome<Vec<MxRecord>>,
    apex_txt: DnsOutcome<Vec<String>>,
    // Per-selector TXT answers for the sweep; unlisted selectors
    // authoritatively have no records. Absent when the gate completes
    // without sweeping.
    #[serde(default)]
    selectors: Option<std::collections::HashMap<String, DnsOutcome<Vec<String>>>>,
}

#[derive(Deserialize)]
struct DnsMxInput {
    domain: String,
    mx: DnsOutcome<Vec<MxRecord>>,
}

#[derive(Deserialize)]
struct DnssecInput {
    domain: String,
    dnskey: DnsOutcome<usize>,
}

#[derive(Deserialize)]
struct CaaInput {
    domain: String,
    caa: DnsOutcome<Vec<CaaRecord>>,
}

#[derive(Deserialize)]
struct DanglingCnameInput {
    domain: String,
    cname: DnsOutcome<Vec<String>>,
    // The alias target's address answer, present exactly when the CNAME
    // answer names a target.
    #[serde(default)]
    target_addresses: Option<DnsOutcome<Vec<String>>>,
}

#[derive(Deserialize)]
struct DomainExpiryInput {
    domain: String,
    evaluation_time: String,
    outcome: ProbeOutcome,
}

#[derive(Deserialize)]
struct OgImageInput {
    page_body: String,
    // A classified probe outcome, the literal "disallowed" for a target the
    // runner's network policy refused, or absent when the plan completes
    // without a probe.
    #[serde(default)]
    outcome: Option<serde_json::Value>,
}

// The fixture robots endpoint state: a body means Found, a bare status
// means Status, neither means a network-level Error.
fn robots_fetch(input: RobotsInput) -> RobotsTxtFetch {
    match (input.body, input.status) {
        (Some(body), _) => RobotsTxtFetch::Found { body },
        (None, Some(code)) => RobotsTxtFetch::Status(code),
        (None, None) => RobotsTxtFetch::Error("request failed".into()),
    }
}

// The one fixture sitemap-document constructor: root and entry count come
// from the engine parser, so found-cases exercise it too.
fn sitemap_fetch(url: &str, xml: &str) -> SitemapFetch {
    let sitemap::SitemapParse::WellFormed(document) = sitemap::parse_sitemap_document(xml) else {
        panic!("fixture sitemap document must satisfy the shared grammar");
    };
    SitemapFetch::new(url, xml, &document)
}

fn sitemap_probe(input: SitemapProbeInput) -> SitemapProbe {
    let observations = input
        .observations
        .into_iter()
        .map(|(url, outcome)| SitemapProbeObservation { url, outcome })
        .collect();
    match input.kind.as_str() {
        "found" => SitemapProbe::Found(sitemap_fetch(&input.url, &input.xml)),
        "missing" => SitemapProbe::Missing { observations },
        "inconclusive" => SitemapProbe::Inconclusive { observations },
        other => panic!("unknown sitemap probe kind '{other}'"),
    }
}

// The fixture page every page-consuming probe verdict evaluates against,
// under the corpus's frozen evaluation time.
fn fixture_page(body: String) -> PageContext {
    PageContext {
        evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .expect("fixture evaluation_time")
            .with_timezone(&chrono::Utc),
        url: url::Url::parse("https://example.com/").expect("fixture page url"),
        response_headers: http::header::HeaderMap::new(),
        status_code: 200,
        body,
        is_localhost: false,
        is_strict_localhost: false,
        http_version: Some("HTTP/2.0".into()),
        body_lower_cache: std::sync::OnceLock::new(),
    }
}

fn absent_probe() -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status: 404,
        final_url: String::new(),
        content_type: None,
        content_length: None,
        headers: Vec::new(),
        body: None,
    })
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("golden_probes.json parses")
}

fn run_case(case: &Case) -> Vec<CheckResult> {
    match case.check.as_str() {
        "security.security_txt" => {
            let input: SecurityTxtInput =
                serde_json::from_value(case.input.clone()).expect("security_txt input parses");
            let evaluation_time = chrono::DateTime::parse_from_rfc3339(&input.evaluation_time)
                .expect("fixture evaluation_time")
                .with_timezone(&chrono::Utc);
            match security_txt::evaluate_well_known(
                "security.security_txt",
                &input.base,
                input.well_known,
                evaluation_time,
            ) {
                security_txt::SecurityTxtStep::Done(results) => {
                    assert!(
                        input.legacy.is_none(),
                        "{}: legacy outcome provided but the well-known verdict completed",
                        case.name
                    );
                    results
                }
                security_txt::SecurityTxtStep::ProbeLegacy { well_known_status } => {
                    let legacy = input.legacy.unwrap_or_else(|| {
                        panic!(
                            "{}: well-known 404/410 requires a legacy outcome in the fixture",
                            case.name
                        )
                    });
                    security_txt::evaluate_legacy(
                        "security.security_txt",
                        &input.base,
                        well_known_status,
                        legacy,
                        evaluation_time,
                    )
                }
            }
        }
        "security.directory_listing" => {
            let input: DirectoryListingInput =
                serde_json::from_value(case.input.clone()).expect("directory_listing input parses");
            vec![directory_listing::grade_listing_probes(
                directory_listing::exposed_directories(input.outcomes),
            )]
        }
        "security.exposed_files" => {
            let input: ExposedFilesInput =
                serde_json::from_value(case.input.clone()).expect("exposed_files input parses");
            let per_path = if input.probes == serde_json::json!("all_404") {
                std::collections::HashMap::new()
            } else {
                serde_json::from_value::<std::collections::HashMap<String, ProbeOutcome>>(
                    input.probes,
                )
                .expect("exposed_files probes map parses")
            };
            let source_advisory = exposed_files::source_secrets_result(&input.page_body);
            let path_rows = exposed_files::SENSITIVE_PATHS
                .iter()
                .map(|(path, desc, severity): &(&str, &str, Severity)| {
                    let outcome = per_path.get(*path).cloned().unwrap_or_else(absent_probe);
                    exposed_files::grade_path_probe(path, desc, severity, outcome)
                })
                .collect();
            exposed_files::summarize_exposed_files(source_advisory, path_rows, 0)
        }
        "config.favicon" => {
            let input: FaviconInput =
                serde_json::from_value(case.input.clone()).expect("favicon input parses");
            let outcome = if input.outcome == serde_json::json!("disallowed") {
                Err(favicon::FaviconProbeSkip::Disallowed)
            } else {
                Ok(serde_json::from_value::<ProbeOutcome>(input.outcome)
                    .expect("favicon outcome parses"))
            };
            match input.kind.as_str() {
                "declared" => {
                    favicon::evaluate_declared(&input.safe_href, &input.probed_url, outcome)
                }
                "fallback" => favicon::evaluate_fallback(outcome),
                other => panic!("unknown favicon case kind '{other}'"),
            }
        }
        "config.custom_404" => {
            let input: OutcomeInput =
                serde_json::from_value(case.input.clone()).expect("custom_404 input parses");
            missing_page::evaluate_missing_page(input.outcome)
        }
        "config.www_redirect" => {
            let input: AltHostInput =
                serde_json::from_value(case.input.clone()).expect("www_redirect input parses");
            alt_host::evaluate_alt_host(&input.alt_host, input.outcome)
        }
        "security.cors_reflection" => {
            let input: OutcomeInput =
                serde_json::from_value(case.input.clone()).expect("cors_reflection input parses");
            cors::evaluate_reflection(input.outcome)
        }
        "config.sitemap_in_robots" => {
            let input: RobotsInput =
                serde_json::from_value(case.input.clone()).expect("sitemap_in_robots input parses");
            evaluate_sitemap_in_robots(&robots_fetch(input))
        }
        "seo.robots_txt" => {
            let input: RobotsInput =
                serde_json::from_value(case.input.clone()).expect("robots_txt input parses");
            robots::evaluate_robots_txt(&robots_fetch(input))
        }
        "seo.ai_crawler_blocking" => {
            let input: RobotsBodyInput = serde_json::from_value(case.input.clone())
                .expect("ai_crawler_blocking input parses");
            geo::ai_crawlers::evaluate_ai_crawler_blocking(&input.body)
        }
        "seo.llms_txt" => {
            let input: OutcomeInput =
                serde_json::from_value(case.input.clone()).expect("llms_txt input parses");
            geo::llms_txt::evaluate_llms_txt(input.outcome)
        }
        "seo.sitemap_freshness" => {
            let input: SitemapDocumentInput =
                serde_json::from_value(case.input.clone()).expect("sitemap_freshness input parses");
            geo::sitemap_freshness::evaluate_sitemap_freshness(&sitemap_fetch(
                &input.url, &input.xml,
            ))
        }
        "seo.sitemap" => {
            let input: SitemapCaseInput =
                serde_json::from_value(case.input.clone()).expect("sitemap input parses");
            sitemap::evaluate_sitemap(
                &fixture_page(input.page_body),
                &robots_fetch(input.robots),
                &sitemap_probe(input.probe),
            )
        }
        "seo.og_image_status" => {
            let input: OgImageInput =
                serde_json::from_value(case.input.clone()).expect("og_image input parses");
            match og_image::plan_og_image(&input.page_body) {
                og_image::OgImageStep::Done(results) => {
                    assert!(
                        input.outcome.is_none(),
                        "{}: outcome provided but the og:image plan completed without a probe",
                        case.name
                    );
                    results
                }
                og_image::OgImageStep::Probe { value, .. } => {
                    let outcome = input.outcome.unwrap_or_else(|| {
                        panic!(
                            "{}: planned probe requires an outcome in the fixture",
                            case.name
                        )
                    });
                    let outcome = if outcome == serde_json::json!("disallowed") {
                        Err(og_image::OgImageProbeSkip::Disallowed)
                    } else {
                        Ok(serde_json::from_value::<ProbeOutcome>(outcome)
                            .expect("og_image outcome parses"))
                    };
                    og_image::evaluate_og_image(&value, outcome)
                }
            }
        }
        "seo.broken_links" | "seo.broken_external_links" => {
            let input: BrokenLinksInput =
                serde_json::from_value(case.input.clone()).expect("broken_links input parses");
            let page = fixture_page(input.page_body);
            let targets = links::resolve_link_targets(&page, |_| true);
            let (scope, severity, sample_limit, eligible) = match input.scope.as_str() {
                "internal" => (
                    links::LinkScope::Internal,
                    Severity::High,
                    links::BROKEN_LINK_INTERNAL_SAMPLE,
                    targets.internal.len(),
                ),
                "external" => (
                    links::LinkScope::External,
                    Severity::Medium,
                    links::BROKEN_LINK_EXTERNAL_SAMPLE,
                    targets.external.len(),
                ),
                other => panic!("unknown link scope '{other}'"),
            };
            if input.observations.is_empty() {
                return vec![links::no_link_targets_result(
                    &case.check,
                    severity,
                    scope,
                    &targets,
                    sample_limit,
                )];
            }
            let observations: Vec<_> = input
                .observations
                .iter()
                .map(|entry| {
                    let url = url::Url::parse(&entry.url).expect("fixture link url");
                    links::observe_link(&url, &entry.head, entry.get.as_ref())
                })
                .collect();
            let sampled = observations.len();
            let summary = links::summarize_link_probes(sampled, observations);
            vec![links::link_probe_result(
                &case.check,
                severity,
                scope,
                &targets,
                eligible,
                sampled,
                sample_limit,
                summary,
            )]
        }
        "security.ssl" => {
            let input: TlsInput =
                serde_json::from_value(case.input.clone()).expect("tls input parses");
            let evaluation_time = chrono::DateTime::parse_from_rfc3339(&input.evaluation_time)
                .expect("fixture evaluation_time")
                .with_timezone(&chrono::Utc);
            match (input.facts, input.unavailable.as_deref()) {
                (Some(facts), None) => tls::evaluate_tls(&input.host, &facts, evaluation_time),
                (None, Some(reason)) => {
                    let reason = match reason {
                        "not_https" => tls::TlsUnavailable::NotHttps,
                        "no_host" => tls::TlsUnavailable::NoHost,
                        "transport" => tls::TlsUnavailable::Transport {
                            detail: "connection reset".into(),
                        },
                        "probe_failed" => tls::TlsUnavailable::ProbeFailed {
                            detail: "probe task did not return".into(),
                        },
                        other => panic!("unknown tls unavailable reason '{other}'"),
                    };
                    tls::tls_unavailable_results(&reason)
                }
                _ => panic!(
                    "{}: a tls case needs exactly one of `facts` or `unavailable`",
                    case.name
                ),
            }
        }
        "security.vulnerable_libraries" => {
            let input: VulnerableLibrariesInput = serde_json::from_value(case.input.clone())
                .expect("vulnerable_libraries input parses");
            // Detection runs for real, so a fixture that pins a verdict also
            // pins which script URLs the detector accepted.
            let detected = vulnerable_libraries::detect_libraries(&input.page_body);
            let lookup = match input.advisories {
                None => vulnerable_libraries::AdvisoryLookup::Unavailable,
                Some(advisories) => vulnerable_libraries::AdvisoryLookup::Answered(
                    advisories
                        .into_iter()
                        .map(|advisory| vulnerable_libraries::LibraryAdvisory {
                            package_name: advisory.package_name,
                            current_version: advisory.current_version,
                            advisory_id: advisory.advisory_id,
                            severity: advisory.severity,
                            advisory_url: advisory.advisory_url,
                            fixed_version: advisory.fixed_version,
                        })
                        .collect(),
                ),
            };
            vulnerable_libraries::evaluate_vulnerable_libraries(&detected, lookup)
        }
        "config.web_manifest" => {
            let input: WebManifestInput =
                serde_json::from_value(case.input.clone()).expect("web_manifest input parses");
            let page_url = url::Url::parse("https://example.com/page").expect("fixture page url");
            match web_manifest::plan_web_manifest(&input.page_body, &page_url) {
                web_manifest::WebManifestStep::Done(results) => {
                    assert!(
                        input.outcome.is_none(),
                        "{}: outcome provided but the plan completed without a probe",
                        case.name
                    );
                    results
                }
                web_manifest::WebManifestStep::Probe { safe_href, url } => {
                    let outcome = input.outcome.unwrap_or_else(|| {
                        panic!(
                            "{}: planned probe requires an outcome in the fixture",
                            case.name
                        )
                    });
                    let outcome = if outcome == serde_json::json!("disallowed") {
                        Err(web_manifest::WebManifestProbeSkip::Disallowed {
                            safe_url: url.to_string(),
                        })
                    } else {
                        Ok(serde_json::from_value::<ProbeOutcome>(outcome)
                            .expect("web_manifest outcome parses"))
                    };
                    web_manifest::evaluate_web_manifest(&safe_href, outcome)
                }
            }
        }
        "compliance.privacy_policy" | "compliance.terms" => {
            let input: LegalDocumentInput =
                serde_json::from_value(case.input.clone()).expect("legal document input parses");
            let lower = input.page_body.to_ascii_lowercase();
            let (linked, paths) = match input.kind.as_str() {
                "privacy" => (
                    legal_documents::page_links_privacy_policy(&lower),
                    legal_documents::PRIVACY_PATHS,
                ),
                "terms" => (
                    legal_documents::has_terms_link(&lower),
                    legal_documents::TERMS_PATHS,
                ),
                other => panic!("unknown legal document kind '{other}'"),
            };
            let mut walk = legal_documents::LegalPathWalk::default();
            if !linked {
                for (path, outcome) in paths.iter().copied().zip(&input.path_outcomes) {
                    if walk.observe(path, outcome) {
                        break;
                    }
                }
            }
            let sweep = walk.finish();
            match input.kind.as_str() {
                "privacy" => legal_documents::evaluate_privacy_policy(linked, &sweep),
                _ => legal_documents::evaluate_terms(linked, &sweep),
            }
        }
        "security.https_enforcement" => {
            let input: HttpsEnforcementInput =
                serde_json::from_value(case.input.clone()).expect("https_enforcement input parses");
            let page_url = url::Url::parse(&input.page_url).expect("fixture page url");
            let step = https_enforcement::plan_https_enforcement(&page_url, input.page_is_local);
            let planned_outcome = || {
                input.outcome.clone().unwrap_or_else(|| {
                    panic!(
                        "{}: planned probe requires an outcome in the fixture",
                        case.name
                    )
                })
            };
            match step {
                https_enforcement::HttpsEnforcementStep::Done(results) => {
                    assert!(
                        input.outcome.is_none(),
                        "{}: outcome provided but the plan completed without a probe",
                        case.name
                    );
                    results
                }
                https_enforcement::HttpsEnforcementStep::ProbeHttpOrigin { url } => {
                    https_enforcement::evaluate_http_downgrade(url.as_str(), planned_outcome())
                }
                https_enforcement::HttpsEnforcementStep::ProbeHttpsOrigin { url } => {
                    https_enforcement::evaluate_https_availability(url.as_str(), planned_outcome())
                }
            }
        }
        "security.open_redirect" => {
            let input: OpenRedirectInput =
                serde_json::from_value(case.input.clone()).expect("open_redirect input parses");
            let benign = ProbeOutcome::Response(ProbeResponse {
                status: 302,
                final_url: String::new(),
                content_type: None,
                content_length: None,
                headers: vec![("location".into(), "/dashboard".into())],
                body: None,
            });
            // The whole plan runs, so a fixture that names one vulnerable
            // label also proves the other probes stay clean.
            let unlisted = input.unlisted_outcome.as_ref().unwrap_or(&benign);
            let mut sweep = open_redirect::OpenRedirectSweep::default();
            for planned in open_redirect::open_redirect_probes("https://site.example") {
                let outcome = input.outcomes.get(&planned.label).unwrap_or(unlisted);
                sweep.observe(&planned, outcome);
            }
            open_redirect::evaluate_open_redirect(sweep)
        }
        "performance.redirect_chain" => {
            let input: RedirectWalkInput =
                serde_json::from_value(case.input.clone()).expect("redirect_chain input parses");
            let walk = walk_through(&case.name, &input);
            vec![evaluate_redirect_chain(&input.start_url, &walk)]
        }
        "seo.temporary_redirect" => {
            let input: RedirectWalkInput = serde_json::from_value(case.input.clone())
                .expect("temporary_redirect input parses");
            vec![evaluate_temporary_redirect(&walk_through(
                &case.name, &input,
            ))]
        }
        "security.dns.spf" => {
            let input: DnsTxtWithMxInput =
                serde_json::from_value(case.input.clone()).expect("spf input parses");
            match spf::evaluate_spf_txt(&input.domain, input.txt) {
                spf::SpfStep::Done(results) => {
                    assert!(
                        input.mx.is_none(),
                        "{}: mx answer provided but the TXT verdict completed",
                        case.name
                    );
                    results
                }
                spf::SpfStep::NeedsMx(pending) => {
                    let mx = input.mx.unwrap_or_else(|| {
                        panic!("{}: a missing SPF record requires an mx answer", case.name)
                    });
                    pending.evaluate(&mx)
                }
            }
        }
        "security.dns.dmarc" => {
            let input: DnsTxtWithMxInput =
                serde_json::from_value(case.input.clone()).expect("dmarc input parses");
            match dmarc::evaluate_dmarc_txt(&input.domain, input.txt) {
                dmarc::DmarcStep::Done(results) => {
                    assert!(
                        input.mx.is_none(),
                        "{}: mx answer provided but the TXT verdict completed",
                        case.name
                    );
                    results
                }
                dmarc::DmarcStep::NeedsMx(pending) => {
                    let mx = input.mx.unwrap_or_else(|| {
                        panic!(
                            "{}: an answered DMARC lookup requires an mx answer",
                            case.name
                        )
                    });
                    pending.evaluate(&mx)
                }
            }
        }
        "security.dns.dkim" => {
            let input: DkimInput =
                serde_json::from_value(case.input.clone()).expect("dkim input parses");
            match dkim::evaluate_dkim_gate(&input.domain, &input.mx, &input.apex_txt) {
                dkim::DkimStep::Done(results) => {
                    assert!(
                        input.selectors.is_none(),
                        "{}: selector answers provided but the gate completed",
                        case.name
                    );
                    results
                }
                dkim::DkimStep::Sweep(sweep) => {
                    let listed = input.selectors.unwrap_or_else(|| {
                        panic!("{}: a sweeping gate requires selector answers", case.name)
                    });
                    let outcomes: Vec<(String, DnsOutcome<Vec<String>>)> = sweep
                        .probe_names()
                        .iter()
                        .map(|(selector, _)| {
                            (
                                selector.to_string(),
                                listed
                                    .get(*selector)
                                    .cloned()
                                    .unwrap_or(DnsOutcome::NoRecords),
                            )
                        })
                        .collect();
                    sweep.evaluate(&outcomes)
                }
            }
        }
        "security.dns.mx" => {
            let input: DnsMxInput =
                serde_json::from_value(case.input.clone()).expect("mx input parses");
            dns_records::evaluate_mx(&input.domain, input.mx)
        }
        "security.dns.dnssec" => {
            let input: DnssecInput =
                serde_json::from_value(case.input.clone()).expect("dnssec input parses");
            dns_records::evaluate_dnssec(&input.domain, input.dnskey)
        }
        "security.dns.caa" => {
            let input: CaaInput =
                serde_json::from_value(case.input.clone()).expect("caa input parses");
            dns_records::evaluate_caa(&input.domain, input.caa)
        }
        "security.dns.dangling_cname" => {
            let input: DanglingCnameInput =
                serde_json::from_value(case.input.clone()).expect("dangling_cname input parses");
            match dangling_cname::evaluate_www_cname(&input.domain, input.cname) {
                dangling_cname::WwwAliasStep::Done(results) => {
                    assert!(
                        input.target_addresses.is_none(),
                        "{}: target addresses provided but the CNAME verdict completed",
                        case.name
                    );
                    results
                }
                dangling_cname::WwwAliasStep::LookupTarget(probe) => {
                    let addresses = input.target_addresses.unwrap_or_else(|| {
                        panic!("{}: an alias requires a target address answer", case.name)
                    });
                    probe.evaluate(addresses)
                }
            }
        }
        "security.domain_expiry" => {
            let input: DomainExpiryInput =
                serde_json::from_value(case.input.clone()).expect("domain_expiry input parses");
            let evaluation_time = chrono::DateTime::parse_from_rfc3339(&input.evaluation_time)
                .expect("fixture evaluation_time")
                .with_timezone(&chrono::Utc);
            domain_expiry::evaluate_rdap(&input.domain, &input.outcome, evaluation_time)
        }
        "performance.page_weight" => {
            let input: PageWeightInput =
                serde_json::from_value(case.input.clone()).expect("page_weight input parses");
            vec![page_weight::html_size_result(input.html_size_bytes)]
        }
        "performance.ttfb" => {
            let input: TtfbInput =
                serde_json::from_value(case.input.clone()).expect("ttfb input parses");
            match (input.ttfb_ms, input.unavailable) {
                (Some(ms), None) => ttfb::evaluate_ttfb(ms, &input.measurement_source),
                (None, Some(detail)) => ttfb::ttfb_unavailable(&detail),
                _ => panic!(
                    "{}: exactly one of ttfb_ms and unavailable must be present",
                    case.name
                ),
            }
        }
        "performance.compression" => {
            let input: CompressionInput =
                serde_json::from_value(case.input.clone()).expect("compression input parses");
            match compression::evaluate_compression_head(input.head.as_ref()) {
                compression::CompressionStep::Done(results) => {
                    assert!(
                        input.get.is_none(),
                        "{}: get answer provided but the HEAD verdict completed",
                        case.name
                    );
                    results
                }
                compression::CompressionStep::NeedsGet => {
                    let mut page = fixture_page(String::new());
                    if let Some(encoding) = &input.page_content_encoding {
                        page.response_headers.insert(
                            "content-encoding",
                            encoding.parse().expect("fixture encoding header"),
                        );
                    }
                    compression::evaluate_compression_get(input.get, &page)
                }
            }
        }
        "performance.asset_weight" => {
            let input: AssetSampleInput =
                serde_json::from_value(case.input.clone()).expect("asset sample input parses");
            let lower = input.page_body.to_ascii_lowercase();
            let page_url = url::Url::parse("https://example.com/").expect("fixture page url");
            let blocked: std::collections::HashSet<&str> =
                input.blocked_urls.iter().map(String::as_str).collect();
            let collection = perf_assets::collect_assets(
                &input.page_body,
                &lower,
                &page_url,
                |target| !blocked.contains(target.as_str()),
                input.sample_limit,
            );
            perf_assets::evaluate_asset_sample(
                input.page_body.len() as u64,
                &collection,
                &input.measured,
            )
        }
        other => panic!("no probe-check driver registered for corpus id '{other}'"),
    }
}

#[test]
fn golden_cases_reproduce_their_verdicts() {
    let corpus = corpus();
    assert!(!corpus.cases.is_empty(), "corpus has cases");
    for case in &corpus.cases {
        let expected = case.expected.as_ref().unwrap_or_else(|| {
            panic!(
                "case '{}' has no expected block; run the ignored `regenerate` test",
                case.name
            )
        });
        let actual = run_case(case);
        assert_eq!(
            actual.len(),
            expected.len(),
            "{}: result row count",
            case.name
        );
        for (index, (actual_row, expected_row)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(
                serde_json::to_value(actual_row).expect("actual row serializes"),
                serde_json::to_value(expected_row).expect("expected row serializes"),
                "{}[{index}] ({})",
                case.name,
                actual_row.check_id
            );
        }
    }
}

#[test]
fn headline_verdicts_match_the_documented_checks() {
    let corpus = corpus();
    let status = |name: &str| -> CheckStatus {
        let case = corpus
            .cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("case '{name}' present"));
        let rows = run_case(case);
        assert_eq!(rows.len(), 1, "{name}: one result row");
        rows[0].status
    };

    // A fresh, well-formed RFC 9116 file at the well-known path passes.
    assert_eq!(status("valid_well_known_file_passes"), CheckStatus::Pass);
    // An Expires value in the past cannot pass: staleness is the field's
    // entire purpose.
    assert_ne!(
        status("expired_expires_value_is_flagged"),
        CheckStatus::Pass
    );
    // Definite 404/410 at both paths is a Warn (absence of the standard
    // disclosure route), never a Fail: the org may have another channel.
    assert_eq!(status("missing_at_both_paths_warns"), CheckStatus::Warn);
    // A file only at the legacy root path is found but cannot pass: RFC 9116
    // requires the well-known location.
    assert_ne!(
        status("legacy_location_only_is_graded_as_migration_evidence"),
        CheckStatus::Pass
    );
    // A server error is directly observed unavailability: reviewable Warn.
    assert_eq!(
        status("server_error_at_well_known_is_reviewable_unavailability"),
        CheckStatus::Warn
    );
    // A transport failure makes no presence claim at all: Skipped.
    assert_eq!(
        status("transport_failure_makes_no_presence_claim"),
        CheckStatus::Skipped
    );
    // One confirmed server-generated index fails; clean, blocked, and
    // unreachable probes are not evidence of a listing.
    assert_eq!(
        status("one_exposed_directory_fails_high"),
        CheckStatus::Fail
    );
    assert_eq!(
        status("clean_and_unreachable_probes_pass"),
        CheckStatus::Pass
    );

    // exposed_files emits multiple rows, so assert against the whole set.
    let rows_of = |name: &str| -> Vec<CheckResult> {
        let case = corpus
            .cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("case '{name}' present"));
        run_case(case)
    };
    let row = |rows: &[CheckResult], id: &str| -> CheckResult {
        rows.iter()
            .find(|r| r.check_id == id)
            .unwrap_or_else(|| panic!("row '{id}' present"))
            .clone()
    };

    let env = rows_of("exposed_env_with_secret_assignments_is_critical");
    let env_row = row(&env, "security.exposed_files.env");
    assert_eq!(env_row.status, CheckStatus::Fail);
    assert_eq!(env_row.severity, Severity::Critical);
    assert!(!env
        .iter()
        .any(|r| r.check_id == "security.exposed_files.summary"));

    // Every path absent: a single clean Pass summary.
    let clean = rows_of("all_paths_absent_summary_passes");
    assert_eq!(
        row(&clean, "security.exposed_files.summary").status,
        CheckStatus::Pass
    );

    // An SPA catch-all HTML shell at /.env is not an exposure - the summary
    // still passes.
    let spa = rows_of("spa_catch_all_shell_is_not_an_exposure");
    assert_eq!(
        row(&spa, "security.exposed_files.summary").status,
        CheckStatus::Pass
    );

    // A secret-named identifier in an inline script surfaces as the
    // source-secrets advisory (Warn, never Critical).
    let advisory = rows_of("inline_script_secret_name_is_a_source_advisory");
    let advisory_row = row(&advisory, "security.exposed_files.source_secrets");
    assert_eq!(advisory_row.status, CheckStatus::Warn);
    assert_ne!(advisory_row.severity, Severity::Critical);

    assert_eq!(
        status("declared_icon_serving_an_image_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("declared_icon_returning_404_warns"),
        CheckStatus::Warn
    );
    assert_eq!(
        status("declared_icon_serving_html_needs_review"),
        CheckStatus::Warn
    );
    assert_eq!(
        status("no_declaration_with_conventional_icon_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("no_declaration_and_no_conventional_icon_warns"),
        CheckStatus::Warn
    );
    assert_eq!(
        status("disallowed_favicon_target_is_never_requested"),
        CheckStatus::Skipped
    );

    // Custom 404: only a real 404 with a substantial body passes. A 2xx for
    // a missing path is the soft-404 review case.
    assert_eq!(status("substantial_404_page_passes"), CheckStatus::Pass);
    assert_eq!(
        status("soft_404_two_hundred_needs_review"),
        CheckStatus::Warn
    );
    assert_eq!(status("bare_404_body_is_a_minimal_warn"), CheckStatus::Warn);
    // A status that only says the origin refused the probe is not a verdict
    // about missing pages at all. (Content negotiation is pinned by the unit
    // test on the request plan, not here: this corpus feeds verdicts an
    // outcome, so it cannot express one URL answering two ways.)
    assert_eq!(
        status("a_rate_limited_404_probe_produces_no_verdict"),
        CheckStatus::Skipped
    );

    // www/non-www: only BOTH hosts serving the site is a duplicate-content
    // warning; a redirect or an error status is not. A host the resolver has
    // no address for is a single-host configuration, not a failed request.
    assert_eq!(
        status("alternate_host_redirecting_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("both_hosts_serving_the_site_warns"),
        CheckStatus::Warn
    );
    assert_eq!(
        status("alternate_host_error_status_is_not_duplicate_content"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("an_alternate_host_that_does_not_resolve_is_a_single_host_configuration"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("reflected_origin_with_credentials_fails_high"),
        CheckStatus::Fail
    );
    assert_eq!(
        status("reflected_origin_without_credentials_warns"),
        CheckStatus::Warn
    );
    assert_eq!(
        status("allowlisted_origin_is_not_reflection"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("unreachable_reflection_probe_makes_no_claim"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("robots_with_a_sitemap_directive_passes"),
        CheckStatus::Pass
    );
    for name in [
        "robots_without_the_optional_directive_is_not_a_defect",
        "confirmed_missing_robots_is_distinct_from_unavailable",
        "unavailable_robots_endpoint_is_inconclusive",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }

    assert_eq!(
        status("internal_links_all_responding_pass"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("a_get_confirmed_404_fails_the_internal_sample"),
        CheckStatus::Fail
    );
    // Cloudflare's email-obfuscation anchor is 404 by design and is never a
    // site route, so it leaves the sample instead of failing it.
    let reserved = &rows_of("a_cloudflare_email_protection_anchor_is_never_sampled")[0];
    assert_eq!(reserved.status, CheckStatus::Pass);
    assert_eq!(
        reserved.raw_data.as_ref().expect("raw data")["excluded_reserved_paths"],
        1
    );
    assert_eq!(
        status("a_head_404_that_gets_200_is_not_broken"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("a_server_error_destination_is_inconclusive_not_broken"),
        CheckStatus::Skipped
    );
    assert_eq!(
        status("a_page_with_no_eligible_internal_targets_passes"),
        CheckStatus::Pass
    );
    // External destinations carry Medium severity, internal High.
    assert_eq!(
        status("external_confirmed_missing_fails_at_medium"),
        CheckStatus::Fail
    );
    assert_eq!(
        status("external_unreachable_host_is_inconclusive"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("robots_policy_with_sitemap_directive_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("wildcard_root_disallow_warns_as_a_default_block"),
        CheckStatus::Warn
    );
    for name in [
        "confirmed_missing_robots_file_is_a_skip",
        "server_error_robots_endpoint_is_not_evaluated",
        "failed_robots_request_makes_no_policy_claim",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }

    assert_eq!(
        status("training_only_token_block_is_reported_as_policy"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("discovery_token_block_warns_for_review"),
        CheckStatus::Warn
    );
    let wildcard = rows_of("wildcard_root_block_is_left_to_the_primary_robots_check");
    assert!(wildcard.is_empty(), "the wildcard block emits no rows");
    let path_scoped = "path_scoped_ai_rules_block_no_crawler_at_the_root";
    assert_eq!(status(path_scoped), CheckStatus::Pass, "{path_scoped}");

    assert_eq!(
        status("nonempty_llms_text_passes_with_bounded_claims"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("empty_llms_body_warns_as_an_incomplete_endpoint"),
        CheckStatus::Warn
    );
    for name in [
        "html_catch_all_at_llms_txt_is_not_a_text_file",
        "confirmed_missing_llms_file_is_a_skip",
        "rate_limited_llms_endpoint_is_inconclusive",
        "llms_transport_failure_makes_no_presence_claim",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }

    assert_eq!(
        status("well_formed_urlset_passes_with_entry_count"),
        CheckStatus::Pass
    );
    for name in [
        "empty_sitemap_document_warns",
        "missing_sitemap_on_wordpress_names_the_core_sitemap",
        "cross_origin_declaration_is_reported_unverified",
        // A document the grammar rejects is not a sitemap here, even though
        // page discovery still reads locations out of it.
        "malformed_sitemap_is_reported_as_not_a_sitemap",
    ] {
        assert_eq!(status(name), CheckStatus::Warn, "{name}");
    }
    // An inconclusive probe establishes nothing, so it is a skip and never a
    // warning the operator is asked to clear.
    assert_eq!(
        status("inconclusive_probe_never_becomes_a_missing_sitemap"),
        CheckStatus::Skipped
    );
    assert_eq!(
        status("plain_text_sitemap_passes_as_a_sitemap"),
        CheckStatus::Pass
    );

    // Sitemap freshness: the optional lastmod tag never fails by absence or
    // coverage; only malformed (or repeated) direct values warn.
    assert_eq!(
        status("lastmod_free_sitemap_passes_because_the_tag_is_optional"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("valid_lastmod_coverage_passes_with_contextual_math"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("malformed_lastmod_values_warn_with_direct_evidence"),
        CheckStatus::Warn
    );
    // The sitemap protocol references the W3C Datetime note: every profile
    // shape (including minute precision with a zone) is valid, while a
    // space-separated, impossible, or zone-less value is not.
    assert_eq!(
        status("every_w3c_datetime_profile_shape_passes_freshness"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("space_separated_impossible_and_zoneless_lastmod_values_warn"),
        CheckStatus::Warn
    );

    assert_eq!(
        status("og_image_404_is_a_broken_preview_image"),
        CheckStatus::Fail
    );
    assert_eq!(
        status("image_typed_og_success_passes_with_bounded_claim"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("bot_gated_og_image_403_is_hedged_for_review"),
        CheckStatus::Warn
    );
    for name in [
        "page_without_og_image_is_skipped_without_a_probe",
        "relative_og_image_defers_to_the_relative_check",
        "unreachable_og_image_is_skipped_not_broken",
        "disallowed_og_image_target_is_never_requested",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }

    assert_eq!(
        status("direct_final_response_passes_with_no_redirects"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("relative_location_hop_resolves_against_the_current_position"),
        CheckStatus::Pass
    );
    assert_eq!(status("two_hop_chain_warns_by_count"), CheckStatus::Warn);
    for name in [
        "four_hop_chain_fails_by_count",
        "revisited_url_fails_as_a_redirect_loop",
        "redirect_without_location_fails_as_unresolvable",
        "hop_limit_walk_fails_without_claiming_a_final_url",
    ] {
        assert_eq!(status(name), CheckStatus::Fail, "{name}");
    }
    assert_eq!(
        status("transport_failure_walk_is_inconclusive"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("https_upgrade_via_302_warns_for_intent_review"),
        CheckStatus::Warn
    );
    assert_eq!(status("https_upgrade_via_301_passes"), CheckStatus::Pass);
    assert_eq!(
        status("cross_domain_302_is_a_content_redirect_not_canonicalization"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("inconclusive_walk_never_passes_the_status_review"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("http_origin_permanent_redirect_to_https_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("http_origin_serving_the_site_fails_high"),
        CheckStatus::Fail
    );
    for name in [
        "http_origin_temporary_redirect_to_https_warns",
        "first_hop_to_another_http_host_needs_review",
        "http_origin_dead_end_error_is_not_insecure_content",
    ] {
        assert_eq!(status(name), CheckStatus::Warn, "{name}");
    }
    for name in [
        "unreachable_http_origin_makes_no_enforcement_claim",
        // A local preview is the only http scan with nothing to grade.
        "a_local_http_scan_keeps_the_preview_skip",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }
    // A public http scan already observed cleartext delivery, so it fails
    // either way; the HTTPS probe only decides which defect is reported.
    for name in [
        "an_http_scan_of_a_host_that_serves_https_is_a_missing_redirect",
        "an_http_only_host_fails_instead_of_reporting_https_untested",
    ] {
        assert_eq!(status(name), CheckStatus::Fail, "{name}");
    }

    assert_eq!(
        status("a_canary_redirect_on_an_auth_path_fails"),
        CheckStatus::Fail
    );
    assert_eq!(
        status("a_protocol_relative_canary_location_still_counts"),
        CheckStatus::Fail
    );
    for name in [
        "no_probe_redirecting_to_the_canary_passes",
        "a_same_origin_bounce_echoing_the_canary_is_not_a_finding",
        "a_canary_lookalike_host_is_not_a_finding",
    ] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    assert_ne!(
        status("no_open_redirect_probe_answering_produces_no_verdict"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("no_open_redirect_probe_answering_produces_no_verdict"),
        CheckStatus::Skipped
    );
    // 90 real answers out of 98 are still real evidence, so the check
    // grades - and the copy states 90 rather than claiming the full grid.
    let partial_sweep = rows_of("a_partially_answered_open_redirect_sweep_states_what_it_tested");
    assert_eq!(partial_sweep[0].status, CheckStatus::Pass);
    assert!(partial_sweep[0]
        .description
        .contains("Tested 90 of the 98 planned probes"));
    assert_eq!(partial_sweep[0].confidence, IssueConfidence::NeedsReview);

    for name in [
        "no_privacy_path_answering_produces_no_verdict",
        "no_terms_path_answering_produces_no_verdict",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }
    let partial_paths = rows_of("a_partially_answered_privacy_sweep_warns_from_what_answered");
    assert_eq!(partial_paths[0].status, CheckStatus::Warn);
    // Only the two paths that ANSWERED may be named as tested.
    assert_eq!(
        partial_paths[0].raw_data.as_ref().expect("raw data")["probed_paths"],
        serde_json::json!(["/privacy", "/legal/privacy"])
    );

    assert_ne!(
        status("an_unreachable_alternate_host_produces_no_verdict"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("an_unreachable_alternate_host_produces_no_verdict"),
        CheckStatus::Skipped
    );

    for name in [
        "no_declared_manifest_passes_without_a_probe",
        "a_complete_manifest_passes_with_bounded_install_claims",
    ] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    for name in [
        "a_manifest_missing_name_and_icons_warns",
        "an_html_rewrite_at_the_manifest_url_is_invalid_json",
        "a_json_array_manifest_is_not_a_manifest_object",
        "a_confirmed_missing_manifest_warns_at_high_confidence",
        "a_server_error_manifest_response_needs_review",
    ] {
        assert_eq!(status(name), CheckStatus::Warn, "{name}");
    }
    for name in [
        "an_unreachable_manifest_makes_no_availability_claim",
        "an_oversized_manifest_body_reports_an_unread_response",
        "a_disallowed_manifest_target_is_never_requested",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }

    for name in [
        "an_in_page_privacy_link_passes_without_probing",
        "a_french_privacy_link_counts_as_a_policy",
        "a_served_privacy_path_passes_but_needs_verification",
        "an_in_page_terms_link_passes_without_probing",
        "a_served_terms_path_passes_but_needs_verification",
    ] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    for name in [
        "no_privacy_link_or_path_warns_at_medium",
        "no_terms_link_or_path_warns_at_low",
    ] {
        assert_eq!(status(name), CheckStatus::Warn, "{name}");
    }
    let severity_of = |name: &str| rows_of(name)[0].severity;
    assert_eq!(
        severity_of("no_privacy_link_or_path_warns_at_medium"),
        Severity::Medium
    );
    assert_eq!(
        severity_of("no_terms_link_or_path_warns_at_low"),
        Severity::Low
    );

    for name in [
        "a_page_with_no_pinned_libraries_emits_no_rows",
        "a_site_bundle_name_is_never_queried_as_an_npm_package",
    ] {
        assert!(rows_of(name).is_empty(), "{name} must emit no rows");
    }
    assert_eq!(
        status("clean_advisory_answer_passes_for_the_detected_versions"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("an_advisory_for_another_version_does_not_fail_this_page"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("an_unreachable_advisory_database_makes_no_verification_claim"),
        CheckStatus::Skipped
    );
    assert_eq!(
        status("a_matching_advisory_fails_at_medium_by_default"),
        CheckStatus::Fail
    );
    assert_eq!(
        severity_of("a_matching_advisory_fails_at_medium_by_default"),
        Severity::Medium
    );
    assert_eq!(
        severity_of("a_critical_advisory_raises_the_finding_to_high"),
        Severity::High
    );

    let tls_row = |case_name: &str, check_id: &str| -> CheckResult {
        let rows = rows_of(case_name);
        assert_eq!(rows.len(), 4, "{case_name}: one row per TLS sub-check");
        rows.iter()
            .find(|row| row.check_id == check_id)
            .unwrap_or_else(|| panic!("{case_name}: row '{check_id}' present"))
            .clone()
    };
    let healthy = "a_healthy_certificate_passes_all_four_sub_checks";
    for check_id in tls::TLS_CHECK_IDS {
        assert_eq!(
            tls_row(healthy, check_id).status,
            CheckStatus::Pass,
            "{check_id}"
        );
    }

    // Expiry: past is Critical, within a week is a High warning, and the
    // 8-30 day renewal window passes rather than crying wolf.
    let expired = tls_row(
        "an_expired_certificate_fails_expiry_critical",
        tls::EXPIRY_CHECK_ID,
    );
    assert_eq!(expired.status, CheckStatus::Fail);
    assert_eq!(expired.severity, Severity::Critical);
    let soon = tls_row(
        "a_certificate_expiring_within_a_week_warns_high",
        tls::EXPIRY_CHECK_ID,
    );
    assert_eq!(soon.status, CheckStatus::Warn);
    assert_eq!(soon.severity, Severity::High);
    assert_eq!(
        tls_row(
            "a_certificate_inside_the_renewal_window_passes",
            tls::EXPIRY_CHECK_ID
        )
        .status,
        CheckStatus::Pass
    );
    // A missing expiry is never assumed valid, and it skips ONLY expiry.
    let no_expiry = "an_adapter_without_expiry_skips_that_sub_check_only";
    assert_eq!(
        tls_row(no_expiry, tls::EXPIRY_CHECK_ID).status,
        CheckStatus::Skipped
    );
    assert_eq!(
        tls_row(no_expiry, tls::HOSTNAME_CHECK_ID).status,
        CheckStatus::Pass
    );

    // Hostname: a wildcard covers exactly one label, never the bare parent.
    assert_eq!(
        tls_row(
            "a_wildcard_certificate_covers_one_label",
            tls::HOSTNAME_CHECK_ID
        )
        .status,
        CheckStatus::Pass
    );
    for name in [
        "a_wildcard_certificate_does_not_cover_the_bare_parent",
        "a_certificate_naming_another_host_fails_the_hostname_check",
    ] {
        let row = tls_row(name, tls::HOSTNAME_CHECK_ID);
        assert_eq!(row.status, CheckStatus::Fail, "{name}");
        assert_eq!(row.severity, Severity::Critical, "{name}");
    }
    assert_eq!(
        tls_row(
            "an_adapter_without_certificate_names_skips_the_hostname_check",
            tls::HOSTNAME_CHECK_ID
        )
        .status,
        CheckStatus::Skipped
    );

    // Chain: a definitive validity condition fails; an unanchorable chain is
    // a trust-store difference (Warn), because the page fetch succeeded.
    let definitive = tls_row(
        "a_definitive_chain_rejection_fails_critical",
        tls::CHAIN_CHECK_ID,
    );
    assert_eq!(definitive.status, CheckStatus::Fail);
    assert_eq!(definitive.severity, Severity::Critical);
    let trust_difference = tls_row(
        "an_unknown_issuer_is_a_trust_difference_not_a_failure",
        tls::CHAIN_CHECK_ID,
    );
    assert_eq!(trust_difference.status, CheckStatus::Warn);
    assert_eq!(trust_difference.severity, Severity::High);
    assert_eq!(
        tls_row(
            "an_unavailable_chain_verdict_is_skipped",
            tls::CHAIN_CHECK_ID
        )
        .status,
        CheckStatus::Skipped
    );

    // Protocol: deprecated versions fail; an unreported version skips.
    let deprecated = tls_row(
        "a_deprecated_tls_version_fails_the_protocol_check",
        tls::PROTOCOL_CHECK_ID,
    );
    assert_eq!(deprecated.status, CheckStatus::Fail);
    assert_eq!(deprecated.severity, Severity::High);
    assert_eq!(
        tls_row(
            "an_adapter_without_a_negotiated_version_skips_the_protocol_check",
            tls::PROTOCOL_CHECK_ID
        )
        .status,
        CheckStatus::Skipped
    );

    // No facts at all: every sub-check reports its own coverage exception,
    // and a transport failure never becomes a certificate finding.
    for name in [
        "a_non_https_scan_target_skips_every_sub_check",
        "a_transport_failure_skips_every_sub_check",
    ] {
        let rows = rows_of(name);
        assert_eq!(rows.len(), 4, "{name}");
        assert!(
            rows.iter().all(|row| row.status == CheckStatus::Skipped),
            "{name}"
        );
    }

    assert_eq!(status("spf_hardfail_record_passes"), CheckStatus::Pass);
    assert_eq!(status("spf_plus_all_fails_high"), CheckStatus::Fail);
    assert_eq!(severity_of("spf_plus_all_fails_high"), Severity::High);
    for name in [
        "spf_duplicate_records_fail_as_permerror",
        "spf_over_the_lookup_limit_fails",
    ] {
        assert_eq!(status(name), CheckStatus::Fail, "{name}");
    }
    assert_eq!(
        status("spf_missing_on_a_mail_receiving_domain_warns_medium"),
        CheckStatus::Warn
    );
    assert_eq!(
        severity_of("spf_missing_on_a_mail_receiving_domain_warns_medium"),
        Severity::Medium
    );
    assert_eq!(
        severity_of("spf_missing_on_a_no_mail_domain_warns_low"),
        Severity::Low
    );
    assert_eq!(
        status("spf_lookup_failure_makes_no_claim"),
        CheckStatus::Skipped
    );

    assert_eq!(status("dmarc_reject_policy_passes"), CheckStatus::Pass);
    assert_eq!(
        status("dmarc_p_none_on_a_mail_receiving_domain_warns_medium"),
        CheckStatus::Warn
    );
    assert_eq!(
        severity_of("dmarc_p_none_on_a_mail_receiving_domain_warns_medium"),
        Severity::Medium
    );
    assert_eq!(status("dmarc_missing_record_warns"), CheckStatus::Warn);
    assert_eq!(
        status("dmarc_malformed_record_on_a_mail_receiving_domain_fails"),
        CheckStatus::Fail
    );
    assert_eq!(
        rows_of("dmarc_unrelated_txt_reports_no_record")[0].title,
        "No DMARC record"
    );
    assert_eq!(
        status("dmarc_lookup_failure_makes_no_claim"),
        CheckStatus::Skipped
    );

    // A domain with no MX and no SPF shows no mail setup: the selector sweep
    // is skipped, never graded as a pass or a warning.
    assert_eq!(
        status("dkim_gate_skips_non_mail_domains"),
        CheckStatus::Skipped
    );
    for name in [
        "dkim_gate_honors_a_declared_no_mail_posture",
        "dkim_active_selector_passes",
        "dkim_proton_mail_selector_passes",
        "dkim_empty_sweep_with_null_spf_is_consistent",
    ] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    for name in [
        "dkim_empty_sweep_on_a_sending_domain_warns",
        "dkim_revoked_selector_warns_without_verification_claims",
    ] {
        let row = &rows_of(name)[0];
        assert_eq!(row.status, CheckStatus::Warn, "{name}");
        assert_eq!(row.confidence, IssueConfidence::NeedsReview, "{name}");
    }
    assert!(
        !rows_of("dkim_revoked_selector_warns_without_verification_claims")[0]
            .description
            .contains("can verify")
    );

    // MX is informational: every answered posture (receiving, null MX)
    // passes; only a failed lookup skips.
    for name in [
        "mx_receiving_domain_passes",
        "mx_null_mx_is_a_healthy_no_mail_posture",
    ] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    assert_eq!(
        status("mx_lookup_failure_makes_no_claim"),
        CheckStatus::Skipped
    );

    // DNSSEC and CAA are hardening nudges: absence (and a non-restricting
    // CAA set) warns at Low, never harder.
    assert_eq!(status("dnssec_published_keys_pass"), CheckStatus::Pass);
    assert_eq!(status("dnssec_absent_keys_warn"), CheckStatus::Warn);
    assert_eq!(severity_of("dnssec_absent_keys_warn"), Severity::Low);
    assert_eq!(status("caa_issue_restriction_passes"), CheckStatus::Pass);
    for name in [
        "caa_iodef_only_does_not_restrict_issuance",
        "caa_missing_records_warn",
    ] {
        assert_eq!(status(name), CheckStatus::Warn, "{name}");
        assert_eq!(severity_of(name), Severity::Low, "{name}");
    }

    for name in [
        "www_without_a_cname_passes",
        "www_alias_with_a_resolving_target_passes",
    ] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    assert_eq!(
        status("www_alias_with_an_unresolving_target_fails"),
        CheckStatus::Fail
    );
    assert_eq!(
        severity_of("www_alias_with_an_unresolving_target_fails"),
        Severity::Medium
    );
    assert_eq!(
        status("www_target_lookup_failure_makes_no_claim"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("domain_expiry_distant_expiration_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("domain_expiry_inside_a_week_warns_high"),
        CheckStatus::Warn
    );
    assert_eq!(
        severity_of("domain_expiry_inside_a_week_warns_high"),
        Severity::High
    );
    let past_expiry = &rows_of("domain_expiry_past_date_needs_registrar_review")[0];
    assert_eq!(past_expiry.status, CheckStatus::Warn);
    assert_eq!(past_expiry.confidence, IssueConfidence::NeedsReview);
    assert_eq!(
        status("domain_expiry_registry_infrastructure_never_fails"),
        CheckStatus::Skipped
    );

    // Page weight: 1 MB warns, 3 MB fails, from the exact fetched byte count.
    assert_eq!(
        status("page_weight_small_document_passes"),
        CheckStatus::Pass
    );
    assert_eq!(
        status("page_weight_over_one_megabyte_warns"),
        CheckStatus::Warn
    );
    let huge_html = &rows_of("page_weight_over_three_megabytes_fails")[0];
    assert_eq!(huge_html.status, CheckStatus::Fail);
    assert_eq!(huge_html.severity, Severity::High);

    for name in ["ttfb_fast_sample_passes", "ttfb_good_sample_passes"] {
        assert_eq!(status(name), CheckStatus::Pass, "{name}");
    }
    let slow_ttfb = &rows_of("ttfb_slow_sample_warns_for_review")[0];
    assert_eq!(slow_ttfb.status, CheckStatus::Warn);
    assert_eq!(slow_ttfb.confidence, IssueConfidence::NeedsReview);
    assert_eq!(status("ttfb_very_slow_sample_fails"), CheckStatus::Fail);
    assert_eq!(
        status("ttfb_failed_measurement_makes_no_claim"),
        CheckStatus::Skipped
    );

    assert_eq!(
        status("compression_proven_on_head_passes"),
        CheckStatus::Pass
    );
    for name in [
        "compression_uncompressed_get_fails",
        "compression_vary_only_get_fails_with_capability_copy",
    ] {
        assert_eq!(status(name), CheckStatus::Fail, "{name}");
    }
    assert!(
        rows_of("compression_vary_only_get_fails_with_capability_copy")[0]
            .description
            .contains("only signals capability")
    );
    for name in [
        "compression_non_2xx_probe_is_inconclusive",
        "compression_failed_probes_without_page_signal_skip",
    ] {
        assert_eq!(status(name), CheckStatus::Skipped, "{name}");
    }
    assert_eq!(
        status("compression_failed_probes_fall_back_to_page_headers"),
        CheckStatus::Pass
    );

    let sampler_row = |case_name: &str, check_id: &str| -> CheckResult {
        let rows = rows_of(case_name);
        assert_eq!(rows.len(), 4, "{case_name}: one row per sampler id");
        rows.iter()
            .find(|row| row.check_id == check_id)
            .unwrap_or_else(|| panic!("{case_name}: row '{check_id}' present"))
            .clone()
    };
    let clean = rows_of("asset_sample_clean_page_passes");
    assert!(clean.iter().all(|row| row.status == CheckStatus::Pass));
    assert_eq!(
        sampler_row("asset_sample_heavy_image_warns", "performance.images.heavy").status,
        CheckStatus::Warn
    );
    assert_eq!(
        sampler_row(
            "asset_sample_single_broken_image_warns",
            "performance.broken_images"
        )
        .status,
        CheckStatus::Warn
    );
    assert_eq!(
        sampler_row(
            "asset_sample_three_broken_images_fail",
            "performance.broken_images"
        )
        .status,
        CheckStatus::Fail
    );
    let weak_cache = sampler_row(
        "asset_sample_weak_cached_fingerprint_warns",
        "performance.asset_caching",
    );
    assert_eq!(weak_cache.status, CheckStatus::Warn);
    assert_eq!(weak_cache.severity, Severity::Low);
    // A third-party origin sets its own cache headers: counted, never graded.
    let third_party = sampler_row(
        "asset_sample_third_party_weak_cache_is_not_graded",
        "performance.asset_caching",
    );
    assert_eq!(third_party.status, CheckStatus::Pass);
    let third_party_raw = third_party.raw_data.as_ref().expect("raw data");
    assert_eq!(third_party_raw["third_party_sampled"], 1);
    assert_eq!(third_party_raw["weak_count"], 0);
    // Two srcset candidates in one group: the weight counts the largest
    // (2 MB), never the 3 MB sum no navigation transfers.
    let srcset_weight = sampler_row(
        "asset_sample_srcset_group_counts_one_representative",
        "performance.asset_weight",
    );
    let srcset_raw = srcset_weight.raw_data.as_ref().expect("raw data");
    assert_eq!(srcset_raw["measured_asset_bytes"], 2_000_000);
    let refused = sampler_row(
        "asset_sample_refused_target_marks_coverage_incomplete",
        "performance.asset_weight",
    );
    let refused_raw = refused.raw_data.as_ref().expect("raw data");
    assert_eq!(refused_raw["measurement_incomplete"], true);
    assert_eq!(refused_raw["skipped_unsupported"], 1);
    assert_eq!(refused.confidence, IssueConfidence::NeedsReview);
}

#[test]
#[ignore]
fn regenerate() {
    let mut value: serde_json::Value =
        serde_json::from_str(CORPUS).expect("golden_probes.json parses");
    let cases: Vec<Case> =
        serde_json::from_value(value.get("cases").expect("cases array present").clone())
            .expect("cases parse");
    let out = value
        .get_mut("cases")
        .and_then(|c| c.as_array_mut())
        .expect("cases array");
    for (slot, case) in out.iter_mut().zip(&cases) {
        let rows = run_case(case);
        slot["expected"] = serde_json::to_value(&rows).expect("rows serialize");
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/checks/golden_probes.json"
    );
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("corpus serializes")
    );
    std::fs::write(path, rendered).expect("write golden_probes.json");
    println!("regenerated {path}");
}
