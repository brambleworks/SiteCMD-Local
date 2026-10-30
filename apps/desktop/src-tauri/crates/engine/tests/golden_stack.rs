//! Cross-runtime stack-detection fixtures, replayed through `evaluate` with each case's resolver facts. The scan runner replays these pages
//! through the checks artifact and compares the stack its evaluation answers.
//!
//! Regenerate with `cargo test -p sitecmd-engine --test golden_stack -- --ignored regenerate`.

use serde::Deserialize;
use sitecmd_engine::dns::ResolverFacts;
use sitecmd_engine::evaluation::{evaluate, EvaluationRequest, PageArtifact};
use sitecmd_engine::stack::DetectedStack;

const CORPUS: &str = include_str!("../fixtures/stack/golden.json");

#[derive(Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    comment: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    page: PageArtifact,
    #[serde(default)]
    resolver_facts: Option<ResolverFacts>,
    expected: Option<DetectedStack>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("golden.json parses")
}

fn detected(case: &Case) -> DetectedStack {
    evaluate(&EvaluationRequest {
        page: case.page.clone(),
        resolver_facts: case.resolver_facts.clone(),
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    })
    .expect("corpus pages evaluate")
    .stack
}

fn replay(value: serde_json::Value) {
    let slots = value["cases"].as_array().expect("cases array");
    assert!(!slots.is_empty(), "corpus has cases");
    for slot in slots {
        let case: Case = serde_json::from_value(slot.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", slot["name"]));
        case.expected.as_ref().unwrap_or_else(|| {
            panic!(
                "case '{}' has no expected block; run the ignored `regenerate` test",
                case.name
            )
        });
        assert_eq!(
            serde_json::to_value(detected(&case)).unwrap(),
            slot["expected"],
            "{}",
            case.name
        );
    }
    let _: Corpus = serde_json::from_value(value).expect("corpus parses");
}

#[test]
fn golden_pages_reproduce_their_stacks() {
    replay(serde_json::from_str(CORPUS).unwrap());
}

#[test]
fn headline_stacks_match_the_detector() {
    let corpus = corpus();
    let stack = |name: &str| {
        detected(
            corpus
                .cases
                .iter()
                .find(|c| c.name == name)
                .expect("case present"),
        )
    };
    assert_eq!(stack("wordpress_paths").cms.as_deref(), Some("WordPress"));
    assert!(stack("brand_words_are_not_a_cms").is_empty());
    assert_eq!(
        stack("a_cloudflare_ray_alone_names_the_host")
            .cdn
            .as_deref(),
        Some("Cloudflare")
    );
    assert_eq!(
        stack("an_unknown_server_keeps_its_product_name")
            .server
            .as_deref(),
        Some("Kestrel")
    );
    assert_eq!(
        stack("a_cname_to_pages_dev_names_cloudflare_pages")
            .hosting
            .as_deref(),
        Some("Cloudflare Pages")
    );
    let proxied = stack("a_proxied_custom_domain_names_its_cdn_and_dns_and_no_host");
    assert_eq!(proxied.cdn.as_deref(), Some("Cloudflare"));
    assert_eq!(proxied.dns_provider.as_deref(), Some("Cloudflare"));
    assert_eq!(proxied.hosting, None);
    assert_eq!(
        stack("an_apex_site_reads_its_www_cname").hosting.as_deref(),
        Some("Netlify")
    );
    assert_eq!(stack("a_failed_lookup_names_nothing").hosting, None);
    assert_eq!(
        stack("framer_generator_tag").hosting.as_deref(),
        Some("Framer")
    );
    assert!(stack("brand_words_name_no_host").is_empty());
    assert_eq!(stack("vercel_headers").hosting.as_deref(), Some("Vercel"));
}

#[test]
#[ignore]
fn regenerate() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("golden.json parses");
    let corpus = corpus();
    let slots = value["cases"].as_array_mut().expect("cases array");
    for (slot, case) in slots.iter_mut().zip(&corpus.cases) {
        slot["expected"] = serde_json::to_value(detected(case)).expect("stack serializes");
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/stack/golden.json");
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("corpus serializes")
    );
    std::fs::write(path, rendered).expect("write golden.json");
}

#[test]
#[should_panic(expected = "vercel_headers")]
fn removing_a_nullable_server_key_names_the_case() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][2]["expected"]
        .as_object_mut()
        .unwrap()
        .remove("server");
    replay(value);
}

#[test]
#[should_panic(expected = "wordpress_paths")]
fn null_is_not_an_absent_stack_field() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][0]["expected"]["server"] = serde_json::Value::Null;
    replay(value);
}
