use super::*;
use crate::checks::CheckStatus;
use crate::probe::{ProbeFailure, ProbeFailureClass, ProbeMethod, ProbeResponse};

fn asset(url: &str, kind: AssetKind) -> CollectedAsset {
    CollectedAsset {
        url: url::Url::parse(url).expect("asset url"),
        kind,
        has_srcset: false,
        group: 0,
    }
}

fn answer(status: u16, headers: &[(&str, &str)]) -> ProbeOutcome {
    let named = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| *header == name)
            .map(|(_, value)| (*value).to_string())
    };
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: String::new(),
        content_type: named("content-type"),
        content_length: named("content-length").and_then(|value| value.parse().ok()),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        body: None,
    })
}

fn unanswered() -> ProbeOutcome {
    ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::Transport,
        detail: "connection refused".into(),
    })
}

#[test]
fn an_asset_request_is_a_raw_one_byte_range_that_counts_an_unsized_body() {
    let request = asset_request(&url::Url::parse("https://example.com/hero.png").expect("url"));
    // HEAD cannot count an unsized body, so the sampler must request GET.
    assert_eq!(request.method, ProbeMethod::Get);
    assert_eq!(request.url, "https://example.com/hero.png");
    assert_eq!(request.body, BodyPolicy::Count);
    assert_eq!(request.coding, ContentCoding::Raw);
    assert!(request
        .headers
        .contains(&("range".into(), "bytes=0-0".into())));
    assert!(request
        .headers
        .contains(&("accept-encoding".into(), "identity".into())));
}

#[test]
fn a_range_answer_is_sized_by_its_content_range_total() {
    let measured = measured_asset(
        &asset("https://example.com/hero.jpg", AssetKind::Image),
        &answer(
            206,
            &[
                ("content-type", "image/jpeg; charset=binary"),
                ("content-range", "bytes 0-0/900000"),
                ("cache-control", "public"),
                ("cache-control", "max-age=60"),
            ],
        ),
        None,
    );
    assert_eq!(measured.status_code, 206);
    assert_eq!(measured.bytes, Some(900_000));
    assert_eq!(measured.content_type.as_deref(), Some("image/jpeg"));
    assert_eq!(
        measured.cache_control.as_deref(),
        Some("public, max-age=60")
    );
}

#[test]
fn a_range_answer_with_an_unknown_total_has_no_size() {
    let measured = measured_asset(
        &asset("https://example.com/a.png", AssetKind::Image),
        &answer(206, &[("content-range", "bytes 0-0/*")]),
        Some(ProbeMeasure::counted(1, false)),
    );
    assert_eq!(measured.bytes, None);
}

#[test]
fn an_ignored_range_is_sized_by_the_declared_length_before_any_count() {
    let measured = measured_asset(
        &asset("https://example.com/a.js", AssetKind::Script),
        &answer(200, &[("content-length", "4096")]),
        Some(ProbeMeasure::counted(10, false)),
    );
    assert_eq!(measured.bytes, Some(4096));
    assert!(!measured.measured_floor);
}

#[test]
fn an_unsized_answer_is_sized_by_its_count_and_a_capped_count_is_a_floor() {
    let script = asset("https://example.com/a.js", AssetKind::Script);
    let counted = measured_asset(
        &script,
        &answer(200, &[]),
        Some(ProbeMeasure::counted(700, false)),
    );
    assert_eq!(counted.bytes, Some(700));
    let floored = measured_asset(
        &script,
        &answer(200, &[]),
        Some(ProbeMeasure::counted(600_000, true)),
    );
    assert_eq!(floored.bytes, Some(600_000));
    assert!(floored.measured_floor);
    assert_eq!(measured_asset(&script, &answer(200, &[]), None).bytes, None);
}

#[test]
fn an_error_status_keeps_its_status_and_has_no_size() {
    let measured = measured_asset(
        &asset("https://example.com/gone.png", AssetKind::Image),
        &answer(404, &[("content-length", "12")]),
        None,
    );
    assert_eq!(measured.status_code, 404);
    assert_eq!(measured.bytes, None);
}

#[test]
fn an_unanswered_request_is_an_unfetched_asset() {
    let measured = measured_asset(
        &asset("https://example.com/a.png", AssetKind::Image),
        &unanswered(),
        None,
    );
    assert_eq!(measured.status_code, 0);
    assert_eq!(measured.bytes, None);
}

/// The sampler's four rows for a page naming `assets`, each answered as given.
fn sample_of(assets: &[(&str, AssetKind, ProbeOutcome)]) -> Vec<CheckResult> {
    let body: String = assets
        .iter()
        .map(|(url, kind, _)| match kind {
            AssetKind::Image => format!("<img src=\"{url}\" alt=\"\">"),
            AssetKind::Script => format!("<script src=\"{url}\"></script>"),
            AssetKind::Style => format!("<link rel=\"stylesheet\" href=\"{url}\">"),
        })
        .collect();
    let lower = body.to_ascii_lowercase();
    let page = url::Url::parse("https://example.com/").expect("page url");
    let collection = collect_assets(&body, &lower, &page, |_| true, ASSET_SAMPLE_LIMIT);
    let measured: Vec<MeasuredAsset> = collection
        .sampled
        .iter()
        .map(|sampled| {
            let (_, _, outcome) = assets
                .iter()
                .find(|(url, _, _)| sampled.url.as_str() == *url)
                .expect("every sampled asset is answered");
            measured_asset(sampled, outcome, None)
        })
        .collect();
    evaluate_asset_sample(body.len() as u64, &collection, &measured)
}

fn row<'a>(rows: &'a [CheckResult], id: &str) -> &'a CheckResult {
    rows.iter()
        .find(|row| row.check_id == id)
        .unwrap_or_else(|| panic!("{id} row"))
}

#[test]
fn a_sample_nobody_answered_states_no_size_sum_or_cache_verdict() {
    let rows = sample_of(&[
        (
            "https://example.com/hero.png",
            AssetKind::Image,
            unanswered(),
        ),
        (
            "https://example.com/app-3f9a8c2b1e.js",
            AssetKind::Script,
            unanswered(),
        ),
    ]);
    for id in [
        "performance.asset_weight",
        "performance.broken_images",
        "performance.images.heavy",
        "performance.asset_caching",
    ] {
        assert_eq!(row(&rows, id).status, CheckStatus::Skipped, "{id}");
    }
    assert_eq!(
        row(&rows, "performance.asset_weight").description,
        "2 sampled asset requests went unanswered, so no asset bytes were measured."
    );
    assert_eq!(
        row(&rows, "performance.asset_caching").description,
        "2 sampled asset requests went unanswered, so no cache header was read."
    );
}

#[test]
fn images_nobody_answered_state_no_size_beside_a_script_that_answered() {
    let rows = sample_of(&[
        (
            "https://example.com/hero.png",
            AssetKind::Image,
            unanswered(),
        ),
        (
            "https://example.com/app.js",
            AssetKind::Script,
            answer(200, &[("content-length", "1000")]),
        ),
    ]);
    assert_eq!(
        row(&rows, "performance.images.heavy").status,
        CheckStatus::Skipped
    );
    assert_eq!(
        row(&rows, "performance.images.heavy").description,
        "1 sampled image request went unanswered, so no image size was measured."
    );
    assert_eq!(
        row(&rows, "performance.asset_weight").status,
        CheckStatus::Pass
    );
}

#[test]
fn a_page_naming_no_asset_still_passes_on_its_markup() {
    for check in sample_of(&[]) {
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.check_id);
    }
}

#[test]
fn a_capped_image_count_is_listed_as_at_least_its_measured_size() {
    // A capped count presented as a total hides that the image may be larger.
    let body = r#"<img src="/hero.png" alt="">"#;
    let page = url::Url::parse("https://example.com/").expect("page url");
    let collection = collect_assets(
        body,
        &body.to_ascii_lowercase(),
        &page,
        |_| true,
        ASSET_SAMPLE_LIMIT,
    );
    let measured = measured_asset(
        &collection.sampled[0],
        &answer(200, &[("content-type", "image/png")]),
        Some(ProbeMeasure::counted(600_000, true)),
    );
    let rows = evaluate_asset_sample(body.len() as u64, &collection, &[measured]);
    assert!(row(&rows, "performance.images.heavy")
        .description
        .contains("at least 600 KB"));
}
