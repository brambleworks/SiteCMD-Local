use sitecmd_engine::evaluation::{
    evaluate_session, session_page, PageArtifact, SessionPageRequest, SessionRequest,
};
use sitecmd_engine::{CheckStatus, IssueConfidence};

#[test]
fn duplicate_title_confidence_survives_the_session_response() {
    // A cross-page finding's needs-review confidence is lost on the way to the hosted runner.
    let routes = vec![
        "https://example.com/".to_string(),
        "https://example.com/menu".to_string(),
    ];
    let pages = routes
        .iter()
        .map(|url| {
            session_page(&SessionPageRequest {
                page: serde_json::from_value::<PageArtifact>(serde_json::json!({
                    "url": url,
                    "status_code": 200,
                    "headers": [],
                    "body": "<html><head><title>Shared</title></head></html>",
                    "evaluation_time": "2026-11-05T00:00:00Z"
                }))
                .unwrap(),
                probe_outcomes: Vec::new(),
                routes: routes.clone(),
            })
            .expect("page facts")
            .expect("named page")
        })
        .collect();
    let response = evaluate_session(&SessionRequest { pages });
    let row = response
        .verdicts
        .iter()
        .find(|row| row.check_id == "seo.duplicate_title_across_pages")
        .expect("duplicate title verdict");
    assert_eq!(row.status, CheckStatus::Warn);
    assert_eq!(row.pages, [0, 1]);
    assert_eq!(row.confidence, IssueConfidence::NeedsReview);
    assert_eq!(
        serde_json::to_value(row).unwrap()["confidence"],
        "needs_review"
    );
}
