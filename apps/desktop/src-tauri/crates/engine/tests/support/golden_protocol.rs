use sitecmd_engine::checks::performance::protocol::Http2Check;
use sitecmd_engine::evaluation::{PageArtifact, RouteFacts};
use sitecmd_engine::CheckResult;

pub fn run(input: &serde_json::Value) -> Vec<CheckResult> {
    let page: PageArtifact = serde_json::from_value(input["page"].clone()).unwrap();
    let facts: RouteFacts = serde_json::from_value(input.clone()).unwrap();
    Http2Check.run_with_protocol(
        &page.page_context().unwrap(),
        facts.negotiated_protocol.as_ref(),
    )
}
