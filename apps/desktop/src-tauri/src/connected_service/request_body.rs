//! Only audited request roots can reach the connected transport serializer.
use serde::Serialize;
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::super::GateRequest {}
    impl Sealed for crate::connected_ci::DeploymentFacts {}
    impl Sealed for crate::connected_ci::CiSubmission {}
    impl Sealed for super::super::autofix_jobs::ClaimRequest {}
    impl Sealed for super::super::autofix_jobs::ResultReport {}
    impl Sealed for super::super::autofix_jobs::PublishTokenRequest {}
    impl Sealed for super::EmptyRequest {}
    impl Sealed for crate::connected_codes::CodeRequestBody {}
    impl Sealed for crate::connected_codes::PollTokenRequest {}
    impl Sealed for crate::connected_codes::BaselineRequest {}
    impl Sealed for crate::connected_codes::ProvisionedRequest {}
}
pub(crate) trait WireRequest: Serialize + sealed::Sealed {
    const PRETTY: bool = false;
}
impl WireRequest for super::GateRequest {
    const PRETTY: bool = true;
}
impl WireRequest for crate::connected_ci::DeploymentFacts {
    const PRETTY: bool = true;
}
impl WireRequest for crate::connected_ci::CiSubmission {
    const PRETTY: bool = true;
}
impl WireRequest for super::autofix_jobs::ClaimRequest {}
impl WireRequest for super::autofix_jobs::ResultReport {}
impl WireRequest for super::autofix_jobs::PublishTokenRequest {}
impl WireRequest for EmptyRequest {}
impl WireRequest for crate::connected_codes::CodeRequestBody {}
impl WireRequest for crate::connected_codes::PollTokenRequest {}
impl WireRequest for crate::connected_codes::BaselineRequest {}
impl WireRequest for crate::connected_codes::ProvisionedRequest {}
#[derive(Serialize)]
pub(crate) struct EmptyRequest {}
pub(crate) const NO_BODY: Option<&EmptyRequest> = None;

pub(super) fn encode<B: WireRequest>(body: &B) -> Result<String, serde_json::Error> {
    if B::PRETTY {
        serde_json::to_string_pretty(body)
    } else {
        serde_json::to_string(body)
    }
}
