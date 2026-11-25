use crate::constants::CODE_SCAN_MAX_TEXT_BYTES;
use sitecmd_engine_host::wants::{self, HostIo, ReadBudget};
use sitecmd_protocol::engine_abi::{
    AuditFailure, AuditFileOffer, AuditReport, BodyRef, SessionBegin, Want, WantAnswer,
    AUDIT_MAX_FILE_BYTES,
};

pub(in crate::core) mod report;
#[cfg(test)]
mod tests;
#[cfg(test)]
use sitecmd_protocol::engine_abi::{Done, Step};

#[derive(Debug)]
pub struct SessionReport {
    pub report: AuditReport,
    pub files: Vec<AuditFileOffer>,
}

pub(in crate::core) fn read_budget() -> ReadBudget {
    ReadBudget::new(CODE_SCAN_MAX_TEXT_BYTES, AUDIT_MAX_FILE_BYTES)
}

#[cfg(test)]
pub(super) fn resume_round(
    request: &SessionBegin,
    budget: &mut ReadBudget,
    io: &dyn HostIo,
    wants: Vec<Want>,
    cancelled: &dyn Fn() -> bool,
    resume: impl FnOnce(Vec<WantAnswer>, &[u8]) -> Step,
) -> Step {
    match answer_batch(request, budget, io, wants, cancelled) {
        Ok((answers, region)) => resume(answers, &region),
        Err(error) => Step::Done {
            done: Done::AuditFailed(error),
        },
    }
}

#[cfg(test)]
pub(super) fn answer_batch(
    request: &SessionBegin,
    budget: &mut ReadBudget,
    io: &dyn HostIo,
    wants: Vec<Want>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<WantAnswer>, Vec<u8>), AuditFailure> {
    answer_observed_batch(request, budget, io, wants, cancelled, &mut |_| {})
}

pub(in crate::core) fn answer_observed_batch(
    request: &SessionBegin,
    budget: &mut ReadBudget,
    io: &dyn HostIo,
    wants: Vec<Want>,
    cancelled: &dyn Fn() -> bool,
    handed_file: &mut dyn FnMut(&[u8]),
) -> Result<(Vec<WantAnswer>, Vec<u8>), AuditFailure> {
    let before = budget.completed_requests();
    let mut answers = Vec::with_capacity(wants.len());
    let mut region = Vec::new();
    for want in wants {
        if cancelled() {
            return Err(AuditFailure::Cancelled);
        }
        let (mut answer, bytes) = wants::answer(request, budget, io, &want).into_parts();
        if let WantAnswer::File { body } = &mut answer {
            handed_file(&bytes);
            *body = BodyRef {
                at: u32::try_from(region.len()).map_err(|_| AuditFailure::InvalidInput)?,
                len: body.len,
            };
            region.extend_from_slice(&bytes);
        }
        answers.push(answer);
    }
    if budget.completed_requests() == before {
        return Err(AuditFailure::InvalidInput);
    }
    Ok((answers, region))
}
