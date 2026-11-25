//! Host adapter for fix text and template requests.

use sitecmd_engine_host::wants::{self, ReadBudget};
use sitecmd_engine_host::Interrupt;
use sitecmd_protocol::engine_abi::{
    Done, FixTextTarget, RelPath, SessionBegin, Step, Task, Want, WantAnswer, AUDIT_MAX_FILE_BYTES,
};

use super::engine_io::ProjectIo;
use super::project_listing::ProjectListing;

pub(crate) fn request(task: Task, project: Option<&ProjectListing>) -> Result<Done, String> {
    request_with_file(task, project, |_, _| {})
}

pub(crate) fn request_with_file(
    task: Task,
    project: Option<&ProjectListing>,
    mut handed_file: impl FnMut(&RelPath, &[u8]),
) -> Result<Done, String> {
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    let mut session = engine
        .session(&Interrupt::new())
        .map_err(|error| error.to_string())?;
    let request = SessionBegin {
        task,
        listing: project.map_or_else(Default::default, |project| project.wire().clone()),
        options: Default::default(),
        now_ms: 0,
        text_budget: AUDIT_MAX_FILE_BYTES,
        host: Default::default(),
    };
    let mut step = session.begin(&request).map_err(|error| error.to_string())?;
    if let Step::Wants { wants } = &step {
        let (Some(project), [want @ Want::File { path }]) = (project, wants.as_slice()) else {
            return Err("The engine requested unexpected inputs for a fix.".into());
        };
        let mut budget = ReadBudget::new(AUDIT_MAX_FILE_BYTES, AUDIT_MAX_FILE_BYTES);
        let (answer, bytes) =
            wants::answer(&request, &mut budget, &ProjectIo::new(project), want).into_parts();
        if matches!(answer, WantAnswer::File { .. }) {
            handed_file(path, &bytes);
        }
        step = session
            .resume(vec![answer], &bytes)
            .map_err(|error| error.to_string())?;
    }
    match step {
        Step::Done { done } => Ok(done),
        Step::Wants { .. } => Err("The engine requested another file for a fix.".into()),
    }
}

pub(crate) fn fix_text(targets: Vec<FixTextTarget>) -> Result<Vec<String>, String> {
    const BATCH_SIZE: usize = 128;
    let mut output = Vec::with_capacity(targets.len());
    let mut remaining = targets.into_iter();
    loop {
        let targets: Vec<_> = remaining.by_ref().take(BATCH_SIZE).collect();
        let count = targets.len();
        if count == 0 {
            return Ok(output);
        }
        match request(Task::FixText { targets }, None)? {
            Done::FixText(mut texts) if texts.len() == count => output.append(&mut texts),
            _ => return Err("The engine returned invalid fix text.".into()),
        }
    }
}

pub(crate) fn one_fix_text(target: FixTextTarget) -> Result<String, String> {
    fix_text(vec![target]).map(|mut texts| texts.remove(0))
}
