use std::{env, ffi::OsStr, thread};

use sitecmd_protocol::engine_abi::{
    AnalyzeFilesRequest, BodyRef, FileAnalysisContext, FileAnalysisInput, FileAnalysisResult,
};

use crate::session::Guest;
use crate::{EngineError, Interrupt};

const MAX_WORKERS: usize = 8;

pub(crate) fn worker_count() -> Result<usize, EngineError> {
    let override_count = env::var_os("SITECMD_ENGINE_WORKERS");
    parse_worker_count(
        override_count.as_deref(),
        thread::available_parallelism().map_or(1, usize::from),
    )
}

fn parse_worker_count(value: Option<&OsStr>, available: usize) -> Result<usize, EngineError> {
    let Some(value) = value else {
        return Ok(available.clamp(1, MAX_WORKERS));
    };
    value
        .to_str()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
        .map(|count| count.clamp(1, MAX_WORKERS as u64) as usize)
        .ok_or(EngineError::InvalidWorkerCount)
}

pub(crate) struct AnalysisFile {
    pub(crate) path: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct Batch {
    files: Vec<(usize, AnalysisFile)>,
    bytes: usize,
}

pub(crate) fn batches(files: Vec<AnalysisFile>, workers: usize) -> Vec<Batch> {
    let count = workers.min(files.len());
    let mut result: Vec<_> = (0..count).map(|_| Batch::default()).collect();
    let mut indexed: Vec<_> = files.into_iter().enumerate().collect();
    indexed.sort_unstable_by_key(|(index, file)| (std::cmp::Reverse(file.bytes.len()), *index));
    for (index, file) in indexed {
        let batch = result
            .iter_mut()
            .min_by_key(|batch| (batch.bytes, batch.files.len()))
            .expect("a nonempty file list has a batch");
        batch.bytes += file.bytes.len();
        batch.files.push((index, file));
    }
    result
}

impl Batch {
    fn run(
        self,
        context: &FileAnalysisContext,
        mut guest: Guest,
    ) -> Result<Vec<(usize, FileAnalysisResult)>, EngineError> {
        let mut region = Vec::with_capacity(self.bytes);
        let mut files = Vec::with_capacity(self.files.len());
        let mut indices = Vec::with_capacity(self.files.len());
        for (index, file) in self.files {
            let body = BodyRef {
                at: u32::try_from(region.len())
                    .map_err(|_| EngineError::malformed("invalid file analysis offset"))?,
                len: u32::try_from(file.bytes.len())
                    .map_err(|_| EngineError::malformed("invalid file analysis length"))?,
            };
            region.extend_from_slice(&file.bytes);
            files.push(FileAnalysisInput {
                path: file.path,
                body,
            });
            indices.push(index);
        }
        let request = AnalyzeFilesRequest {
            files,
            context: context.clone(),
        };
        let results: Vec<FileAnalysisResult> =
            guest.request("engine_analyze_files", &request, &region)?;
        if results.len() != request.files.len()
            || results
                .iter()
                .zip(&request.files)
                .any(|(result, input)| result.path != input.path)
        {
            return Err(EngineError::malformed("invalid file analysis answer order"));
        }
        Ok(indices.into_iter().zip(results).collect())
    }
}

fn in_listing_order<T>(mut indexed: Vec<(usize, T)>) -> Vec<T> {
    indexed.sort_unstable_by_key(|(index, _)| *index);
    indexed.into_iter().map(|(_, value)| value).collect()
}

pub(crate) fn analyze_batches(
    batches: Vec<Batch>,
    context: &FileAnalysisContext,
    interrupt: &Interrupt,
    factory: impl Fn(&Interrupt) -> Result<Guest, EngineError> + Sync,
) -> Result<Vec<FileAnalysisResult>, EngineError> {
    let abort = Interrupt::new();
    thread::scope(|scope| {
        let mut jobs = Vec::with_capacity(batches.len());
        let mut failure = None;
        for batch in batches {
            let factory = &factory;
            let abort = &abort;
            match thread::Builder::new().spawn_scoped(scope, move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let guest = factory(abort)?;
                    batch.run(context, guest)
                }))
                .unwrap_or_else(|_| Err(EngineError::malformed("file analysis worker panicked")));
                if result.is_err() {
                    abort.trigger();
                }
                result
            }) {
                Ok(job) => jobs.push(job),
                Err(_) => {
                    failure = Some(EngineError::malformed(
                        "could not start file analysis worker",
                    ));
                    abort.trigger();
                    break;
                }
            }
        }
        let mut indexed = Vec::new();
        for job in jobs {
            let result = job
                .join()
                .unwrap_or_else(|_| Err(EngineError::malformed("file analysis worker panicked")));
            match result {
                Ok(results) => indexed.extend(results),
                Err(error) if failure.is_none() || failure == Some(EngineError::Interrupted) => {
                    failure = Some(error);
                }
                Err(_) => {}
            }
        }
        if interrupt.is_triggered() {
            return Err(EngineError::Interrupted);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(in_listing_order(indexed)),
        }
    })
}

#[cfg(test)]
#[path = "workers_tests.rs"]
mod tests;
