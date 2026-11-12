//! Origin-scoped candidate sweeps, planned together and graded from compact
//! readings, and security.txt, graded from its ordinary probe answers.

use crate::checks::security::{directory_listing, exposed_files, security_txt};
use crate::evaluation::{sweep_reading, unexecuted_probe, ProbeContext};
use crate::page::origin_with_port;
use crate::probe::ProbeRequest;
use crate::vocab::CheckResult;

pub(super) fn sensitive_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    let origin = origin_with_port(&ctx.page.url);
    exposed_files::SENSITIVE_PATHS
        .iter()
        .map(|(path, _, _)| exposed_files::sensitive_path_request(&origin, path))
        .collect()
}

pub(super) fn sensitive_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    let origin = origin_with_port(&ctx.page.url);
    let missing = sweep_reading(&unexecuted_probe());
    let rows = exposed_files::SENSITIVE_PATHS
        .iter()
        .map(|(path, description, severity)| {
            let request = exposed_files::sensitive_path_request(&origin, path);
            exposed_files::grade_path_probe(
                path,
                description,
                severity,
                ctx.readings.sweep(&request).unwrap_or(&missing),
            )
        })
        .collect();
    exposed_files::summarize_exposed_files(
        exposed_files::source_secrets_result(&ctx.page.body),
        rows,
        0,
    )
}

pub(super) fn listing_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    if ctx.page.is_localhost {
        return Vec::new();
    }
    let origin = origin_with_port(&ctx.page.url);
    directory_listing::PROBE_DIRS
        .iter()
        .map(|dir| directory_listing::listing_request(&origin, dir))
        .collect()
}

pub(super) fn listing_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    if ctx.page.is_localhost {
        return vec![directory_listing::localhost_skip_result()];
    }
    let origin = origin_with_port(&ctx.page.url);
    let readings = directory_listing::PROBE_DIRS
        .iter()
        .filter_map(|dir| {
            let request = directory_listing::listing_request(&origin, dir);
            ctx.readings
                .sweep(&request)
                .map(|reading| ((*dir).into(), reading))
        })
        .collect();
    vec![directory_listing::grade_listing_probes(readings)]
}

fn well_known_step(ctx: &ProbeContext) -> security_txt::SecurityTxtStep {
    let origin = origin_with_port(&ctx.page.url);
    let (well_known, _) = security_txt::security_txt_urls(&origin);
    security_txt::evaluate_well_known(
        security_txt::CHECK_ID,
        &origin,
        security_txt::classify_security_txt_probe(
            ctx.outcomes
                .owned(&security_txt::security_txt_request(&well_known)),
        ),
        ctx.page.evaluation_time,
    )
}

pub(super) fn security_txt_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    let origin = origin_with_port(&ctx.page.url);
    let (well_known, legacy) = security_txt::security_txt_urls(&origin);
    let request = security_txt::security_txt_request(&well_known);
    if ctx.outcomes.get(&request).is_none() {
        return vec![request];
    }
    match well_known_step(ctx) {
        security_txt::SecurityTxtStep::Done(_) => Vec::new(),
        security_txt::SecurityTxtStep::ProbeLegacy { .. } => {
            vec![security_txt::security_txt_request(&legacy)]
        }
    }
}

pub(super) fn security_txt_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    match well_known_step(ctx) {
        security_txt::SecurityTxtStep::Done(rows) => rows,
        security_txt::SecurityTxtStep::ProbeLegacy { well_known_status } => {
            let origin = origin_with_port(&ctx.page.url);
            let (_, legacy) = security_txt::security_txt_urls(&origin);
            security_txt::evaluate_legacy(
                security_txt::CHECK_ID,
                &origin,
                well_known_status,
                security_txt::classify_security_txt_probe(
                    ctx.outcomes
                        .owned(&security_txt::security_txt_request(&legacy)),
                ),
                ctx.page.evaluation_time,
            )
        }
    }
}
