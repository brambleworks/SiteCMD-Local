//! Synthetic engine ABI responses for host and CLI tests.

#![deny(unsafe_op_in_unsafe_fn)]

mod audit;

use std::cell::RefCell;

use sitecmd_protocol::code_domain::CodeScanDomain;
use sitecmd_protocol::engine_abi::{
    guest::{alloc, answer, error, raw_answer, request, take},
    AnalyzeFilesRequest, Brief, CodeRuleInfo, Done, EngineInfo, ErrorCode, FixPlan, FixTextTarget,
    FixUnavailable, FixerInfo, LocalSiteAnswer, LocalSiteRequest, Patch, RelPath, SessionBegin,
    SessionContinue, Step, Task, Want, WantAnswer, ENGINE_ABI_VERSION,
};
use sitecmd_protocol::score::{CategoryScore, ScoreBreakdown, ScoreSnapshot};
use sitecmd_protocol::vocab::{Category, CheckResult, CheckStatus, Severity};

const RULE: &str = "standin.rule";
const CHECK_ID: &str = "code_scan.standin.rule";
const RULE_CATEGORY: Category = Category::Reliability;
const TITLE: &str = "Sample finding";
const QUOTE: &str = "quote.txt";
const PATCH_FILE: &str = "vercel.json";
const REPLACEMENT: &str = "{\"example\":true}\n";
const FIX_TEXT: &str = "Synthetic module guidance";

enum Session {
    Audit(audit::PendingAudit),
    Quote,
    Patch(RelPath),
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

#[no_mangle]
pub extern "C" fn engine_alloc(len: u32) -> *mut u8 {
    alloc(len)
}

/// # Safety
///
/// The pointer and length must identify a live guest buffer.
#[no_mangle]
pub unsafe extern "C" fn engine_free(ptr: *mut u8, len: u32) {
    // SAFETY: The caller owns the buffer and supplies its original length.
    drop(unsafe { take(ptr, len) });
}

#[no_mangle]
pub extern "C" fn engine_info() -> *const u8 {
    answer(&EngineInfo {
        module_version: "standin".into(),
        abi_version: ENGINE_ABI_VERSION,
        manifest_digest: "0000000000000000".try_into().unwrap(),
        code_rules: vec![CodeRuleInfo {
            id: RULE.into(),
            title: TITLE.into(),
            domain: CodeScanDomain::Operations,
            default_severity: Some(Severity::Low),
            check_id: CHECK_ID.into(),
            category: RULE_CATEGORY,
            rationale: None,
        }],
        local_checks: vec![RULE.try_into().unwrap()],
    })
}

/// # Safety
///
/// The pointer and length must identify an unused request buffer.
#[no_mangle]
pub unsafe extern "C" fn session_begin(ptr: *mut u8, len: u32) -> *const u8 {
    // SAFETY: The caller transfers the original request buffer.
    let frame = unsafe { take(ptr, len) };
    SESSION.take();
    let (input, _) = match request::<SessionBegin>(&frame) {
        Ok(input) => input,
        Err(code) => return error(code),
    };
    match input.task {
        Task::Audit {} => {
            let pending = audit::PendingAudit::new(input);
            if pending.has("want-parent.txt") {
                return raw_answer(br#"{"wants":[{"kind":"file","path":"../x"}]}"#);
            }
            for name in ["spin.txt", "grow.txt", "trap.txt"] {
                if pending.has(name) {
                    run_script(name);
                }
            }
            let wants = pending.wants();
            if wants.is_empty() {
                return finish(pending.finish(vec![], &[]));
            }
            SESSION.replace(Some(Session::Audit(pending)));
            answer(&Step::Wants { wants })
        }
        Task::FixCatalog {} => done(Done::FixCatalog(vec![FixerInfo {
            check_id: RULE.into(),
            title: TITLE.into(),
            write_set: vec![RelPath::parse(PATCH_FILE).unwrap()],
        }])),
        Task::FixPlan { target } => {
            if target.check_id != RULE {
                return done(Done::FixUnavailable(FixUnavailable::NoTemplate));
            }
            let path = RelPath::parse(PATCH_FILE).unwrap();
            if !input.listing.is_file(&path) {
                return done(Done::FixUnavailable(FixUnavailable::NoHost));
            }
            SESSION.replace(Some(Session::Patch(path.clone())));
            answer(&Step::Wants {
                wants: vec![Want::File { path }],
            })
        }
        Task::FixText { targets } => done(Done::FixText(
            targets
                .into_iter()
                .map(|target| match target {
                    FixTextTarget::Web { issue, .. } if issue.check_id == RULE => {
                        format!("{FIX_TEXT} for {TITLE}")
                    }
                    FixTextTarget::Code { issue, .. } if issue.check_id == CHECK_ID => {
                        FIX_TEXT.into()
                    }
                    _ => String::new(),
                })
                .collect(),
        )),
        Task::Brief { target } => {
            let path = RelPath::parse(QUOTE).unwrap();
            if input.listing.is_file(&path) {
                SESSION.replace(Some(Session::Quote));
                return answer(&Step::Wants {
                    wants: vec![Want::File { path }],
                });
            }
            if target.check_id == CHECK_ID {
                let locations: Vec<_> = target
                    .locations
                    .iter()
                    .map(|location| format!("`{}:{}`", location.path, location.line))
                    .collect();
                return done(Done::Brief(Brief {
                    title: format!("SiteCMD: {TITLE}"),
                    body: format!(
                        "@{} Please address the finding.\n\n## Where to look\n{}\n\nOpen a pull request.",
                        target.agent,
                        locations.join("\n")
                    ),
                }));
            }
            done(brief(String::new()))
        }
    }
}

/// # Safety
///
/// The pointer and length must identify an unused request buffer.
#[no_mangle]
pub unsafe extern "C" fn session_continue(ptr: *mut u8, len: u32) -> *const u8 {
    // SAFETY: The caller transfers the original request buffer.
    let frame = unsafe { take(ptr, len) };
    let pending = SESSION.take();
    let result = request::<SessionContinue>(&frame).and_then(|(input, region)| match pending {
        Some(Session::Audit(pending)) => pending.finish(input.answers, region),
        Some(Session::Quote) => match input.answers.as_slice() {
            [WantAnswer::File { body }] => {
                let bytes = body
                    .slice(region)
                    .map_err(|_| ErrorCode::InvalidBodyReference)?;
                let text = std::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
                Ok(brief(text.lines().next().unwrap_or_default().into()))
            }
            _ => Err(ErrorCode::InvalidRequest),
        },
        Some(Session::Patch(path)) => match input.answers.as_slice() {
            [WantAnswer::File { body }] => {
                let bytes = body
                    .slice(region)
                    .map_err(|_| ErrorCode::InvalidBodyReference)?;
                if bytes == REPLACEMENT.as_bytes() {
                    return Ok(Done::FixUnavailable(FixUnavailable::AlreadySatisfied {
                        path,
                    }));
                }
                Ok(Done::FixPlan(FixPlan {
                    patches: vec![Patch {
                        path,
                        base_sha256: Patch::hash_base(bytes),
                        content: REPLACEMENT.into(),
                    }],
                }))
            }
            _ => Err(ErrorCode::InvalidRequest),
        },
        None => Err(ErrorCode::InvalidRequest),
    });
    finish(result)
}

/// # Safety
///
/// The pointer and length must identify an unused request buffer.
#[no_mangle]
pub unsafe extern "C" fn engine_analyze_files(ptr: *mut u8, len: u32) -> *const u8 {
    // SAFETY: The caller transfers the original request buffer.
    let frame = unsafe { take(ptr, len) };
    match request::<AnalyzeFilesRequest>(&frame)
        .and_then(|(input, region)| audit::analyze(input, region))
    {
        Ok(results) => answer(&results),
        Err(code) => error(code),
    }
}

/// # Safety
///
/// The pointer and length must identify an unused request buffer.
#[no_mangle]
pub unsafe extern "C" fn local_site_evaluate(ptr: *mut u8, len: u32) -> *const u8 {
    // SAFETY: The caller transfers the original request buffer.
    let frame = unsafe { take(ptr, len) };
    let (input, region) = match request::<LocalSiteRequest>(&frame) {
        Ok(input) => input,
        Err(code) => return error(code),
    };
    if input.body.slice(region).is_err() {
        return error(ErrorCode::InvalidBodyReference);
    }
    if input.final_url.ends_with("/spin.txt") {
        run_script("spin.txt");
    }
    let selected = !input.polish_only
        && input
            .categories
            .as_ref()
            .is_none_or(|categories| categories.contains(&RULE_CATEGORY));
    answer(&LocalSiteAnswer {
        fix_points: selected.then_some(0).into_iter().collect(),
        results: selected
            .then(|| CheckResult {
                covered: false,
                check_id: RULE.into(),
                category: Some(RULE_CATEGORY),
                title: TITLE.into(),
                description: String::new(),
                status: CheckStatus::Fail,
                skip_reason: None,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: Default::default(),
                confidence_reason: None,
                why_it_matters: None,
            })
            .into_iter()
            .collect(),
        score: ScoreSnapshot {
            overall: if selected { 100.0 } else { 0.0 },
            per_category: selected
                .then(|| (RULE_CATEGORY.key().into(), 100.0))
                .into_iter()
                .collect(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: usize::from(selected),
            exploitable_capped: false,
            breakdown: ScoreBreakdown {
                base: 100.0,
                ..Default::default()
            },
            computed_at: input.now_ms,
        },
        categories: Some(
            selected
                .then_some(CategoryScore {
                    category: RULE_CATEGORY,
                    score: 100,
                    issues_total: 1,
                    issues_critical: 0,
                    issues_high: 0,
                    issues_medium: 0,
                    issues_low: 1,
                    issues_passed: 0,
                })
                .into_iter()
                .collect(),
        ),
    })
}

fn finish(result: Result<Done, ErrorCode>) -> *const u8 {
    match result {
        Ok(value) => done(value),
        Err(code) => error(code),
    }
}

fn done(done: Done) -> *const u8 {
    answer(&Step::Done { done })
}

fn brief(body: String) -> Done {
    Done::Brief(Brief {
        title: String::new(),
        body,
    })
}

fn run_script(name: &str) {
    match name {
        "spin.txt" => loop {
            std::hint::black_box(());
        },
        #[cfg(target_arch = "wasm32")]
        "grow.txt" => {
            // A 1 GiB growth must fail once the guest's initial pages are counted.
            if std::arch::wasm32::memory_grow::<0>(16_384) == usize::MAX {
                std::arch::wasm32::unreachable();
            }
        }
        "trap.txt" => panic!("fixture trap"),
        _ => {}
    }
}
