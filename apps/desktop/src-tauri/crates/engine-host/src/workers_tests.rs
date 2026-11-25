use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

use super::*;
use crate::{
    load_tests::{wat_answer, Fixture},
    Engine, Interrupt, ModuleSession,
};
use sitecmd_protocol::engine_abi::{
    FileAnalysisContext, FileAnalysisSource, FileLocation, RelPath, SessionBegin,
};

fn file(path: &str, size: usize) -> AnalysisFile {
    AnalysisFile {
        path: path.into(),
        bytes: vec![b'x'; size],
    }
}

#[test]
fn batches_merge_in_listing_order() {
    // Bug: Balancing batches by bytes can return findings out of listing order.
    let inputs = vec![
        file("z.ts", 1),
        file("a.ts", 8),
        file("m.ts", 7),
        file("b.ts", 2),
    ];
    let batches = batches(inputs, 2);
    let sizes: Vec<_> = batches
        .iter()
        .map(|batch| {
            batch
                .files
                .iter()
                .map(|(_, file)| file.bytes.len())
                .sum::<usize>()
        })
        .collect();
    assert_eq!(sizes, [9, 9]);

    let mut merged = Vec::new();
    for batch in batches.into_iter().rev() {
        merged.extend(
            batch
                .files
                .into_iter()
                .map(|(index, file)| (index, file.path)),
        );
    }
    assert_eq!(in_listing_order(merged), ["z.ts", "a.ts", "m.ts", "b.ts"]);
}

#[test]
fn a_worker_trap_fails_the_audit() {
    // Bug: A worker trap can leave the audit running with incomplete findings.
    const TRAP_BYTE: u8 = b'y';
    let answer = wat_answer(
        br#"[{"path":"a.ts","issues":[],"summary":{
            "pattern_registry":false,"scanner_rule_impl":false,"route_like":false,
            "server_action_like":false,"uses_env":false,"uses_llm":false,"touches_db":false,
            "background_jobs":false,"frontend_supabase":false,"client_auth":false,
            "healthcheck":false,"error_reporting":false,"structured_logging":false,
            "ai_observability":false,"feature_flags":false,"error_boundary":false,
            "job_visibility":false,"job_marker_words":false,"auth_enforcement":false,
            "ai_heavy_marker":false,"shared_data_layer":false,"sensitive_handler":false,
            "write_handler":false,"inline_rust_tests":false}}]"#,
    );
    let engine = Fixture {
        declarations: &format!(r#"(data (i32.const 2048) "{answer}")"#),
        worker: &format!(
            "(if (i32.eq
                (i32.load8_u (i32.sub (i32.add (local.get 0) (local.get 1)) (i32.const 1)))
                (i32.const {TRAP_BYTE}))
                (then unreachable))
            i32.const 2048"
        ),
        ..Fixture::default()
    }
    .load();
    let interrupt = Interrupt::new();
    let mut session = engine.session(&interrupt).unwrap();
    session.set_worker_count(2);
    let files = ["a.ts", "b.ts"].map(|path| FileAnalysisSource {
        path: path.into(),
        location: FileLocation::Listed(RelPath::parse(path).unwrap()),
    });
    let context = FileAnalysisContext::default();
    let good = file("a.ts", 1);
    let bad = AnalysisFile {
        path: "b.ts".into(),
        bytes: vec![TRAP_BYTE],
    };
    let results = session
        .analyze_files(&files[..1], &context, |_| Some(good.bytes.clone()))
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, good.path);

    let trap = EngineError::Trap {
        module_version: "test-version".into(),
    };
    let factory = session.worker_factory().unwrap();
    // Isolate batch failure so the good worker finishes regardless of scheduling.
    assert_eq!(
        analyze_batches(batches(vec![good, bad], 2), &context, &interrupt, |_| {
            factory(&Interrupt::new())
        }),
        Err(trap.clone())
    );
    let error = session
        .analyze_files(&files, &context, |location| {
            Some(vec![if location == &files[0].location {
                b'x'
            } else {
                TRAP_BYTE
            }])
        })
        .unwrap_err();
    assert_eq!(error, trap);
    let request = SessionBegin {
        task: sitecmd_protocol::engine_abi::Task::Audit {},
        listing: Default::default(),
        options: Default::default(),
        now_ms: 0,
        text_budget: 0,
        host: Default::default(),
    };
    assert_eq!(
        session.begin(&request),
        Err(EngineError::malformed("engine session is closed"))
    );
    assert!(!interrupt.is_triggered());
}

#[test]
fn interrupt_stops_every_worker() {
    // Bug: Epoch interruption can stop the session while worker stores keep running.
    let engine = looping_worker_engine();
    let interrupt = Interrupt::new();
    let session = engine.session(&interrupt).unwrap();
    assert_all_workers_stop(session, &interrupt, || interrupt.trigger());
}

#[test]
fn desktop_cancellation_stops_every_worker() {
    // Bug: Worker stores can lose the desktop cancellation probe and keep running.
    let engine = looping_worker_engine();
    let interrupt = Interrupt::new();
    let cancelled = Arc::new(AtomicBool::new(false));
    let probe = Arc::clone(&cancelled);
    let session = engine
        .session_with_cancellation(&interrupt, move || probe.load(Ordering::Relaxed))
        .unwrap();
    assert_all_workers_stop(session, &interrupt, || {
        cancelled.store(true, Ordering::Relaxed)
    });
    assert!(!interrupt.is_triggered());
}

fn looping_worker_engine() -> Engine {
    Fixture {
        declarations: r#"(global (export "in_loop") (mut i32) (i32.const 0))"#,
        worker: "i32.const 1 global.set 0 (loop br 0) unreachable",
        ..Fixture::default()
    }
    .load()
}

fn assert_all_workers_stop(session: ModuleSession, interrupt: &Interrupt, cancel: impl FnOnce()) {
    let timeout = Duration::from_secs(5);
    let (entered, wait_for_entry) = mpsc::channel();
    let (finished, wait_for_result) = mpsc::channel();
    let factory = session.worker_factory().unwrap();
    let worker_interrupt = interrupt.clone();
    std::thread::spawn(move || {
        let result = analyze_batches(
            batches(vec![file("a.ts", 3), file("b.ts", 2)], 2),
            &FileAnalysisContext::default(),
            &worker_interrupt,
            |_| {
                // Require each worker to observe cancellation independently.
                let mut guest = factory(&Interrupt::new())?;
                guest.observe_loop_entry(entered.clone());
                Ok(guest)
            },
        );
        let _ = finished.send(result);
    });
    let ready = (0..2).try_for_each(|_| wait_for_entry.recv_timeout(timeout));
    let start = Instant::now();
    cancel();
    ready.expect("both workers must enter the guest loop");
    assert_eq!(
        wait_for_result
            .recv_timeout(timeout)
            .expect("workers did not stop"),
        Err(EngineError::Interrupted)
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn configured_worker_count_is_clamped_and_validated() {
    // Bug: A malformed override can be ignored or an oversized override can spawn too many stores.
    assert_eq!(parse_worker_count(None, 0).unwrap(), 1);
    assert_eq!(parse_worker_count(None, 4).unwrap(), 4);
    assert_eq!(parse_worker_count(None, 24).unwrap(), 8);
    assert_eq!(parse_worker_count(Some("0".as_ref()), 4).unwrap(), 1);
    assert_eq!(parse_worker_count(Some("2".as_ref()), 4).unwrap(), 2);
    assert_eq!(parse_worker_count(Some("99".as_ref()), 4).unwrap(), 8);
    for invalid in ["", "-1", "2.5", "eight", " 2", "18446744073709551616"] {
        assert_eq!(
            parse_worker_count(Some(invalid.as_ref()), 4),
            Err(EngineError::InvalidWorkerCount)
        );
    }
}
