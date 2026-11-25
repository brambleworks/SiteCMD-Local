use std::{sync::mpsc, thread, time::Duration};

use sha2::{Digest, Sha256};
use sitecmd_protocol::engine_abi::{
    encode_answer, BodyRef, EngineInfo, LocalSiteRequest, SessionBegin, Step, Task,
    ENGINE_ABI_VERSION, EXPORTS,
};

use crate::{load, load_bytes, Engine, EngineError, Interrupt, MODULE_TABLE_ELEMENT_LIMIT};

pub(crate) struct Fixture<'a> {
    pub(crate) abi_version: u32,
    pub(crate) extra_info_field: bool,
    pub(crate) declarations: &'a str,
    pub(crate) worker: &'a str,
    pub(crate) alloc: u32,
    pub(crate) begin: &'a str,
    pub(crate) local: &'a str,
}

impl Default for Fixture<'_> {
    fn default() -> Self {
        Self {
            abi_version: ENGINE_ABI_VERSION,
            extra_info_field: false,
            declarations: "",
            worker: "unreachable",
            alloc: 1024,
            begin: "i32.const 512",
            local: "unreachable",
        }
    }
}

pub(crate) fn wat_answer(json: &[u8]) -> String {
    encode_answer(json)
        .iter()
        .map(|byte| format!(r"\{byte:02x}"))
        .collect::<String>()
}

impl Fixture<'_> {
    pub(crate) fn build(&self) -> Vec<u8> {
        let mut info = serde_json::to_value(EngineInfo {
            abi_version: self.abi_version,
            module_version: "test-version".into(),
            manifest_digest: "0".repeat(16).try_into().unwrap(),
            code_rules: vec![],
            local_checks: vec![],
        })
        .unwrap();
        if self.extra_info_field {
            info["new_field"] = true.into();
        }
        let info = wat_answer(&serde_json::to_vec(&info).unwrap());
        let step = wat_answer(br#"{"wants":[]}"#);
        let Self {
            declarations,
            worker,
            alloc,
            begin,
            local,
            ..
        } = self;
        wat::parse_str(format!(
            r#"(module
                (memory (export "memory") 1)
                {declarations}
                (data (i32.const 16) "{info}")
                (data (i32.const 512) "{step}")
                (data (i32.const 640) "\ff\ff\ff\ff")
                (data (i32.const 648) "\00\00\10\00")
                (func (export "engine_info") (result i32) i32.const 16)
                (func (export "engine_analyze_files") (param i32 i32) (result i32) {worker})
                (func (export "engine_alloc") (param i32) (result i32) i32.const {alloc})
                (func (export "engine_free") (param i32 i32))
                (func (export "session_begin") (param i32 i32) (result i32) {begin})
                (func (export "session_continue") (param i32 i32) (result i32) i32.const 512)
                (func (export "local_site_evaluate") (param i32 i32) (result i32) {local})
            )"#
        ))
        .unwrap()
    }

    pub(crate) fn load(&self) -> Engine {
        load_bytes(&self.build(), None).unwrap()
    }
}

fn engine(begin: &str, local: &str) -> Engine {
    Fixture {
        begin,
        local,
        ..Fixture::default()
    }
    .load()
}

pub(crate) fn audit() -> SessionBegin {
    SessionBegin {
        task: Task::Audit {},
        listing: Default::default(),
        options: Default::default(),
        now_ms: 0,
        text_budget: 0,
        host: Default::default(),
    }
}

#[test]
fn a_module_with_one_import_is_refused() {
    // Bug: A module can gain a capability through an import.
    let bytes = wat::parse_str(
        r#"(module (import "host" "capability" (func)) (func $start unreachable) (start $start))"#,
    )
    .unwrap();
    assert!(matches!(
        load_bytes(&bytes, None),
        Err(EngineError::HasImports(1))
    ));
}

#[test]
fn a_digest_mismatch_is_refused() {
    // Bug: An unreviewed module can reach compilation.
    let bytes = wat::parse_str("(module)").unwrap();
    assert!(matches!(
        load_bytes(&bytes[..3], Some([0; 32])),
        Err(EngineError::DigestMismatch)
    ));
}

#[test]
fn a_matching_digest_is_accepted() {
    // Bug: A module with the expected digest can be refused by the runtime.
    let bytes = Fixture::default().build();
    let engine = load_bytes(&bytes, Some(Sha256::digest(&bytes).into())).unwrap();
    assert_eq!(engine.info().module_version, "test-version");
}

#[test]
fn an_abi_mismatch_is_refused() {
    // Bug: A module with an incompatible wire version can open a session.
    let other = ENGINE_ABI_VERSION + 1;
    let bytes = Fixture {
        abi_version: other,
        ..Fixture::default()
    }
    .build();
    assert!(matches!(
        load_bytes(&bytes, None),
        Err(EngineError::AbiMismatch { module, host }) if module == other && host == ENGINE_ABI_VERSION
    ));
}

#[test]
fn a_new_abi_with_extra_info_fields_reports_its_version() {
    // Bug: An expanded info schema can mask the ABI mismatch.
    let next = ENGINE_ABI_VERSION + 1;
    let bytes = Fixture {
        abi_version: next,
        extra_info_field: true,
        ..Fixture::default()
    }
    .build();
    assert_eq!(
        load_bytes(&bytes, None).unwrap_err(),
        EngineError::AbiMismatch {
            module: next,
            host: ENGINE_ABI_VERSION,
        }
    );
}

#[test]
fn the_current_abi_still_rejects_extra_info_fields() {
    // Bug: Reading the ABI header can accidentally relax the current info schema.
    let bytes = Fixture {
        extra_info_field: true,
        ..Fixture::default()
    }
    .build();
    assert_eq!(
        load_bytes(&bytes, None).unwrap_err(),
        EngineError::Malformed("invalid engine answer".into())
    );
}

#[test]
fn a_trap_reports_the_module_version() {
    // Bug: A module trap loses the version or leaves its instance reusable.
    let engine = engine("unreachable", "unreachable");
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Trap {
            module_version: "test-version".into()
        }
    );
    assert!(matches!(
        session.resume(vec![], &[]),
        Err(EngineError::Malformed(_))
    ));
}

#[test]
fn memory_past_the_limit_fails_the_session() {
    // Bug: Memory growth beyond 1 GiB can continue or return a valid step.
    let engine = engine(
        "i32.const 16384 memory.grow drop i32.const 512",
        "unreachable",
    );
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Trap {
            module_version: "test-version".into()
        }
    );
}

#[test]
fn memory_can_grow_to_16383_pages() {
    // Bug: The memory limit can refuse guest memory growth within the budget.
    let engine = engine(
        "i32.const 16382 memory.grow drop
         memory.size i32.const 16383 i32.ne if unreachable end i32.const 512",
        "unreachable",
    );
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert!(matches!(session.begin(&audit()), Ok(Step::Wants { .. })));
}

#[test]
fn table_growth_past_the_limit_fails_the_session() {
    // Bug: Guest table growth can allocate host memory beyond the table budget.
    let engine = Fixture {
        declarations: "(table 1 funcref)",
        begin: &format!(
            "ref.null func i32.const {MODULE_TABLE_ELEMENT_LIMIT} table.grow 0 drop i32.const 512"
        ),
        ..Fixture::default()
    }
    .load();
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Trap {
            module_version: "test-version".into()
        }
    );
}

#[test]
fn a_second_table_is_refused() {
    // Bug: A module can multiply its table budget by declaring additional tables.
    let bytes = Fixture {
        declarations: "(table 0 funcref) (table 0 funcref)",
        ..Fixture::default()
    }
    .build();
    assert_eq!(
        load_bytes(&bytes, None).unwrap_err(),
        EngineError::Trap {
            module_version: "unknown".into()
        }
    );
}

#[test]
fn interrupt_stops_a_spinning_module_within_a_second() {
    // Bug: Cancellation cannot stop a guest loop or can cancel an unrelated store.
    let engine = Fixture {
        declarations: r#"(global $in_loop (export "in_loop") (mut i32) (i32.const 0))"#,
        begin: "(loop i32.const 1 global.set $in_loop br 0) unreachable",
        ..Fixture::default()
    }
    .load();
    let interrupt = Interrupt::new();
    let mut session = engine.session(&interrupt).unwrap();
    let mut unrelated = engine.session(&Interrupt::new()).unwrap();
    let (started, entered) = mpsc::channel();
    session.observe_loop_entry(started);
    let (finished, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        finished.send(session.begin(&audit())).unwrap();
    });
    let guest_entered = entered.recv_timeout(Duration::from_secs(1));
    let before_interrupt = result.try_recv();
    interrupt.trigger();
    guest_entered.expect("guest reached the loop before interruption");
    assert!(matches!(before_interrupt, Err(mpsc::TryRecvError::Empty)));
    assert_eq!(
        result
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err(),
        EngineError::Interrupted
    );
    worker.join().unwrap();
    assert!(matches!(
        unrelated.resume(vec![], &[]),
        Ok(Step::Wants { .. })
    ));
}

#[test]
fn a_spinning_local_site_evaluation_times_out() {
    // Bug: A looping local page evaluation can exceed its wall-clock deadline.
    let engine = engine("unreachable", "(loop br 0) unreachable");
    assert_local_site_deadline(engine, "http://localhost/".into());
}

#[test]
fn standin_corpus_respects_the_local_site_deadline() {
    // Bug: The host can let a looping stand-in page outlive its deadline.
    let engine = load().unwrap();
    if engine.info().module_version != "standin" {
        return;
    }
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../standin/corpus.json")).unwrap();
    let page = corpus["deadline"].as_str().unwrap();
    assert_local_site_deadline(engine, format!("http://localhost/{page}"));
}

fn assert_local_site_deadline(engine: Engine, url: String) {
    let request = LocalSiteRequest {
        requested_url: url.clone(),
        final_url: url,
        status: 200,
        header_lines: vec![],
        body: BodyRef { at: 0, len: 0 },
        now_ms: 0,
        polish_only: false,
        categories: None,
    };
    let (finished, result) = mpsc::channel();
    thread::spawn(move || {
        finished
            .send(engine.local_site_with_deadline(&request, &[], Duration::from_millis(25)))
            .unwrap();
    });
    assert_eq!(
        result
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err(),
        EngineError::TimedOut
    );
}

#[test]
fn malformed_answer_length_is_refused() {
    // Bug: A length prefix can make the host read beyond guest memory.
    let engine = engine("i32.const 640", "unreachable");
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Malformed("invalid answer length".into())
    );
}

#[test]
fn answer_length_beyond_memory_is_refused() {
    // Bug: A length that fits in u32 can still overrun the memory tail.
    let engine = engine("i32.const 648", "unreachable");
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Malformed("answer exceeds engine memory".into())
    );
}

#[test]
fn an_out_of_range_answer_pointer_is_refused() {
    // Bug: The host can read an answer pointer outside guest memory.
    let engine = engine("i32.const 65537", "unreachable");
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Malformed("invalid answer pointer".into())
    );
}

#[test]
fn an_out_of_range_alloc_pointer_is_refused() {
    // Bug: The host can write a request to an allocation outside guest memory.
    let engine = Fixture {
        alloc: 65537,
        ..Fixture::default()
    }
    .load();
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&audit()).unwrap_err(),
        EngineError::Malformed("engine allocation is outside memory".into())
    );
}

#[test]
fn embedded_module_uses_the_public_abi() {
    // Bug: The embedded engine and the host can disagree on exports or framing.
    let engine = load().unwrap();
    let mut exports = engine.exports();
    exports.sort_unstable();
    let mut expected = EXPORTS.to_vec();
    expected.sort_unstable();
    assert_eq!(exports, expected);
    assert_eq!(engine.info().abi_version, ENGINE_ABI_VERSION);
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert!(matches!(session.begin(&audit()), Ok(Step::Done { .. })));
}
