use std::sync::mpsc;

use sitecmd_protocol::engine_abi::{encode_answer, ErrorCode};

use super::*;
use crate::build_support::engine_config;

impl ModuleSession {
    pub(crate) fn set_worker_count(&mut self, count: usize) {
        self.worker_count = count;
    }

    pub(crate) fn observe_loop_entry(&mut self, sender: mpsc::Sender<()>) {
        self.guest.as_mut().unwrap().observe_loop_entry(sender);
    }
}

impl Guest {
    pub(crate) fn observe_loop_entry(&mut self, sender: mpsc::Sender<()>) {
        let guest = self;
        let flag = guest
            .instance
            .get_global(&mut guest.store, "in_loop")
            .unwrap();
        guest.store.data_mut().loop_entry = Some((flag, sender));
    }
}

#[test]
fn a_second_instance_is_refused() {
    // Bug: A guest's store can host more than one instance.
    let runtime = wasmtime::Engine::new(&engine_config(None)).unwrap();
    let compile = |wat| Module::from_binary(&runtime, &wat::parse_str(wat).unwrap()).unwrap();
    let first = compile(r#"(module (memory (export "memory") 1))"#);
    let second = compile("(module)");
    let mut guest =
        Guest::instantiate(&first, &Interrupt::new(), None, Arc::from("test-version")).unwrap();
    let error = Linker::new(&runtime)
        .instantiate(&mut guest.store, &second)
        .unwrap_err();
    assert!(error.to_string().contains("instance count too high at 2"));
}

fn answer_with_json_len(json_len: usize) -> Result<(), EngineError> {
    let mut json = serde_json::to_vec(&ErrorAnswer {
        error: ErrorCode::InvalidRequest,
    })
    .unwrap();
    json.resize(json_len, b' ');
    let frame = encode_answer(&json);
    let pointer = 1;
    let pages = (pointer as usize + frame.len()).div_ceil(64 * 1024);
    let bytes = wat::parse_str(format!(
        r#"(module
            (memory (export "memory") {pages})
            (func (export "engine_free") (param i32 i32))
        )"#
    ))
    .unwrap();
    let runtime = wasmtime::Engine::new(&engine_config(None)).unwrap();
    let module = Module::from_binary(&runtime, &bytes).unwrap();
    let mut guest =
        Guest::instantiate(&module, &Interrupt::new(), None, Arc::from("test-version")).unwrap();
    guest
        .memory
        .write(&mut guest.store, pointer as usize, &frame)
        .unwrap();
    guest.answer(pointer, |_| {
        panic!("an error answer reached the caller's parser")
    })
}

#[test]
fn an_answer_one_byte_over_the_limit_is_refused_before_parsing() {
    // Bug: an answer larger than the limit is parsed and multiplies host memory.
    assert_eq!(
        answer_with_json_len(MODULE_ANSWER_LIMIT + 1),
        Err(EngineError::malformed(
            "answer exceeds the module answer limit"
        ))
    );
}

#[test]
fn an_answer_of_exactly_the_limit_is_read() {
    // Bug: an off-by-one refuses a full-size answer from a large audit.
    assert_eq!(
        answer_with_json_len(MODULE_ANSWER_LIMIT),
        Err(EngineError::Malformed(
            "engine returned InvalidRequest".into()
        ))
    );
}
