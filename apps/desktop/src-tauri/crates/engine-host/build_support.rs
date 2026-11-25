pub(crate) fn engine_config(target: Option<&str>) -> wasmtime::Config {
    let mut config = wasmtime::Config::new();
    // Serialized modules require matching debug-info settings at build and load time.
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
    config.epoch_interruption(true);
    if let Some(target) = target {
        config.target(target).expect("Configure the engine target");
    }
    config
}
