use std::{env, fs, path::PathBuf};

mod build_input;

include!("build_support.rs");

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.ancestors().nth(5).expect("repository root");
    let unpinned = env::var("SITECMD_ENGINE_UNPINNED").as_deref() == Ok("1");

    println!("cargo:rerun-if-env-changed=SITECMD_ENGINE_WASM");
    println!("cargo:rerun-if-env-changed=SITECMD_ENGINE_UNPINNED");
    let input = build_input::engine_input(root, env::var_os("SITECMD_ENGINE_WASM"), unpinned)
        .unwrap_or_else(|error| panic!("{error}"));
    for path in input.rerun_paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rustc-env=SITECMD_ENGINE_BUILD_SHA256={}",
        input.sha256.as_deref().unwrap_or_default()
    );
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    println!("cargo:rustc-env=SITECMD_ENGINE_BUILD_TARGET={target}");
    let compiler = wasmtime::Engine::new(&engine_config(Some(&target)))
        .expect("Initialize the engine compiler");
    let compiled = compiler
        .precompile_module(&input.bytes)
        .expect("Precompile the embedded engine module");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(out.join("local-engine.wasm"), input.bytes).expect("Write embedded engine module");
    fs::write(out.join("local-engine.cwasm"), compiled).expect("Write compiled engine module");
}
