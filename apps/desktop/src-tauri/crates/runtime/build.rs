#[path = "../../build_config.rs"]
mod build_config;

fn main() {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    build_config::configure_runtime(manifest.parent().unwrap().parent().unwrap());
}
