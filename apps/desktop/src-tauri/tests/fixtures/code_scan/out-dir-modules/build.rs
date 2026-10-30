use std::path::Path;

fn main() {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let out = std::env::var_os("OUT_DIR").unwrap();
    let handler = Path::new(&manifest).join("src/handlers/helper.rs");
    let code = format!("#[path = {:?}]\npub mod helper;\n", handler);
    std::fs::write(Path::new(&out).join("handlers.rs"), code).unwrap();
    println!("cargo:rerun-if-changed=src/handlers");
}
