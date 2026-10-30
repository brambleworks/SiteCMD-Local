include!("support/common.rs");

fn main() {
    if let Some(dir) = vendor_dir() {
        println!("cargo:rustc-link-search={dir}");
    }
}
