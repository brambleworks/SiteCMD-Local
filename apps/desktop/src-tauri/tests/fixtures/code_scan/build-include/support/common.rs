pub(crate) fn vendor_dir() -> Option<String> {
    std::env::var("VENDOR_DIR_RUNTIME").ok()
}
