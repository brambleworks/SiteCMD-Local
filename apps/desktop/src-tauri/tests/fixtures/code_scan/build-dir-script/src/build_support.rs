pub fn lib_dir() -> Option<String> {
    std::env::var("BUILD_DIR_RUNTIME").ok()
}
