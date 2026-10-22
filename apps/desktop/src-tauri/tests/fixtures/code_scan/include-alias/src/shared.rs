pub fn shared_value() -> Option<String> {
    std::env::var("INCLUDE_RUNTIME").ok()
}
