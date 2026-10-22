pub fn start() {
    let _ = std::env::var("LIB_RUNTIME");
}

#[cfg(test)]
#[path = "main.rs"]
mod main_tests;
