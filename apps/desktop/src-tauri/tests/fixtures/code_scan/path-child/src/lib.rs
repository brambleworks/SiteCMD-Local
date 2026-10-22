pub fn start() {
    let _ = std::env::var("RUNTIME_URL");
}

#[cfg(test)]
#[path = "capacity.rs"]
mod measurements;
