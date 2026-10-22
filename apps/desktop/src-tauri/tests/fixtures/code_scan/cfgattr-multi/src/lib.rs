#[cfg_attr(unix, path = "unix.rs", allow(dead_code))]
mod platform;

#[cfg(test)]
#[path = "unix.rs"]
mod unix_tests;

pub fn start() {
    platform::run();
}
