#[cfg_attr(unix, path = "unix.rs")]
mod platform;

#[cfg(test)]
#[path = "unix.rs"]
mod unix_tests;

pub fn start() {
    platform::run();
}
