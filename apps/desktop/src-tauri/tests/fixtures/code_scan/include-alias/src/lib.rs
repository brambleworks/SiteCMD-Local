include!("shared.rs");

#[cfg(test)]
#[path = "shared.rs"]
mod shared_tests;

pub fn entry() -> Option<String> {
    shared_value()
}
