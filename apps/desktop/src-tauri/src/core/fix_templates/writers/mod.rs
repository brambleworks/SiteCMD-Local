//! Formatting-preserving writers: a fixer edits a config file without
//! reflowing the lines it did not touch.

pub mod json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub reason: String,
}
