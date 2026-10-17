//! Detects technology stacks from HTTP headers and HTML.
//!
//! The detector is the engine's (`sitecmd_engine::stack`), so a hosted scan
//! reports the stack the desktop and the CLI see.

pub use sitecmd_engine::stack::{detect_stack, DetectedStack};
