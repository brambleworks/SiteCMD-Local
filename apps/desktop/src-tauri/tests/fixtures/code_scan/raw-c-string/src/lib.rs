pub const INSTALL_DIR: &core::ffi::CStr = cr"C:\Program Files\Probe\";
mod helper;
pub const QUOTE: char = '"';

pub fn run() {
    helper::start();
}

#[cfg(test)]
#[path = "helper.rs"]
mod helper_alias;
