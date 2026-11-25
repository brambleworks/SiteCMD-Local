use std::{env, ffi::OsString};

pub fn cli_binary() -> OsString {
    env::var_os("NEXTEST_BIN_EXE_sitecmd_cli")
        .or_else(|| env::var_os("CARGO_BIN_EXE_sitecmd_cli"))
        .expect("nextest or Cargo must provide the runtime CLI path")
}
