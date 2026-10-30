macro_rules! declare_helper {
    () => {
        mod helper;
    };
}

declare_helper!();
pub mod util;

#[cfg(test)]
#[path = "util/helper.rs"]
mod util_helper_tests;

pub fn a() {
    helper::run();
    util::b();
}
