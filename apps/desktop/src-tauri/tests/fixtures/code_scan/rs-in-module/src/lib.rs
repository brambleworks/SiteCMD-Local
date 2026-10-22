#[path = "imp.rs.in"]
mod imp;

pub fn run() {
    imp::run();
}

#[cfg(test)]
#[path = "helper.rs"]
mod helper_alias;
