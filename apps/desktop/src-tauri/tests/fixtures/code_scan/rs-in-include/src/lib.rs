include!("parts.rs.in");

pub fn run() {
    helper::start();
}

#[cfg(test)]
#[path = "helper.rs"]
mod helper_alias;
