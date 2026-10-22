include!(concat!(env!("OUT_DIR"), "/handlers.rs"));

pub fn run() {
    helper::start();
}

#[cfg(test)]
#[path = "handlers/helper.rs"]
mod helper_alias;
