pub mod testing;

pub fn run() {
    testing::clock::start();
}

#[cfg(test)]
#[path = "clock.rs"]
mod clock_alias;
