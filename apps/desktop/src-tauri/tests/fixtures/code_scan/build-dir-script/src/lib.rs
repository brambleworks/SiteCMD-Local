pub fn run() {}

#[cfg(test)]
mod build_support;

#[cfg(test)]
mod checks {
    #[test]
    fn lib_dir_is_optional() {
        let _ = super::build_support::lib_dir();
    }
}
