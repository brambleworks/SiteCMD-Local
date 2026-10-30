#[cfg(test)]
#[path = "../support/common.rs"]
mod build_common;

#[cfg(test)]
mod tests {
    #[test]
    fn reads_vendor_dir() {
        let _ = super::build_common::vendor_dir();
    }
}
