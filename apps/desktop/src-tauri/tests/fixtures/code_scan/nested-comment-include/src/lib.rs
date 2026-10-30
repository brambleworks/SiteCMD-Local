mod imp {
    #[cfg(test)]
    mod tests {
        /* see /* nested */ { */
    }

    include!("helper.rs");
}

pub fn run() {
    imp::start();
}
