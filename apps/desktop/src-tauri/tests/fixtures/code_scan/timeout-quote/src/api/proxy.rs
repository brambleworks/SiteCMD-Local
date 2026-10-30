pub async fn proxy(url: &str) -> String {
    let body = fetch(url).await;
    body
}

pub fn is_quote(c: char) -> bool {
    c == '"'
}

#[cfg(test)]
mod tests {
    struct Config {
        timeout: u64,
    }

    #[test]
    fn config() {
        let _ = Config { timeout: 30 };
        assert!(!super::is_quote('q'));
    }
}
