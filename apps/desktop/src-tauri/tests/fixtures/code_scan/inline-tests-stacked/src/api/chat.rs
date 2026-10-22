pub fn handler() -> &'static str {
    "new OpenAI("
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    #[test]
    fn handler_answers() {
        assert!(!super::handler().is_empty());
    }
}
