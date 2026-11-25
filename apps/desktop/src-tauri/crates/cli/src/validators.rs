use sitecmd_runtime::core::scan_types::Category;

pub(crate) fn parse_score(value: &str, option: &str) -> Result<u32, String> {
    let score = value
        .parse::<u32>()
        .map_err(|_| format!("Invalid number for {option}: {value}"))?;
    if score > 100 {
        return Err(format!("{option} must be between 0 and 100"));
    }
    Ok(score)
}

pub(crate) fn parse_positive_seconds(value: &str, option: &str) -> Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| format!("Invalid number for {option}: {value}"))?;
    if seconds == 0 {
        return Err(format!("{option} must be greater than zero"));
    }
    Ok(seconds)
}

/// Old spellings keep working for one release; the warning names the replacement.
pub(crate) fn warn_deprecated_flag(old: &str, new: &str) {
    eprintln!("warning: {old} is deprecated; use {new}");
}

pub(crate) fn parse_category(value: &str) -> Result<Category, String> {
    let value = value.trim();
    value.to_ascii_lowercase().parse().map_err(|_| {
        format!(
            "Unknown category: {}. Use: {}",
            if value.is_empty() { "<empty>" } else { value },
            Category::ALL.map(Category::key).join(", ")
        )
    })
}

pub(crate) fn parse_categories(value: &str) -> Result<Vec<Category>, String> {
    let mut categories = Vec::new();
    for raw in value.split(',') {
        let category = parse_category(raw)?;
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    Ok(categories)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_are_bounded_to_the_product_scale() {
        assert_eq!(parse_score("0", "--threshold"), Ok(0));
        assert_eq!(parse_score("100", "--threshold"), Ok(100));
        assert!(parse_score("101", "--threshold").is_err());
        assert!(parse_score("high", "--threshold").is_err());
    }

    #[test]
    fn durations_must_be_positive() {
        assert_eq!(parse_positive_seconds("1", "--timeout"), Ok(1));
        assert!(parse_positive_seconds("0", "--timeout").is_err());
        assert!(parse_positive_seconds("soon", "--timeout").is_err());
    }

    #[test]
    fn categories_are_normalized_deduplicated_and_allowlisted() {
        assert_eq!(
            parse_categories("SEO, security,seo"),
            Ok(vec![Category::Seo, Category::Security])
        );
        assert!(parse_categories("").is_err());
        assert!(parse_categories("security,typo").is_err());
        assert_eq!(
            parse_category(" Typo "),
            Err(format!(
                "Unknown category: Typo. Use: {}",
                Category::ALL.map(Category::key).join(", ")
            ))
        );
    }
}
