//! Typed provenance for the embedded polish vocabularies.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    pub title: String,
    pub publisher: String,
    pub license: String,
    pub retrieved: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cite {
    pub source: String,
    pub quote: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listed {
    pub value: String,
    pub cites: Vec<Cite>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PlaceholderShape {
    ReservedAddress,
    Bracketed,
    HereSuffixed,
    CopyrightPlaceholder,
    Filler,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Placeholder {
    pub value: String,
    pub shape: PlaceholderShape,
    pub cites: Vec<Cite>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Formula {
    pub pattern: String,
    pub example: String,
    pub cites: Vec<Cite>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocialPlatform {
    pub domain: String,
    pub names: Vec<String>,
    pub cites: Vec<Cite>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WordLists {
    pub sources: BTreeMap<String, Source>,
    pub marketing_terms: Vec<Listed>,
    pub headline_formulas: Vec<Formula>,
    pub headline_word_slots: BTreeMap<String, Vec<Listed>>,
    pub scaffold_titles: Vec<Listed>,
    pub placeholder_titles: Vec<Listed>,
    pub scaffold_favicons: Vec<Listed>,
    pub scaffold_markers: Vec<Listed>,
    pub scaffold_root_ids: Vec<Listed>,
    pub error_page_markers: Vec<Listed>,
    pub hosting_suffixes: Vec<Listed>,
    pub placeholder_phrases: Vec<Placeholder>,
    pub placeholder_image_hosts: Vec<Listed>,
    pub social_platforms: Vec<SocialPlatform>,
    pub client_template_markers: Vec<Listed>,
}

pub(super) fn lowercase_values(entries: &'static [Listed]) -> Vec<(&'static str, String)> {
    entries
        .iter()
        .map(|entry| (entry.value.as_str(), entry.value.to_lowercase()))
        .collect()
}

static WORD_LISTS: LazyLock<WordLists> = LazyLock::new(|| {
    serde_json::from_str(include_str!("word_lists.json"))
        .expect("embedded polish word lists match their schema")
});

/// Return the embedded vocabularies, parsed once per engine instance.
pub fn word_lists() -> &'static WordLists {
    &WORD_LISTS
}

/// Check list completeness, citation provenance, formulas, and placeholder shapes.
pub fn validate(lists: &WordLists) -> Result<(), String> {
    if lists.sources.is_empty() || lists.headline_word_slots.is_empty() {
        return Err("empty sources or headline word slots".into());
    }
    for (key, source) in &lists.sources {
        validate_source(key, source)?;
    }
    let groups = [
        ("marketing_terms", &lists.marketing_terms),
        ("scaffold_titles", &lists.scaffold_titles),
        ("placeholder_titles", &lists.placeholder_titles),
        ("scaffold_favicons", &lists.scaffold_favicons),
        ("scaffold_markers", &lists.scaffold_markers),
        ("scaffold_root_ids", &lists.scaffold_root_ids),
        ("error_page_markers", &lists.error_page_markers),
        ("hosting_suffixes", &lists.hosting_suffixes),
        ("placeholder_image_hosts", &lists.placeholder_image_hosts),
        ("client_template_markers", &lists.client_template_markers),
    ];
    for (name, entries) in groups {
        unique_values(name, entries.iter().map(|entry| entry.value.as_str()))?;
    }
    for (name, entries) in &lists.headline_word_slots {
        if name.trim().is_empty() {
            return Err("empty headline slot name".into());
        }
        unique_values(name, entries.iter().map(|entry| entry.value.as_str()))?;
    }
    unique_values(
        "headline_formulas",
        lists.headline_formulas.iter().map(|f| f.pattern.as_str()),
    )?;
    unique_values(
        "placeholder_phrases",
        lists.placeholder_phrases.iter().map(|p| p.value.as_str()),
    )?;
    unique_values(
        "social_platforms",
        lists.social_platforms.iter().map(|p| p.domain.as_str()),
    )?;
    for platform in &lists.social_platforms {
        unique_values("platform names", platform.names.iter().map(String::as_str))?;
    }
    if lists
        .headline_formulas
        .iter()
        .any(|formula| formula.example.trim().is_empty())
    {
        return Err("empty formula example".into());
    }

    let mut cited = BTreeSet::new();
    for (_, entries) in groups {
        for entry in entries {
            validate_cites(&entry.value, &entry.cites, &lists.sources, &mut cited)?;
        }
    }
    for entries in lists.headline_word_slots.values() {
        for entry in entries {
            validate_cites(&entry.value, &entry.cites, &lists.sources, &mut cited)?;
        }
    }
    for formula in &lists.headline_formulas {
        validate_cites(&formula.example, &formula.cites, &lists.sources, &mut cited)?;
    }
    for placeholder in &lists.placeholder_phrases {
        validate_cites(
            &placeholder.value,
            &placeholder.cites,
            &lists.sources,
            &mut cited,
        )?;
        if !valid_placeholder(placeholder) {
            return Err("placeholder does not have its recorded shape".into());
        }
    }
    for platform in &lists.social_platforms {
        validate_cites(
            &platform.domain,
            &platform.cites,
            &lists.sources,
            &mut cited,
        )?;
    }

    validate_formulas(lists)?;
    for entry in &lists.hosting_suffixes {
        if !entry.value.strip_prefix('.').is_some_and(bare_host) {
            return Err("hosting suffix must be a bare lowercase host starting with a dot".into());
        }
    }
    for host in lists
        .placeholder_image_hosts
        .iter()
        .map(|entry| entry.value.as_str())
        .chain(
            lists
                .social_platforms
                .iter()
                .map(|platform| platform.domain.as_str()),
        )
    {
        if !bare_host(host) {
            return Err("host must be a bare lowercase name".into());
        }
    }
    for source in lists.sources.keys() {
        if !cited.contains(source.as_str()) {
            return Err(format!("uncited source: {source}"));
        }
    }
    Ok(())
}

fn unique_values<'a>(name: &str, values: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(format!("empty value in {name}"));
        }
        if !seen.insert(value.to_lowercase()) {
            return Err(format!("duplicate entry in {name}"));
        }
    }
    if seen.is_empty() {
        return Err(format!("empty list: {name}"));
    }
    Ok(())
}

fn validate_source(key: &str, source: &Source) -> Result<(), String> {
    if [key, &source.title, &source.publisher, &source.license]
        .iter()
        .any(|s| s.trim().is_empty())
    {
        return Err("source metadata must not be empty".into());
    }
    if !source.url.starts_with("https://")
        || !url::Url::parse(&source.url).is_ok_and(|url| url.host_str().is_some())
    {
        return Err("source address must be an HTTPS URL".into());
    }
    if !chrono::NaiveDate::parse_from_str(&source.retrieved, "%Y-%m-%d")
        .is_ok_and(|date| date.format("%Y-%m-%d").to_string() == source.retrieved)
    {
        return Err("source retrieval date must be a calendar date in YYYY-MM-DD form".into());
    }
    Ok(())
}

fn validate_cites<'a>(
    value: &str,
    cites: &'a [Cite],
    sources: &BTreeMap<String, Source>,
    cited: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    if cites.is_empty() {
        return Err("entry needs at least one citation".into());
    }
    let value = value.to_lowercase();
    for cite in cites {
        if !sources.contains_key(&cite.source) {
            return Err(format!("citation names an unknown source: {}", cite.source));
        }
        if cite.quote.trim().is_empty() || cite.quote.chars().count() > 200 {
            return Err("quote must contain 1 to 200 characters".into());
        }
        if cite.quote.contains(['\u{2014}', '\u{2013}']) {
            return Err("quote contains a forbidden dash".into());
        }
        if !decode_quote_entities(&cite.quote)
            .to_lowercase()
            .contains(&value)
        {
            return Err("quote does not show its entry".into());
        }
        cited.insert(cite.source.as_str());
    }
    Ok(())
}

static QUOTE_ENTITY_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)&(?:#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]+);")
        .expect("static quote entity regex")
});

/// Decode quote entities once for comparison while preserving the recorded excerpt.
pub fn decode_quote_entities(quote: &str) -> std::borrow::Cow<'_, str> {
    QUOTE_ENTITY_RE.replace_all(quote, |capture: &regex::Captures<'_>| match &capture[0] {
        "&copy;" | "&COPY;" => "©".to_string(),
        "&lt;" | "&LT;" => "<".to_string(),
        "&gt;" | "&GT;" => ">".to_string(),
        "&nbsp;" => "\u{00a0}".to_string(),
        entity => crate::checks::html_attrs::decode_url_character_references(entity),
    })
}

static SLOT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\{[A-Za-z_][A-Za-z0-9_]*\}").expect("static headline slot regex")
});

pub(super) fn expanded_slots(lists: &WordLists) -> BTreeMap<String, String> {
    lists
        .headline_word_slots
        .iter()
        .map(|(name, words)| {
            let alternatives = words
                .iter()
                .map(|word| regex::escape(&word.value))
                .collect::<Vec<_>>()
                .join("|");
            (name.clone(), format!("(?:{alternatives})"))
        })
        .collect()
}

pub(super) fn compile_formula(
    formula: &Formula,
    slots: &BTreeMap<String, String>,
) -> Result<regex::Regex, String> {
    if formula.pattern.contains('|') {
        return Err("formula contains a word alternation".into());
    }
    let mut expanded = String::new();
    let mut end = 0;
    for slot in SLOT_RE.find_iter(&formula.pattern) {
        let name = &formula.pattern[slot.start() + 1..slot.end() - 1];
        let words = slots
            .get(name)
            .ok_or_else(|| format!("formula names an unknown slot: {name}"))?;
        expanded.push_str(&formula.pattern[end..slot.start()]);
        expanded.push_str(words);
        end = slot.end();
    }
    expanded.push_str(&formula.pattern[end..]);
    regex::Regex::new(&expanded).map_err(|error| format!("invalid formula: {error}"))
}

fn validate_formulas(lists: &WordLists) -> Result<(), String> {
    let slots = expanded_slots(lists);
    let mut used = BTreeSet::new();
    for formula in &lists.headline_formulas {
        let regex = compile_formula(formula, &slots)?;
        if !regex.is_match(&formula.example) {
            return Err("formula does not match its own example".into());
        }
        for slot in SLOT_RE.find_iter(&formula.pattern) {
            used.insert(&formula.pattern[slot.start() + 1..slot.end() - 1]);
        }
    }
    for name in lists.headline_word_slots.keys() {
        if !used.contains(name.as_str()) {
            return Err(format!("unused slot: {name}"));
        }
    }
    Ok(())
}

fn bare_host(host: &str) -> bool {
    !host.is_empty()
        && host.is_ascii()
        && host == host.to_ascii_lowercase()
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn reserved_address(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let domain = domain.to_ascii_lowercase();
    if local.is_empty()
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&byte))
        || !bare_host(&domain)
    {
        return false;
    }
    // technical vocabulary: https://www.rfc-editor.org/rfc/rfc2606
    [
        "test",
        "example",
        "invalid",
        "localhost",
        "example.com",
        "example.net",
        "example.org",
    ]
    .iter()
    .any(|reserved| {
        domain == *reserved
            || domain
                .strip_suffix(reserved)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn valid_placeholder(placeholder: &Placeholder) -> bool {
    let value = placeholder.value.trim();
    let lower = value.to_lowercase();
    if value.contains('.') && bare_host(&lower) {
        return false;
    }
    match placeholder.shape {
        PlaceholderShape::ReservedAddress => reserved_address(value),
        PlaceholderShape::Bracketed => value
            .strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .or_else(|| value.strip_prefix('{').and_then(|v| v.strip_suffix('}')))
            .is_some_and(|content| content.chars().any(char::is_alphanumeric)),
        PlaceholderShape::HereSuffixed => lower.strip_suffix("here").is_some_and(|prefix| {
            prefix.chars().any(char::is_alphanumeric)
                && prefix
                    .chars()
                    .next_back()
                    .is_none_or(|c| !c.is_alphanumeric() && c != '_')
        }),
        PlaceholderShape::CopyrightPlaceholder => {
            value
                .strip_prefix('©')
                .is_some_and(|tail| tail.chars().any(char::is_alphanumeric))
                || lower.strip_prefix("copyright").is_some_and(|tail| {
                    tail.chars().any(char::is_alphanumeric)
                        && tail
                            .chars()
                            .next()
                            .is_none_or(|c| !c.is_alphanumeric() && c != '_')
                })
        }
        PlaceholderShape::Filler => value.split_whitespace().count() >= 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists() -> WordLists {
        serde_json::from_str(include_str!("word_lists.json")).unwrap()
    }

    fn cites(lists: &WordLists, quote: String) -> Vec<Cite> {
        vec![Cite {
            source: lists.sources.keys().next().unwrap().clone(),
            quote,
        }]
    }

    #[test]
    fn entity_encoded_quotes_support_the_decoded_entry() {
        // Verbatim entity-encoded quotes can fail to support the corresponding visible text.
        let lists = lists();
        for (value, quote) in [
            ("© Your Website", "Copyright &copy; Your Website"),
            ("© Your Website", "Copyright &#169; Your Website"),
            ("© Your Website", "Copyright &#xA9; Your Website"),
            ("Q&A", "Q&amp;A"),
            ("<", "&lt;"),
            (">", "&gt;"),
            ("\"", "&quot;"),
            ("'", "&#39;"),
            ("'", "&apos;"),
            ("\u{00a0}", "&nbsp;"),
        ] {
            assert!(
                validate_cites(
                    value,
                    &cites(&lists, quote.into()),
                    &lists.sources,
                    &mut BTreeSet::new()
                )
                .is_ok(),
                "{quote}"
            );
        }
    }

    #[test]
    fn quotes_without_the_required_symbol_do_not_support_the_entry() {
        // Missing symbols and escaped entity spellings must not become supporting evidence.
        let lists = lists();
        for quote in [
            "Copyright Your Website",
            "Copyright &amp;copy; Your Website",
        ] {
            let error = validate_cites(
                "© Your Website",
                &cites(&lists, quote.into()),
                &lists.sources,
                &mut BTreeSet::new(),
            )
            .unwrap_err();
            assert!(error.contains("show"));
        }
    }

    #[test]
    fn entity_decoding_preserves_the_raw_quote_length_limit() {
        // Short decoded text can hide a raw excerpt longer than the provenance bound.
        let lists = lists();
        assert!(validate_cites(
            "&",
            &cites(&lists, "&amp;".repeat(40)),
            &lists.sources,
            &mut BTreeSet::new()
        )
        .is_ok());
        let error = validate_cites(
            "&",
            &cites(&lists, "&amp;".repeat(41)),
            &lists.sources,
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        assert!(error.contains("1 to 200"));
    }

    #[test]
    fn placeholder_shapes_require_content_beside_their_delimiters() {
        // A shape's own word or delimiters can be mistaken for a complete placeholder.
        for (shape, value) in [
            (PlaceholderShape::HereSuffixed, "here"),
            (PlaceholderShape::CopyrightPlaceholder, "©"),
            (PlaceholderShape::CopyrightPlaceholder, "copyright"),
            (PlaceholderShape::Bracketed, "[]"),
            (PlaceholderShape::Bracketed, "{}"),
        ] {
            assert!(
                !valid_placeholder(&Placeholder {
                    value: value.into(),
                    shape,
                    cites: vec![]
                }),
                "{value}"
            );
        }
    }

    #[test]
    fn embedded_word_lists_parse_once() {
        // A loader that parses on every call rebuilds the lists for each page a scan reads.
        assert!(std::ptr::eq(word_lists(), word_lists()));
    }

    #[test]
    fn quote_limits_count_characters_instead_of_utf8_bytes() {
        // A byte-based quote limit rejects valid excerpts containing non-ASCII characters.
        let mut lists = lists();
        lists.marketing_terms.push(Listed {
            value: "é".into(),
            cites: cites(&lists, "é".repeat(200)),
        });
        assert!(validate(&lists).is_ok());
        lists.marketing_terms.last_mut().unwrap().cites[0]
            .quote
            .push('é');
        assert!(validate(&lists).is_err());
    }

    #[test]
    fn reserved_addresses_accept_subdomains_and_reject_suffix_lookalikes() {
        // A reserved-address check can accept suffix lookalikes or reject reserved subdomains.
        for (address, valid) in [
            ("user@example.com", true),
            ("user@docs.example.org", true),
            ("user@host.test", true),
            ("user@host.invalid", true),
            ("user@host.localhost", true),
            ("user@host.example", true),
            ("user@localhost", true),
            ("user@notexample.com", false),
            ("user@example.com.actual-site.com", false),
            ("user@example.com/path", false),
        ] {
            let mut lists = lists();
            if let Some(entry) = lists
                .placeholder_phrases
                .iter_mut()
                .find(|entry| entry.value == address)
            {
                entry.shape = PlaceholderShape::ReservedAddress;
            } else {
                lists.placeholder_phrases.push(Placeholder {
                    value: address.into(),
                    shape: PlaceholderShape::ReservedAddress,
                    cites: cites(&lists, address.into()),
                });
            }
            assert_eq!(validate(&lists).is_ok(), valid, "{address}");
        }
    }

    #[test]
    fn formula_slots_are_escaped_before_compiling() {
        // Regex metacharacters in sourced slot words can change the meaning of a formula.
        let mut lists = lists();
        let prefix = lists
            .headline_word_slots
            .keys()
            .map(String::as_str)
            .collect::<String>();
        let first = format!("{prefix}literal_one");
        let second = format!("{prefix}literal_two");
        for (name, word) in [(&first, "a+b"), (&second, ".")] {
            let entry = Listed {
                value: word.into(),
                cites: cites(&lists, word.into()),
            };
            lists.headline_word_slots.insert(name.into(), vec![entry]);
        }
        lists.headline_formulas.push(Formula {
            pattern: format!("^{{{first}}}{{{second}}}$"),
            example: "a+b.".into(),
            cites: cites(&lists, "a+b.".into()),
        });
        assert!(validate(&lists).is_ok());
    }
}
