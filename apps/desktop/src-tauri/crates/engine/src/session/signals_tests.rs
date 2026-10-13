use super::*;

#[test]
fn a_page_with_exactly_the_link_cap_keeps_every_alternate_without_truncation() {
    let alternates: String = (0..MAX_INTERNAL_LINKS_PER_PAGE)
        .map(|index| format!("<link rel=\"alternate\" hreflang=\"x{index}\" href=\"/l{index}\">"))
        .collect();
    let page = url::Url::parse("https://example.com/").expect("static url");
    let signals = extract_page_signals(&page, &format!("<html><head>{alternates}</head></html>"));
    let compared = signals.session_page();
    assert_eq!(compared.hreflang.len(), MAX_INTERNAL_LINKS_PER_PAGE);
    assert!(!compared.hreflang_truncated);
    let expected: Vec<_> = (0..MAX_INTERNAL_LINKS_PER_PAGE)
        .map(|index| format!("https://example.com/l{index}"))
        .collect();
    assert_eq!(compared.hreflang, expected);
}

#[test]
fn a_page_keeps_the_link_cap_of_hreflang_alternates_and_says_so() {
    let alternates: String = (0..=MAX_INTERNAL_LINKS_PER_PAGE)
        .map(|index| format!("<link rel=\"alternate\" hreflang=\"x{index}\" href=\"/l{index}\">"))
        .collect();
    let page = url::Url::parse("https://example.com/").expect("static url");
    let signals = extract_page_signals(&page, &format!("<html><head>{alternates}</head></html>"));
    let compared = signals.session_page();
    assert_eq!(compared.hreflang.len(), MAX_INTERNAL_LINKS_PER_PAGE);
    assert!(compared.hreflang_truncated);
    assert_eq!(compared.hreflang[0], "https://example.com/l0");
}

#[test]
fn a_visitor_written_link_is_not_kept() {
    let page = url::Url::parse("https://example.com/").expect("static url");
    let body = concat!(
        "<html><body><a href=\"/menu\" rel=\"nofollow ugc\">Menu</a>",
        "<a href=\"/hours\">Hours</a></body></html>"
    );
    let signals = extract_page_signals(&page, body);
    assert_eq!(signals.internal_links, ["https://example.com/hours"]);
}
