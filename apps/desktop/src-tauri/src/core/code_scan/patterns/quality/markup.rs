//! Raw-HTML sinks, the sanitization vocabulary that clears them, and the
//! inline-style shapes graded beside them.

use std::sync::LazyLock;

pub(in crate::core::code_scan) static DANGEROUS_HTML_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"dangerouslySetInnerHTML").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"v-html").expect("static pattern regex"), // allow-expect: compile-time literal regex
            // Assignment values are classified per occurrence so computed
            // expressions are reported while complete literals stay quiet.
            regex::Regex::new(r"\binnerHTML\s*=").expect("static pattern regex"), // allow-expect: compile-time literal regex
            // `Markup(` with a word boundary so Drupal's safe wrappers
            // (TranslatableMarkup, FormattableMarkup, PlaceholderMarkup, …)
            // don't trip the check on every plugin metadata line.
            regex::Regex::new(r"\bMarkup\(").expect("static pattern regex"), // allow-expect: compile-time literal regex
            // PHP: a request superglobal reaching output directly - echo,
            // print, the short echo tag, or Blade's raw-output braces.
            // Escaped output also matches, but the sanitization patterns
            // suppress the check for those files.
            regex::Regex::new(
                r"\b(?:echo|print)\b[^;]{0,160}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
            )
            .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"(?:<\?=|\{!!)[^;]{0,160}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)")
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static JSX_INLINE_STYLE_PROP_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| {
        regex::Regex::new(r"style\s*=\s*\{\s*\{")
            .expect("static JSX inline style prop opener regex") // allow-expect: compile-time literal regex
    });

/// A style object carrying at least one literal value; objects made only of
/// identifiers, member expressions, and interpolated templates are runtime
/// styling that belongs inline.
pub(in crate::core::code_scan) static JSX_STATIC_STYLE_VALUE_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| {
        regex::Regex::new(r#":\s*(?:"[^"]*"|'[^']*'|`[^`$]*`|-?\d)"#)
            .expect("static literal style value regex") // allow-expect: compile-time literal regex
    });

/// The documented Next.js JSON-LD form: `dangerouslySetInnerHTML` whose
/// `__html` is `JSON.stringify(...)`, in JSX or `createElement` props.
pub(in crate::core::code_scan) static JSON_LD_SERIALIZED_SINK_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| {
        regex::Regex::new(
            r"dangerouslySetInnerHTML\s*[:=]\s*\{?\s*\{\s*__html\s*:\s*JSON\.stringify\s*\(",
        )
        .expect("static pattern regex") // allow-expect: compile-time literal regex
    });

/// A raw-HTML sink whose `__html` value is written out in the file: a quoted
/// string, a template literal with no `${` interpolation, or `JSON.stringify`
/// of a primitive literal. There is no value flow to grade in any of those, so
/// the sink renders exactly the text beside it. An object or array literal is
/// deliberately not accepted: its members can be arbitrary expressions, so
/// `JSON.stringify({ next: req.query.next })` is still a sink.
///
/// The value must END at the property, hence the trailing `,` or `}`. Without
/// it the pattern would accept the leading literal of a larger expression and
/// read `__html: "<b>" + user.bio` as static.
pub(in crate::core::code_scan) static RAW_HTML_STATIC_VALUE_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| {
        regex::Regex::new(
            r#"(?s)^dangerouslySetInnerHTML\s*[:=]\s*\{?\s*\{\s*__html\s*:\s*(?:"[^"]*"|'[^']*'|`[^`$]*`|JSON\.stringify\s*\(\s*(?:"[^"]*"|'[^']*'|-?\d+(?:\.\d+)?)\s*\))\s*[,}]"#,
        )
        .expect("static raw-HTML literal value regex") // allow-expect: compile-time literal regex
    });

pub(in crate::core::code_scan) static SANITIZATION_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"DOMPurify").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"sanitizeHtml").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bsanitize\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bbleach\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"esc_html").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bescapeHtml\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bescape_html\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            // Drupal-specific sanitization helpers
            regex::Regex::new(r"Html::escape\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"Html::format\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"Xss::filter\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"Xss::filterAdmin\b").expect("static pattern regex"), // allow-expect: compile-time literal regex
            // PHP native escaping and the WordPress esc_*/wp_kses/sanitize_*
            // families (esc_html is already covered above).
            regex::Regex::new(r"\bhtmlspecialchars\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bhtmlentities\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\besc_attr").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\besc_url").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bwp_kses").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bsanitize_[a-z_]+\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            // Project-local "already sanitized" naming. A value called
            // `safeHtml`, `labelAsSafeHtml`, or produced by
            // `markdownToSafeHTML` has crossed a sanitization boundary the
            // scanned file does not contain.
            //
            // Case is deliberate rather than `(?i)`, and it is what excludes
            // the negated names a developer writes at exactly this sink.
            // `unsafeHtml`, `isUnsafeHtml`, and `UnsafeHtml` all keep `safe`
            // lowercase INSIDE the word, so they satisfy neither the
            // standalone form (which needs a non-identifier character in
            // front of it) nor the camelCase suffix (which needs a capital
            // `S`). The standalone form takes either case of that `S` so an
            // imported `SafeHtml` type annotation still counts.
            regex::Regex::new(r"(?:^|[^A-Za-z0-9_$])[Ss]afe_?[Hh][Tt][Mm][Ll]")
                .expect("static standalone safe-html regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"[a-z0-9_$]Safe_?[Hh][Tt][Mm][Ll]")
                .expect("static camelCase safe-html suffix regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"(?i)\bsanitized(?:_?html)?\b")
                .expect("static sanitized-value regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\btoSafe[A-Z]\w*\s*\(").expect("static toSafe helper regex"), // allow-expect: compile-time literal regex
            // QR and chart helpers that build their own SVG markup rather than
            // rendering caller-supplied HTML.
            regex::Regex::new(r"\brenderSVG\s*\(").expect("static renderSVG regex"), // allow-expect: compile-time literal regex
        ]
    });

#[cfg(test)]
mod tests {
    use super::{RAW_HTML_STATIC_VALUE_PATTERN, SANITIZATION_PATTERNS};

    fn any_match(patterns: &[regex::Regex], source: &str) -> bool {
        patterns.iter().any(|pattern| pattern.is_match(source))
    }

    #[test]
    fn safe_by_name_values_count_as_sanitization() {
        assert!(any_match(
            &SANITIZATION_PATTERNS,
            "markdownToSafeHTML(source.content)"
        ));
        assert!(any_match(&SANITIZATION_PATTERNS, "field.labelAsSafeHtml"));
        assert!(any_match(
            &SANITIZATION_PATTERNS,
            "const html = sanitizedHtml"
        ));
        assert!(any_match(&SANITIZATION_PATTERNS, "renderSVG(uri)"));
        assert!(any_match(&SANITIZATION_PATTERNS, "toSafeMarkdown(value)"));
        assert!(any_match(
            &SANITIZATION_PATTERNS,
            "const safeHtml = clean(raw)"
        ));
        assert!(any_match(
            &SANITIZATION_PATTERNS,
            "import type { SafeHtml } from \"./types\";"
        ));
        // An unqualified value is still unsanitized.
        assert!(!any_match(&SANITIZATION_PATTERNS, "user.bio"));
        // The negated names a developer writes at exactly this sink must not
        // read as sanitization; that would suppress the finding they describe.
        assert!(!any_match(&SANITIZATION_PATTERNS, "const unsafeHtml = raw"));
        assert!(!any_match(&SANITIZATION_PATTERNS, "isUnsafeHtml(value)"));
        assert!(!any_match(
            &SANITIZATION_PATTERNS,
            "import type { UnsafeHtml } from \"./types\";"
        ));
    }

    #[test]
    fn a_literal_raw_html_value_is_recognised_and_an_interpolated_one_is_not() {
        assert!(RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: `* { animation: none }` }}"));
        assert!(RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: \"<b>hi</b>\" }}"));
        assert!(!RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: user.bio }}"));
        assert!(!RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: `${JSON.stringify(rules)}` }}"));
        // An object literal can carry arbitrary expressions, so it is not static.
        assert!(!RAW_HTML_STATIC_VALUE_PATTERN.is_match(
            "dangerouslySetInnerHTML={{ __html: JSON.stringify({ next: req.query.next }) }}"
        ));
        // A literal that only OPENS the expression is not the whole value: the
        // pattern must reach the end of the property, or concatenation reads
        // as static and clears a real sink.
        assert!(!RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: \"<b>\" + user.bio }}"));
        assert!(!RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: \"\" + user.bio }}"));
        assert!(!RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: `<b>` + user.bio }}"));
        // A trailing comma closes the property just as a brace does.
        assert!(RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{\n  __html: `a {}`,\n}}"));
        assert!(RAW_HTML_STATIC_VALUE_PATTERN
            .is_match("dangerouslySetInnerHTML={{ __html: JSON.stringify(\"ok\") }}"));
    }
}
