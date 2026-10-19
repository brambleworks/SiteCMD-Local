use super::*;

/// React's raw-HTML prop, the only sink the JSON-LD exemption below can excuse.
const REACT_RAW_HTML_SINK: &str = "dangerouslySetInnerHTML";

/// The DOM assignment sink whose complete literals are exempt.
const DOM_RAW_HTML_SINK: &str = "innerHTML";

/// How far the JSON-LD exemption looks around a sink, in bytes.
const JSON_LD_SINK_WINDOW: usize = 200;

/// How far a raw-HTML sink can look for its own value or sanitizer.
const RAW_HTML_SINK_WINDOW: usize = 240;

/// Raw-HTML sink positions that still need review after local exemptions.
pub(in crate::core::code_scan) fn unsafe_html_sink_offsets(content: &str) -> Vec<usize> {
    let mut sinks = DANGEROUS_HTML_PATTERNS
        .iter()
        .flat_map(|pattern| pattern.find_iter(content))
        .filter(|matched| is_executable_sink(content, matched))
        .map(|matched| matched.start())
        .collect::<Vec<_>>();
    sinks.sort_unstable();
    sinks.dedup();

    let all_sinks = sinks.clone();
    sinks.retain(|start| {
        !is_serialized_json_ld_sink_at(content, *start)
            && !is_static_raw_html_sink_at(content, *start)
            && !sink_has_local_sanitization(content, *start, &all_sinks)
    });
    sinks
}

fn is_static_raw_html_sink_at(content: &str, start: usize) -> bool {
    let window = sink_window(content, start, &[]);
    if content[start..].starts_with(REACT_RAW_HTML_SINK) {
        return RAW_HTML_STATIC_VALUE_PATTERN.is_match(window);
    }
    content[start..].starts_with(DOM_RAW_HTML_SINK) && inner_html_value_is_complete_literal(window)
}

fn inner_html_value_is_complete_literal(window: &str) -> bool {
    let Some((_, value)) = window.split_once('=') else {
        return false;
    };
    let value = value.trim_start();
    let Some(quote) = value
        .chars()
        .next()
        .filter(|character| matches!(character, '\'' | '"' | '`'))
    else {
        return false;
    };
    let mut escaped = false;
    let mut interpolated = false;
    let mut previous = None;
    for (offset, character) in value[quote.len_utf8()..].char_indices() {
        if escaped {
            escaped = false;
            previous = Some(character);
            continue;
        }
        if character == '\\' {
            escaped = true;
            previous = Some(character);
            continue;
        }
        if quote == '`' && previous == Some('$') && character == '{' {
            interpolated = true;
        }
        if character == quote {
            let remainder = value[quote.len_utf8() + offset + character.len_utf8()..].trim();
            return !interpolated && (remainder.is_empty() || remainder == ";");
        }
        previous = Some(character);
    }
    false
}

fn sink_has_local_sanitization(content: &str, start: usize, sinks: &[usize]) -> bool {
    let window = sink_window(content, start, sinks);
    has_any(window, &SANITIZATION_PATTERNS)
        || sink_value_identifier(window).is_some_and(|identifier| {
            previous_assignment(content, start, identifier)
                .is_some_and(|assignment| has_any(assignment, &SANITIZATION_PATTERNS))
        })
}

fn sink_value_identifier(window: &str) -> Option<&str> {
    let (_, value) = window.split_once('=')?;
    let value = value.trim_start();
    let end = value
        .find(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '$'
        })
        .unwrap_or(value.len());
    let identifier = &value[..end];
    let remainder = value[end..].trim();
    (!identifier.is_empty() && (remainder.is_empty() || remainder == ";")).then_some(identifier)
}

fn previous_assignment<'a>(content: &'a str, start: usize, identifier: &str) -> Option<&'a str> {
    const ASSIGNMENT_LOOKBACK: usize = 2_000;
    let floor = start.saturating_sub(ASSIGNMENT_LOOKBACK);
    let preceding = &content[floor..start];
    let pattern = regex::Regex::new(&format!(
        r"\b(?:const|let|var)\s+{}\s*=",
        regex::escape(identifier)
    ))
    .ok()?;
    let assignment_start = pattern.find_iter(preceding).last()?.start();
    let assignment = &preceding[assignment_start..];
    let end = assignment.find(';').unwrap_or(assignment.len());
    Some(&assignment[..end])
}

fn sink_window<'a>(content: &'a str, start: usize, sinks: &[usize]) -> &'a str {
    let next_sink = sinks.iter().copied().find(|candidate| *candidate > start);
    let mut end = next_sink
        .unwrap_or(content.len())
        .min(start.saturating_add(RAW_HTML_SINK_WINDOW))
        .min(content.len());
    while !content.is_char_boundary(end) {
        end += 1;
    }
    end = sink_boundary_end(content, start, end).unwrap_or(end);
    &content[start..end]
}

fn sink_boundary_end(content: &str, start: usize, hard_end: usize) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut delimiters = Vec::new();
    let mut previous = None;

    for (offset, character) in content[start..hard_end].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            previous = Some(character);
            continue;
        }

        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '(' | '[' | '{' => delimiters.push(character),
            ')' => close_delimiter(&mut delimiters, '('),
            ']' => close_delimiter(&mut delimiters, '['),
            '}' => close_delimiter(&mut delimiters, '{'),
            ';' if delimiters.is_empty() => return Some(start + offset + character.len_utf8()),
            '>' if delimiters.is_empty() && previous != Some('=') => {
                return Some(start + offset + character.len_utf8());
            }
            _ => {}
        }
        previous = Some(character);
    }
    None
}

fn close_delimiter(delimiters: &mut Vec<char>, expected: char) {
    if delimiters.last() == Some(&expected) {
        delimiters.pop();
    }
}

/// A `<script type="application/ld+json">` element whose
/// `REACT_RAW_HTML_SINK` prop carries `{{ __html: JSON.stringify(...) }}` is the
/// documented Next.js JSON-LD pattern: the sink receives serialized JSON inside
/// a non-executing script type, not markup.
/// True only when every raw-HTML sink in the file is that serialization inside
/// its own `application/ld+json` element. `JSON.stringify` escapes quotes and
/// backslashes but not `<`, so the identical serialization in any other element
/// is still a markup sink and keeps its finding even when a JSON-LD block sits
/// beside it in the same file.
pub(in crate::core::code_scan) fn is_json_ld_serialization_sink(content: &str) -> bool {
    if !content.contains(REACT_RAW_HTML_SINK) {
        return false;
    }
    if has_any_unquoted(
        &content.replace(REACT_RAW_HTML_SINK, ""),
        &DANGEROUS_HTML_PATTERNS,
    ) {
        return false;
    }
    content
        .match_indices(REACT_RAW_HTML_SINK)
        .all(|(start, _)| is_serialized_json_ld_sink_at(content, start))
}

/// Whether the single sink at `start` is a `JSON.stringify` value inside an
/// element that declares `type="application/ld+json"`.
fn is_serialized_json_ld_sink_at(content: &str, start: usize) -> bool {
    let mut end = (start + JSON_LD_SINK_WINDOW).min(content.len());
    while !content.is_char_boundary(end) {
        end += 1;
    }
    JSON_LD_SERIALIZED_SINK_PATTERN.is_match(&content[start..end])
        && enclosing_element_declares_json_ld(content, start)
}

/// Whether the element or `createElement` call that owns the sink at `start`
/// declares the JSON-LD script type. The look-back starts at that element's own
/// opening marker, never crosses an earlier sink, and never crosses an element
/// boundary, so neither a JSON-LD block elsewhere in the file nor a
/// self-closing `<script type="application/ld+json" />` can vouch for a sink in
/// a different element. An element whose opening marker is not found is not
/// excused.
///
/// Two safe shapes stay over-reported on purpose and keep `unsafe-html`: a
/// `type` attribute written after the sink on the same element, and a sink
/// pushed more than `JSON_LD_SINK_WINDOW` bytes past its `<` by other
/// attributes. A tag whose attributes contain `>` (an inline arrow function,
/// say) also stays reported, because that `>` is indistinguishable from the end
/// of the tag here.
fn enclosing_element_declares_json_ld(content: &str, start: usize) -> bool {
    const JSON_LD_TYPE: &str = "application/ld+json";
    let head = &content[..start];
    let Some(opening) = [head.rfind('<'), head.rfind("createElement")]
        .into_iter()
        .flatten()
        .max()
    else {
        return false;
    };
    let floor = head
        .rfind(REACT_RAW_HTML_SINK)
        .map_or(0, |index| index + REACT_RAW_HTML_SINK.len())
        .max(start.saturating_sub(JSON_LD_SINK_WINDOW));
    if opening < floor {
        return false;
    }
    let enclosing = &head[opening..];
    // An element that already closed cannot own this sink.
    if enclosing.starts_with('<') && enclosing.contains('>') {
        return false;
    }
    enclosing.contains(JSON_LD_TYPE)
}
