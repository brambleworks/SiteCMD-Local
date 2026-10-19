use std::ops::Range;

pub(super) fn quoted_spans(structure: &str) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut open = None;
    for (offset, byte) in structure.bytes().enumerate() {
        if let Some((quote, start)) = open {
            if byte == quote {
                spans.push(start..offset + 1);
                open = None;
            }
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            open = Some((byte, offset));
        }
    }
    spans
}

pub(super) fn matching(structure: &str, open: usize) -> Option<usize> {
    let mut stack = Vec::new();
    let mut quote = None;
    for (offset, byte) in structure.bytes().enumerate().skip(open) {
        if let Some(delimiter) = quote {
            if byte == delimiter {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' => stack.push(b')'),
            b'[' => stack.push(b']'),
            b'{' => stack.push(b'}'),
            b')' | b']' | b'}' => {
                if stack.pop() != Some(byte) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn arguments(structure: &str, after: usize) -> Option<(Vec<Range<usize>>, usize)> {
    let end = matching(structure, after.checked_sub(1)?)?;
    let mut arguments = Vec::new();
    let mut start = after;
    let mut offset = after;
    while offset < end {
        match structure.as_bytes()[offset] {
            b'(' | b'[' | b'{' => offset = matching(structure, offset)?,
            b'\'' | b'"' | b'`' => {
                let quote = structure.as_bytes()[offset];
                offset += 1;
                while offset < end && structure.as_bytes()[offset] != quote {
                    offset += 1;
                }
            }
            b',' => {
                arguments.push(start..offset);
                start = offset + 1;
            }
            _ => {}
        }
        offset += 1;
    }
    if !structure[start..end].trim().is_empty() || arguments.is_empty() {
        arguments.push(start..end);
    }
    Some((arguments, end))
}

pub(super) fn literal(value: &str) -> Option<&str> {
    let value = value.trim();
    let quote = *value.as_bytes().first()?;
    if !matches!(quote, b'\'' | b'"' | b'`')
        || value.len() < 2
        || value.as_bytes().last() != Some(&quote)
    {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    (!inner.contains(['\\', '\'', '"', '`']) && !inner.contains("${")).then_some(inner)
}
