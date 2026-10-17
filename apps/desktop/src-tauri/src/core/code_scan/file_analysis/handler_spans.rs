//! Locate JavaScript route handler bodies so request reads and sinks pair per handler.

use std::collections::HashMap;
use std::sync::LazyLock;

fn pattern(source: &str) -> regex::Regex {
    regex::Regex::new(source).expect("static handler pattern") // allow-expect: compile-time literal regex
}

/// Express, Hono, Elysia, and Fastify verb registrations with a path argument,
/// matching the route marker's receiver class.
static ROUTER_VERB_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    pattern(
        r#"(?im)(?:^|[;{}(,\s])(?P<start>[A-Za-z0-9_$]*(?:app|router|server|hono|elysia|fastify|route)\s*\.\s*(?:get|post|put|patch|delete|options|head|all|use)\s*\(\s*["'`/])"#,
    )
});
/// Exported HTTP verb handlers plus Remix and React Router actions and loaders.
static EXPORTED_HANDLER: LazyLock<regex::Regex> = LazyLock::new(|| {
    pattern(
        r"(?m)^[\t ]*(?P<start>export\s+(?:async\s+)?(?:function|const|let|var)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|action|loader)\b)",
    )
});

/// Byte ranges of recognized route handlers in comment- and string-blanked source.
pub(super) struct HandlerSpans {
    spans: Vec<(usize, usize)>,
}

impl HandlerSpans {
    pub(super) fn new(structure: &str) -> Self {
        let starts = [&*ROUTER_VERB_CALL, &*EXPORTED_HANDLER]
            .into_iter()
            .flat_map(|handler| handler.captures_iter(structure))
            .filter_map(|found| found.name("start").map(|start| start.start()))
            .collect::<Vec<_>>();
        if starts.is_empty() {
            return Self { spans: Vec::new() };
        }
        let pairs = bracket_pairs(structure);
        let spans = starts
            .into_iter()
            .map(|start| (start, statement_end(structure, start, &pairs)))
            .collect();
        Self { spans }
    }

    /// Whether both offsets sit in route handlers and no one handler holds both.
    /// Code outside every handler, such as a shared helper, pairs with anything.
    pub(super) fn separate(&self, first: usize, second: usize) -> bool {
        let holds = |span: &(usize, usize), at: usize| span.0 <= at && at < span.1;
        self.spans.iter().any(|span| holds(span, first))
            && self.spans.iter().any(|span| holds(span, second))
            && !self
                .spans
                .iter()
                .any(|span| holds(span, first) && holds(span, second))
    }
}

fn bracket_pairs(structure: &str) -> HashMap<usize, usize> {
    let mut open = Vec::new();
    let mut pairs = HashMap::new();
    for (index, byte) in structure.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => open.push(index),
            b')' | b']' | b'}' => {
                if let Some(start) = open.pop() {
                    pairs.insert(start, index);
                }
            }
            _ => {}
        }
    }
    pairs
}

/// End of the statement that starts at `start`: a semicolon or enclosing
/// closer, or a closed group followed by the next statement's identifier.
/// An unbalanced group runs to the end of the file, which only widens a span.
fn statement_end(structure: &str, start: usize, pairs: &HashMap<usize, usize>) -> usize {
    let bytes = structure.as_bytes();
    let mut index = start;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'(' | b'[' | b'{' => {
                let Some(&close) = pairs.get(&index) else {
                    return bytes.len();
                };
                index = close + 1;
                let next = bytes[index..]
                    .iter()
                    .find(|byte| !byte.is_ascii_whitespace());
                if next
                    .is_none_or(|&byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
                {
                    return index;
                }
            }
            b';' | b')' | b']' | b'}' => return index,
            _ => index += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::HandlerSpans;

    fn separate(source: &str, first: &str, second: &str) -> bool {
        let at = |needle: &str| source.find(needle).expect("needle in source");
        HandlerSpans::new(source).separate(at(first), at(second))
    }

    #[test]
    fn separates_sibling_handlers_with_or_without_semicolons() {
        let typed = "export async function GET(request: Request): Promise<Response> {\n  return first(request)\n}\nexport const POST = async (request: Request) => {\n  return second(request)\n}\n";
        assert!(separate(typed, "first", "second"));
        let unterminated = "app.get('/a', (c) => {\n  return first(c)\n})\napp.post('/b', async (c) => second(c))\n";
        assert!(separate(unterminated, "first", "second"));
    }

    #[test]
    fn pairs_code_outside_or_around_a_handler() {
        let helper = "function first(c) { return c }\napp.post('/b', (c) => second(c));\n";
        assert!(!separate(helper, "first", "second"));
        let nested = "router.use('/api', (req, res, next) => {\n  first(req);\n  router.get('/x', (req, res) => second(req));\n});\n";
        assert!(!separate(nested, "first", "second"));
    }
}
