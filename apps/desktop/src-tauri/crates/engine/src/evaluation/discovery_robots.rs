//! RFC 9309 group selection and path matching for route discovery.

use memchr::memmem::Finder;

use super::origin_reads::robots_request;
use super::probes::ProbeContext;
use crate::checks::seo::robots::robots_fetch_from_probe;
use crate::checks::seo::robots_document::records;

// More selected pattern pieces make the policy unknown, so discovery filters no routes.
const ROBOTS_PIECE_LIMIT: usize = 8000;
// More selected rules containing a star make the policy unknown, so no routes are filtered.
const ROBOTS_STAR_RULE_LIMIT: usize = 400;

#[derive(Default)]
pub(super) struct RobotsRules {
    rules: Vec<Rule>,
}

struct Rule {
    pieces: Vec<Finder<'static>>,
    anchored: bool,
    literal_bytes: usize,
    specificity: usize,
    allow: bool,
}

impl Rule {
    fn compile(pattern: String, allow: bool) -> Self {
        #[cfg(test)]
        tests::COMPILED_RULES.set(tests::COMPILED_RULES.get() + 1);
        let anchored = pattern.ends_with('$');
        let specificity = pattern.len();
        let pieces: Vec<Finder<'static>> = pattern
            .strip_suffix('$')
            .unwrap_or(&pattern)
            .split('*')
            .map(|piece| Finder::new(piece.as_bytes()).into_owned())
            .collect();
        let literal_bytes = pieces.iter().map(|piece| piece.needle().len()).sum();
        Self {
            pieces,
            anchored,
            literal_bytes,
            specificity,
            allow,
        }
    }

    fn matches(&self, path: &str) -> bool {
        if self.literal_bytes > path.len() {
            return false;
        }
        let path = path.as_bytes();
        let first = self.pieces[0].needle();
        let Some(mut remaining_path) = path.strip_prefix(first) else {
            return false;
        };
        let mut literal_bytes = self.literal_bytes - first.len();
        for (at, piece) in self.pieces[1..].iter().enumerate() {
            if literal_bytes > remaining_path.len() {
                return false;
            }
            if self.anchored && at + 2 == self.pieces.len() {
                return remaining_path.ends_with(piece.needle());
            }
            let Some(found) = piece.find(remaining_path) else {
                return false;
            };
            remaining_path = &remaining_path[found + piece.needle().len()..];
            literal_bytes -= piece.needle().len();
        }
        !self.anchored || remaining_path.is_empty()
    }
}

#[derive(Default)]
struct Group<'a> {
    agents: Vec<String>,
    rules: Vec<ParsedRule<'a>>,
}

struct ParsedRule<'a> {
    pattern: &'a str,
    stars: usize,
    allow: bool,
}

impl RobotsRules {
    pub(super) fn from_context(context: &ProbeContext) -> Self {
        let Some(answer) = context.outcomes.get(&robots_request(context)) else {
            return Self::default();
        };
        robots_fetch_from_probe(answer.clone())
            .body()
            .map_or_else(Self::default, |body| Self::parse(body, "SiteCMD"))
    }

    fn parse(body: &str, token: &str) -> Self {
        let mut groups = Vec::new();
        let mut group = Group::default();
        let mut seen_rule = false;
        for (name, value) in records(body) {
            match name.trim().to_ascii_lowercase().as_str() {
                "user-agent" => {
                    if seen_rule {
                        groups.push(std::mem::take(&mut group));
                        seen_rule = false;
                    }
                    group.agents.push(value.to_ascii_lowercase());
                }
                "allow" | "disallow" if !group.agents.is_empty() => {
                    seen_rule = true;
                    if !value.is_empty() {
                        group.rules.push(ParsedRule {
                            pattern: value,
                            stars: value.bytes().filter(|byte| *byte == b'*').count(),
                            allow: name.trim().eq_ignore_ascii_case("allow"),
                        });
                    }
                }
                _ => {}
            }
        }
        groups.push(group);
        let token = token.to_ascii_lowercase();
        let selected = if groups.iter().any(|group| group.agents.contains(&token)) {
            token.as_str()
        } else {
            "*"
        };
        let mut pieces = 0;
        let mut star_rules = 0;
        let mut rules = Vec::new();
        for rule in groups
            .into_iter()
            .filter(|group| group.agents.iter().any(|agent| agent == selected))
            .flat_map(|group| group.rules)
        {
            pieces += 1 + rule.stars;
            star_rules += usize::from(rule.stars > 0);
            if pieces > ROBOTS_PIECE_LIMIT || star_rules > ROBOTS_STAR_RULE_LIMIT {
                return Self::default();
            }
            rules.push(rule);
        }
        Self {
            rules: rules
                .into_iter()
                .map(|rule| Rule::compile(normalized(rule.pattern, true), rule.allow))
                .collect(),
        }
    }

    pub(super) fn allowed(&self, path_and_query: &str) -> bool {
        let path = normalized(path_and_query, false);
        if path == "/robots.txt" {
            return true;
        }
        self.rules
            .iter()
            .filter(|rule| rule.matches(&path))
            .max_by_key(|rule| (rule.specificity, rule.allow))
            .is_none_or(|rule| rule.allow)
    }
}

// Unreserved escapes are decoded; reserved escapes stay distinct from literal URI syntax.
fn normalized(value: &str, pattern: bool) -> String {
    let mut bytes = value.bytes().peekable();
    let mut normalized = Vec::with_capacity(value.len());
    let mut query = false;
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let mut peek = bytes.clone();
            if let Some((high, low)) = peek.next().zip(peek.next()) {
                if let (Some(high), Some(low)) =
                    ((high as char).to_digit(16), (low as char).to_digit(16))
                {
                    bytes.next();
                    bytes.next();
                    let decoded = (high * 16 + low) as u8;
                    if decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded) {
                        normalized.push(decoded);
                    } else {
                        normalized.extend_from_slice(format!("%{decoded:02X}").as_bytes());
                    }
                    continue;
                }
            }
        }
        let syntax = match byte {
            b'/' => !query,
            b'?' if !query => {
                query = true;
                true
            }
            b'=' | b'&' => query,
            b'*' => pattern,
            b'$' => pattern && bytes.peek().is_none(),
            _ => false,
        };
        if syntax || byte.is_ascii_alphanumeric() || b"-._~%".contains(&byte) {
            normalized.push(byte);
        } else {
            normalized.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    String::from_utf8(normalized).expect("normalized URI is ASCII")
}

#[cfg(test)]
#[path = "discovery_robots_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "discovery_robots_capacity.rs"]
mod capacity;
