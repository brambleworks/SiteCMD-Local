//! The sanitized summary a fix result carries back to SiteCMD. A result
//! leaves the customer's repository, so it carries no checkout path, no
//! source line and no credential, and it is bounded. The whole log stays in
//! the Actions run, where only the repository's own people can read it.

use std::path::Path;

const MAX_SUMMARY_CHARS: usize = 2000;

/// Extensions that make a bare filename a source path. Data and configuration
/// extensions (`json`, `toml`, `yml`, `lock`, ...) are deliberately absent: a
/// write set names files like `vercel.json`, and that name is the result the
/// customer asked for rather than a leak.
const SOURCE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts", "rs", "py", "go", "rb", "php", "java",
    "kt", "swift", "cs", "vue", "svelte", "astro", "css", "scss", "sass", "less", "html", "htm",
    "sql", "sh", "bash", "zsh", "ps1", "c", "cc", "cpp", "h", "hpp", "m", "mm",
];

/// Punctuation that wraps a path in prose or in a tool's output, kept around
/// the marker so the sentence still reads.
const LEADING_PUNCTUATION: &[char] = &['(', '\'', '"', '[', '{'];
const TRAILING_PUNCTUATION: &[char] = &[')', ']', '}', '\'', '"', ',', ';', ':', '.'];

/// Reduce arbitrary tool output to something safe to send: the checkout root
/// folded to `<checkout>`, every code frame and path hidden, every known
/// credential shape scrubbed, and the whole thing bounded.
pub fn summary(root: &Path, text: &str) -> String {
    let root_text = root.to_string_lossy();
    let without_root = if root_text.is_empty() {
        text.to_string()
    } else {
        text.replace(root_text.as_ref(), "<checkout>")
    };
    let without_source = without_root
        .split('\n')
        .map(|line| {
            if code_frame(line) {
                "<code>".to_string()
            } else {
                hide_paths(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let redacted = crate::log_sanitizer::redact_secrets(&mask_own_tokens(&without_source));
    redacted.chars().take(MAX_SUMMARY_CHARS).collect()
}

/// SiteCMD's own credentials are `sitecmd_<kind>_<opaque>`: a job token, a
/// connection access token. `redact_secrets` knows the providers' shapes and
/// not ours, so one of ours that reached a tool's output is masked here first.
/// Two underscores after the prefix is the whole shape, and masking a word
/// that merely looks like one costs nothing.
fn mask_own_tokens(text: &str) -> String {
    const PREFIX: &str = "sitecmd_";
    let mut masked = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        masked.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        let candidate = &tail[..end];
        if candidate.matches('_').count() >= 2 {
            masked.push_str("<token>");
        } else {
            masked.push_str(candidate);
        }
        rest = &tail[end..];
    }
    masked.push_str(rest);
    masked
}

/// Whether a line is a compiler or bundler code frame: a numbered source line
/// (`  12 | const value = ...`), a gutter continuation, or the caret underline
/// beneath one. Every one of them quotes the repository's own source.
fn code_frame(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with('|') {
        return true;
    }
    if trimmed
        .chars()
        .all(|character| matches!(character, '^' | '~' | '-' | '_' | ' '))
    {
        return true;
    }
    let numbered = trimmed
        .strip_prefix('>')
        .unwrap_or(trimmed)
        .trim_start_matches(' ');
    let digits = numbered
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(numbered.len());
    digits > 0 && numbered[digits..].trim_start_matches(' ').starts_with('|')
}

/// Rewrite every path-shaped token in one line as `<path>`, leaving the
/// line's whitespace exactly as it was.
fn hide_paths(line: &str) -> String {
    let mut hidden = String::with_capacity(line.len());
    let mut token_start: Option<usize> = None;
    for (index, character) in line.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = token_start.take() {
                hidden.push_str(&hide_path(&line[start..index]));
            }
            hidden.push(character);
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        hidden.push_str(&hide_path(&line[start..]));
    }
    hidden
}

/// One whitespace-delimited token, with the punctuation around it preserved.
fn hide_path(token: &str) -> String {
    let core = token.trim_start_matches(LEADING_PUNCTUATION);
    let prefix = &token[..token.len() - core.len()];
    let core = core.trim_end_matches(TRAILING_PUNCTUATION);
    if !path_shaped(core) {
        return token.to_string();
    }
    let suffix = &token[prefix.len() + core.len()..];
    format!("{prefix}<path>{suffix}")
}

/// A token names a file when it carries a path separator, or when it ends in
/// a source file's extension.
fn path_shaped(token: &str) -> bool {
    if token.contains('/') || token.contains('\\') {
        return true;
    }
    token.rsplit_once('.').is_some_and(|(_, extension)| {
        SOURCE_EXTENSIONS
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    })
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn hides_paths_code_frames_and_credentials_and_bounds_the_length() {
        let root = std::path::Path::new("/home/runner/work/loop/loop");
        let text = format!(
            "error in /home/runner/work/loop/loop/app/page.tsx with token ghp_abcdefghijklmnopqrstuvwxyz0123456789\n  12 | const value = readSecret(process.env.TOKEN);\n     |       ^^^^^\nsee next.config.js and ./lib/util.ts, then vercel.json\nclaimed with sitecmd_job_execute_0123456789abcdef0123456789abcdef\n{}",
            "x".repeat(5000)
        );
        let redacted = summary(root, &text);
        assert!(
            redacted.starts_with("error in <path> with token "),
            "{redacted}"
        );
        for leaked in [
            "/home/runner",
            "page.tsx",
            "readSecret",
            "^^^^^",
            "next.config.js",
            "lib/util.ts",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "sitecmd_job_execute_0123456789abcdef0123456789abcdef",
        ] {
            assert!(!redacted.contains(leaked), "{leaked} survived: {redacted}");
        }
        assert!(
            redacted.contains("<code>\n<code>\nsee <path> and <path>, then vercel.json\n"),
            "{redacted}"
        );
        assert!(redacted.contains("claimed with <token>\n"), "{redacted}");
        assert!(redacted.chars().count() <= 2000);
    }
}
