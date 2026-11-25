use std::borrow::Cow;

use sitecmd_protocol::brief_copy::{
    brief_context_line, encoded_location_path, occurrence_acceptance_criteria, ATTEMPT_PREFIX,
    BRIEF_TITLE_PREFIX, ISSUE_TITLE_PREFIX, METADATA_SEPARATOR, REPORTED_LOCATION_LABEL,
    REPORTED_LOCATION_REASON, SEVERITY_PREFIX,
};
use sitecmd_protocol::engine_abi::BriefTarget;

use super::{redact_text, text_lines};

// Comparison operates on single lines, so this placeholder cannot occur in the input
// and no shingle can span it.
pub(super) const MASKED_FIELD: char = '\n';

#[derive(Default)]
pub(super) struct BriefMetadata {
    full_lines: Vec<String>,
    inline: Vec<String>,
}

impl BriefMetadata {
    pub(super) fn new(target: &BriefTarget) -> Self {
        let headings = [
            format!("{ISSUE_TITLE_PREFIX}{}", target.title),
            format!("{BRIEF_TITLE_PREFIX}{}", target.title),
            brief_context_line(
                target.attempt,
                &target.check_id,
                target.severity,
                &target.site_url,
            ),
        ];
        let prose = [
            Some(target.description.as_str()),
            target.likely_fix.as_deref(),
            target.why_now.as_deref(),
        ];
        let inline = [
            format!("{ATTEMPT_PREFIX}{}{METADATA_SEPARATOR}", target.attempt),
            format!("{SEVERITY_PREFIX}{}{METADATA_SEPARATOR}", target.severity),
            format!("`{}`", target.check_id),
            target.site_url.clone(),
        ];
        let location_refs = target.locations.iter().map(|location| {
            format!(
                "`{}:{}`",
                encoded_location_path(&location.path),
                location.line,
            )
        });

        let criteria = location_refs.clone().next().map(|location| {
            occurrence_acceptance_criteria(&target.check_id, &target.site_url, &location)
        });
        // Hosted briefs always have reported locations and never render the stack.
        Self {
            full_lines: headings
                .iter()
                .map(String::as_str)
                .chain(prose.into_iter().flatten().flat_map(text_lines))
                .map(str::to_owned)
                .chain(criteria)
                .chain(location_refs.clone().map(|location| {
                    format!("- {location} ({REPORTED_LOCATION_LABEL}) - {REPORTED_LOCATION_REASON}")
                }))
                .flat_map(|value| metadata_forms(&value))
                .collect(),
            inline: inline
                .into_iter()
                .chain(location_refs)
                .flat_map(|value| metadata_forms(&value))
                .collect(),
        }
    }

    pub(super) fn mask<'a>(&self, line: &'a str) -> Option<Cow<'a, str>> {
        if self.full_lines.iter().any(|value| value == line) {
            return None;
        }
        let mut ranges: Vec<_> = self
            .inline
            .iter()
            .flat_map(|value| {
                line.match_indices(value)
                    .map(|(start, _)| (start, start + value.len()))
            })
            .collect();
        if ranges.is_empty() {
            return Some(Cow::Borrowed(line));
        }
        ranges.sort_unstable();
        let mut masked = String::with_capacity(line.len());
        let mut end = 0;
        for (start, next_end) in ranges {
            if start >= end {
                masked.push_str(&line[end..start]);
                masked.push(MASKED_FIELD);
            }
            end = end.max(next_end);
        }
        masked.push_str(&line[end..]);
        Some(Cow::Owned(masked))
    }
}

fn metadata_forms(value: &str) -> impl Iterator<Item = String> {
    let redacted = redact_text(value);
    [value.to_owned(), redacted]
        .into_iter()
        .filter(|value| !value.is_empty())
}
