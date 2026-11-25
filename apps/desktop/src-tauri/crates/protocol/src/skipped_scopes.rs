//! Skipped scope accounting and the native report representation.

use crate::engine_abi::{FileLocation, RuleSkipReason, SkippedScopes};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Summary of directories and rules constructs omitted from local analysis.
/// A capped sample lets the UI explain unexpectedly small scans.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeScanSkippedScopes {
    /// Directories skipped because they are a separate nested git repository
    /// (a benchmark clone, a vendored checkout, a submodule or worktree).
    pub nested_repositories: usize,
    /// Directories skipped because the project's own `.gitignore` excludes them
    /// (build output, codegen, third-party working trees).
    pub gitignored_directories: usize,
    /// A small, capped sample of the skipped top-level directory names (relative
    /// to the scan root), for a "skipped: foo, bar,..." note. Not exhaustive.
    pub sample_names: Vec<String>,
    /// Rules constructs omitted by analysis bounds or unsupported syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_blocks_skipped: Option<usize>,
    /// Bounded relative file locations and reasons for omitted rules constructs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_samples: Option<Vec<String>>,
}

impl CodeScanSkippedScopes {
    /// Word the module's skipped scopes, naming each rules file through `path`.
    pub fn from_module<E>(
        scopes: SkippedScopes,
        mut path: impl FnMut(&FileLocation) -> Result<String, E>,
    ) -> Result<Self, E> {
        let rule_samples = scopes
            .rule_samples
            .map(|samples| {
                samples
                    .into_iter()
                    .take(MAX_SKIPPED_SAMPLE_NAMES)
                    .map(|skip| {
                        Ok(format!(
                            "{}:{}:{}: {}",
                            path(&skip.path)?,
                            skip.line,
                            skip.column,
                            skip.reason
                        ))
                    })
                    .collect::<Result<Vec<_>, E>>()
            })
            .transpose()?;
        Ok(Self {
            nested_repositories: scopes.nested_repositories,
            gitignored_directories: scopes.gitignored_directories,
            sample_names: scopes.sample_names,
            rule_blocks_skipped: scopes.rule_blocks_skipped,
            rule_samples,
        })
    }
}

impl fmt::Display for RuleSkipReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopeLimit { limit } => write!(
                formatter,
                "open scope limit ({limit} scopes, including service and root blocks)"
            ),
            Self::PathSegmentLimit { limit } => write!(
                formatter,
                "match path segment limit ({limit} segments below the service root)"
            ),
            Self::JsonNestingLimit { limit } => write!(
                formatter,
                "JSON object nesting limit ({limit} objects, including document and rules)"
            ),
            Self::UnsupportedMatch => formatter.write_str("unsupported match"),
            Self::UnsupportedGrant => formatter.write_str("unsupported grant"),
            Self::UnsupportedService => formatter.write_str("unsupported service"),
            Self::AdditionalService => formatter.write_str("additional service"),
            Self::UnsupportedBlock => formatter.write_str("unsupported block"),
            Self::UnreadableJson => formatter.write_str("unreadable JSON rules file"),
        }
    }
}

/// Cap on each sample list so a pathological tree can never balloon the report.
pub const MAX_SKIPPED_SAMPLE_NAMES: usize = 12;

impl SkippedScopes {
    /// Total directories the walker refused to descend into.
    pub fn total(&self) -> usize {
        self.nested_repositories + self.gitignored_directories
    }

    /// Record a pruned directory, keeping the sample list bounded.
    pub fn record_nested_repository(&mut self, name: String) {
        self.nested_repositories += 1;
        self.push_sample(name);
    }

    pub fn record_gitignored_directory(&mut self, name: String) {
        self.gitignored_directories += 1;
        self.push_sample(name);
    }

    fn push_sample(&mut self, name: String) {
        if name.is_empty() {
            return;
        }
        let depth = |path: &str| path.bytes().filter(|byte| *byte == b'/').count();
        let rank = (depth(&name), name.as_str());
        let index = self
            .sample_names
            .partition_point(|path| (depth(path), path.as_str()) <= rank);
        if index < MAX_SKIPPED_SAMPLE_NAMES {
            if self.sample_names.len() == MAX_SKIPPED_SAMPLE_NAMES {
                self.sample_names.pop();
            }
            self.sample_names.insert(index, name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_abi::{RelPath, RuleSkip};
    use std::convert::Infallible;

    #[test]
    fn skipped_scope_samples_keep_the_same_root_first_paths_in_both_orders() {
        let expected: Vec<_> = (0..MAX_SKIPPED_SAMPLE_NAMES)
            .map(|index| format!("dir-{index:02}"))
            .collect();
        let mut paths = vec!["a/deep".to_owned(), "z-extra".to_owned()];
        paths.extend(expected.iter().cloned());
        for order in [paths.clone(), paths.into_iter().rev().collect()] {
            let mut scopes = SkippedScopes::default();
            for path in order {
                scopes.record_gitignored_directory(path);
            }
            assert_eq!(scopes.total(), MAX_SKIPPED_SAMPLE_NAMES + 2);
            assert_eq!(scopes.sample_names, expected);
        }
    }

    #[test]
    fn module_rules_samples_resolve_listed_paths_and_offer_ids() {
        let scopes = SkippedScopes {
            rule_blocks_skipped: Some(2),
            rule_samples: Some(vec![
                RuleSkip {
                    path: FileLocation::Listed(RelPath::parse("firestore.rules").unwrap()),
                    line: 3,
                    column: 7,
                    reason: RuleSkipReason::UnsupportedMatch,
                },
                RuleSkip {
                    path: FileLocation::Offer { id: 1 },
                    line: 5,
                    column: 9,
                    reason: RuleSkipReason::UnsupportedGrant,
                },
            ]),
            ..SkippedScopes::default()
        };
        let offered = ["other.rules", "database.rules.json"];
        let native = CodeScanSkippedScopes::from_module(scopes, |location| {
            Ok::<_, Infallible>(
                match location {
                    FileLocation::Listed(path) => path.as_str(),
                    FileLocation::Offer { id } => offered[*id as usize],
                }
                .to_owned(),
            )
        })
        .unwrap();

        assert_eq!(native.rule_blocks_skipped, Some(2));
        assert_eq!(
            native.rule_samples.unwrap(),
            [
                "firestore.rules:3:7: unsupported match",
                "database.rules.json:5:9: unsupported grant",
            ]
        );
    }

    #[test]
    fn module_rules_samples_keep_only_the_first_twelve() {
        let scopes = SkippedScopes {
            rule_blocks_skipped: Some(13),
            rule_samples: Some(
                (1..=13)
                    .map(|line| RuleSkip {
                        path: FileLocation::Offer { id: line },
                        line,
                        column: 1,
                        reason: RuleSkipReason::UnsupportedBlock,
                    })
                    .collect(),
            ),
            ..SkippedScopes::default()
        };
        let native = CodeScanSkippedScopes::from_module(scopes, |location| match location {
            FileLocation::Offer { id: 13 } => Err("the thirteenth offer must not be resolved"),
            FileLocation::Offer { id } => Ok(format!("offered/{id}.rules")),
            FileLocation::Listed(_) => unreachable!(),
        })
        .unwrap();

        assert_eq!(native.rule_blocks_skipped, Some(13));
        assert_eq!(
            native.rule_samples.unwrap(),
            (1..=12)
                .map(|line| format!("offered/{line}.rules:{line}:1: unsupported block"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rule_skip_reasons_display_the_report_wording() {
        use RuleSkipReason::*;
        for (reason, expected) in [
            (
                ScopeLimit { limit: 42 },
                "open scope limit (42 scopes, including service and root blocks)",
            ),
            (
                PathSegmentLimit { limit: 15 },
                "match path segment limit (15 segments below the service root)",
            ),
            (
                JsonNestingLimit { limit: 8 },
                "JSON object nesting limit (8 objects, including document and rules)",
            ),
            (UnsupportedMatch, "unsupported match"),
            (UnsupportedGrant, "unsupported grant"),
            (UnsupportedService, "unsupported service"),
            (AdditionalService, "additional service"),
            (UnsupportedBlock, "unsupported block"),
            (UnreadableJson, "unreadable JSON rules file"),
        ] {
            assert_eq!(reason.to_string(), expected, "{reason:?}");
        }
    }
}
