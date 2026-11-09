use super::*;
use chrono::NaiveDate;

const VERSION_FILE_MAX_BYTES: u64 = 64 * 1024;
const CONFIG_FILE_MAX_BYTES: u64 = 250_000;

/// Vendored runtime end-of-life tables, snapshotted November 2026 from the
/// upstream projects' official support schedules. The scanner never fetches
/// these over the network; extend the tables when schedules change.
struct EolEntry {
    major: u32,
    minor: u32,
    eol: &'static str,
}

// Odd Node majors are short-lived non-LTS lines; without them a project
// declaring >=17/19/21 got no verdict at all even though every odd line
// is long past end of life.
const NODE_EOL: &[EolEntry] = &[
    EolEntry {
        major: 16,
        minor: 0,
        eol: "2023-09-11",
    },
    EolEntry {
        major: 17,
        minor: 0,
        eol: "2022-06-01",
    },
    EolEntry {
        major: 18,
        minor: 0,
        eol: "2025-04-30",
    },
    EolEntry {
        major: 19,
        minor: 0,
        eol: "2023-06-01",
    },
    EolEntry {
        major: 20,
        minor: 0,
        eol: "2026-04-30",
    },
    EolEntry {
        major: 21,
        minor: 0,
        eol: "2024-06-01",
    },
    EolEntry {
        major: 22,
        minor: 0,
        eol: "2027-04-30",
    },
    EolEntry {
        major: 23,
        minor: 0,
        eol: "2025-06-01",
    },
    EolEntry {
        major: 24,
        minor: 0,
        eol: "2028-04-30",
    },
    EolEntry {
        major: 25,
        minor: 0,
        eol: "2026-06-01",
    },
];

const PYTHON_EOL: &[EolEntry] = &[
    EolEntry {
        major: 3,
        minor: 7,
        eol: "2023-06-27",
    },
    EolEntry {
        major: 3,
        minor: 8,
        eol: "2024-10-07",
    },
    EolEntry {
        major: 3,
        minor: 9,
        eol: "2025-10-31",
    },
    EolEntry {
        major: 3,
        minor: 10,
        eol: "2026-10-01",
    },
    EolEntry {
        major: 3,
        minor: 11,
        eol: "2027-10-24",
    },
];

const PHP_EOL: &[EolEntry] = &[
    EolEntry {
        major: 8,
        minor: 0,
        eol: "2023-11-26",
    },
    EolEntry {
        major: 8,
        minor: 1,
        eol: "2025-12-31",
    },
    EolEntry {
        major: 8,
        minor: 2,
        eol: "2026-12-31",
    },
    EolEntry {
        major: 8,
        minor: 3,
        eol: "2027-12-31",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runtime {
    Node,
    Python,
    Php,
}

impl Runtime {
    fn label(self) -> &'static str {
        match self {
            Self::Node => "Node.js",
            Self::Python => "Python",
            Self::Php => "PHP",
        }
    }

    /// Node lines are versioned by major only; Python and PHP support
    /// windows are per major.minor line.
    fn matches_major_only(self) -> bool {
        matches!(self, Self::Node)
    }

    fn eol_table(self) -> &'static [EolEntry] {
        match self {
            Self::Node => NODE_EOL,
            Self::Python => PYTHON_EOL,
            Self::Php => PHP_EOL,
        }
    }

    fn upgrade_hint(self) -> &'static str {
        match self {
            Self::Node => "Choose a currently supported Node.js line compatible with the application and its dependencies; production applications should normally use an upstream LTS line.",
            Self::Python => "Choose a currently supported Python line compatible with the application and its dependencies.",
            Self::Php => "Choose a currently supported PHP line compatible with the application and its dependencies.",
        }
    }

    fn support_source(self) -> &'static str {
        match self {
            Self::Node => "nodejs.org release schedule",
            Self::Python => "Python Developer's Guide versions table",
            Self::Php => "php.net supported-versions table",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeVersion {
    major: u32,
    minor: Option<u32>,
}

fn version_key(version: RuntimeVersion) -> (u32, u32) {
    (version.major, version.minor.unwrap_or(0))
}

struct RuntimeDeclaration {
    runtime: Runtime,
    source_label: String,
    spec: String,
    relative_path: String,
    absolute_path: String,
    line: Option<u32>,
    content: String,
    kind: RuntimeDeclarationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeDeclarationKind {
    /// A version-manager file selects a runtime for local/tooling use.
    VersionSelector,
    /// A package metadata field declares compatible runtime versions; it does
    /// not prove which version a deployment selects.
    CompatibilityRange,
}

pub(super) fn collect_runtime_eol_issues(
    issues: &mut Vec<CodeIssue>,
    project_files: &[ProjectFile],
    manifests: &[PackageManifest],
) {
    let today = chrono::Utc::now().date_naive();
    issues.extend(runtime_eol_issues_at(project_files, manifests, today));
}

/// Clock-injectable core so tests can pin `today` instead of drifting with
/// the wall clock (mirrors licensing::access::effective_tier_from_state_at).
fn runtime_eol_issues_at(
    project_files: &[ProjectFile],
    manifests: &[PackageManifest],
    today: NaiveDate,
) -> Vec<CodeIssue> {
    let mut issues = Vec::new();
    let declarations = [
        detect_node_declaration(project_files, manifests),
        detect_python_declaration(project_files),
        detect_php_declaration(project_files),
    ];
    for declaration in declarations.into_iter().flatten() {
        let Some(minimum) = minimum_admitted_version(&declaration.spec) else {
            continue;
        };
        let Some(status) = eol_status(declaration.runtime, minimum, today) else {
            continue;
        };
        issues.push(runtime_eol_issue(&declaration, minimum, status));
    }
    issues
}

enum EolStatus {
    /// The minimum admitted version matches a table row whose date has passed.
    PastEol(&'static EolEntry),
    /// The minimum admitted version is older than the oldest tracked line,
    /// which itself is already past end of life.
    PredatesTable(&'static EolEntry),
}

fn eol_status(runtime: Runtime, version: RuntimeVersion, today: NaiveDate) -> Option<EolStatus> {
    // Python and PHP support windows are per minor line; a bare major such
    // as ".python-version: 3" resolves to "latest 3.x" in practice, so it is
    // not evidence of an end-of-life line.
    if !runtime.matches_major_only() && version.minor.is_none() {
        return None;
    }
    let table = runtime.eol_table();
    let oldest = table.first()?;
    let oldest_key = if runtime.matches_major_only() {
        (oldest.major, 0)
    } else {
        (oldest.major, oldest.minor)
    };
    if version_key(version) < oldest_key {
        return Some(EolStatus::PredatesTable(oldest));
    }
    let entry = table.iter().find(|entry| {
        entry.major == version.major
            && (runtime.matches_major_only() || Some(entry.minor) == version.minor)
    })?;
    let eol = NaiveDate::parse_from_str(entry.eol, "%Y-%m-%d").ok()?;
    (today > eol).then_some(EolStatus::PastEol(entry))
}

fn runtime_eol_issue(
    declaration: &RuntimeDeclaration,
    minimum: RuntimeVersion,
    status: EolStatus,
) -> CodeIssue {
    let runtime = declaration.runtime;
    let label = runtime.label();
    let minimum_display = version_display(runtime, minimum);
    let support_source = runtime.support_source();
    let evidence = match status {
        EolStatus::PastEol(entry) => format!(
            "{} declares '{}', which admits {} {} at minimum. {} {} reached upstream end of life on {} (source: {}).",
            declaration.source_label,
            declaration.spec,
            label,
            minimum_display,
            label,
            entry_display(runtime, entry),
            entry.eol,
            support_source,
        ),
        EolStatus::PredatesTable(oldest) => format!(
            "{} declares '{}', which admits {} {} at minimum. That is older than {} {}, which reached upstream end of life on {}; every earlier line ended before that (source: {}).",
            declaration.source_label,
            declaration.spec,
            label,
            minimum_display,
            label,
            entry_display(runtime, oldest),
            oldest.eol,
            support_source,
        ),
    };

    let (severity, title, description, likely_fix, verify_hint) = match declaration.kind {
        RuntimeDeclarationKind::VersionSelector => (
            Severity::Medium,
            format!("{} version selector names an end-of-life release line", label),
            format!(
                "The scanned version-manager file selects a {} line that is past upstream end of life. This is direct evidence for tools that honor this selector, but it does not prove the CI, container, host, or production runtime uses the same version; commercial or downstream support may also provide patches outside the upstream schedule.",
                label
            ),
            format!(
                "{} Update this selector and every runtime selection that is intended to match it, such as CI, container, or host configuration. If an extended-support build is intentional, document its provider, patch SLA, and end date instead of changing only the version text.",
                runtime.upgrade_hint()
            ),
            "Resolve the selector from a clean environment, run the full build and tests, and inspect the actual CI and deployed runtime versions. Confirm each is upstream-supported or covered by the documented extended-support provider.".into(),
        ),
        RuntimeDeclarationKind::CompatibilityRange => (
            Severity::Low,
            format!("Runtime compatibility declaration permits end-of-life {}", label),
            format!(
                "The scanned package compatibility range still admits a {} line that is past upstream end of life. This does not prove any deployed environment runs that line: a lock, version manager, container, host setting, or deployment platform may select a newer version, and commercial or downstream support may maintain a patched build. For a library, the range may also be an intentional compatibility promise.",
                label
            ),
            format!(
                "Confirm the actual local, CI, container, and deployed runtime first. If the project no longer tests or supports the end-of-life line, raise the compatibility lower bound to the oldest line the project genuinely supports and publish that as a deliberate compatibility change. If support is intentional, document the test matrix and extended-support source. {}",
                runtime.upgrade_hint()
            ),
            "Test the resolved minimum supported line and the actual deployed line. Confirm the compatibility declaration matches the maintained test matrix and that every runtime in use is upstream-supported or covered by a documented extended-support source.".into(),
        ),
    };

    CodeIssue {
        check_id: String::new(),
        id: format!("runtime-version-eol:{}", declaration.relative_path),
        category: "operations".into(),
        severity,
        title,
        description,
        relative_path: declaration.relative_path.clone(),
        absolute_path: declaration.absolute_path.clone(),
        line: declaration.line,
        source_excerpt: excerpt_for_line(&declaration.content, declaration.line),
        evidence: Some(redact_evidence(evidence)),
        why_now: Some("Upstream end of life means that project no longer publishes security or bug-fix releases for the line. Actual risk depends on whether the line is selected in an environment and whether a downstream extended-support provider supplies maintained patches.".into()),
        likely_fix: Some(likely_fix),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        verify_hint: Some(verify_hint),
    }
}

fn version_display(runtime: Runtime, version: RuntimeVersion) -> String {
    match version.minor {
        Some(minor) if !runtime.matches_major_only() => format!("{}.{}", version.major, minor),
        _ => version.major.to_string(),
    }
}

fn entry_display(runtime: Runtime, entry: &EolEntry) -> String {
    if runtime.matches_major_only() {
        entry.major.to_string()
    } else {
        format!("{}.{}", entry.major, entry.minor)
    }
}

/// Return the lowest version admitted across range branches.
/// Upper-only, wildcard, and alias ranges have no minimum.
fn minimum_admitted_version(spec: &str) -> Option<RuntimeVersion> {
    let mut branch_minimums: Vec<RuntimeVersion> = Vec::new();
    for branch in spec.split("||").flat_map(|part| part.split('|')) {
        let branch = branch.trim();
        if branch.is_empty() {
            continue;
        }
        // npm hyphen range: `16 - 18` admits 16 at minimum.
        if let Some((low, _high)) = branch.split_once(" - ") {
            if let Some(version) = parse_version_token(low.trim()) {
                branch_minimums.push(version);
            }
            continue;
        }
        // AND-ed comparators within a branch: the admitted minimum is the
        // highest lower bound (`>=18 >=20` admits 20).
        let mut branch_lower: Option<RuntimeVersion> = None;
        for token in branch.split([' ', ',', '\t']) {
            let token = token.trim();
            if token.is_empty() || token.starts_with('<') {
                continue;
            }
            let Some(version) = parse_version_token(token) else {
                continue;
            };
            branch_lower = Some(match branch_lower {
                Some(current) if version_key(current) >= version_key(version) => current,
                _ => version,
            });
        }
        if let Some(version) = branch_lower {
            branch_minimums.push(version);
        }
    }
    branch_minimums
        .into_iter()
        .min_by_key(|version| version_key(*version))
}

fn parse_version_token(token: &str) -> Option<RuntimeVersion> {
    let mut token = token;
    for prefix in [">=", "~=", "==", ">", "^", "~", "="] {
        if let Some(rest) = token.strip_prefix(prefix) {
            token = rest;
            break;
        }
    }
    let token = token.trim().trim_start_matches('v');
    let mut segments = token.split('.');
    let major_segment = segments.next()?;
    if major_segment.is_empty() || !major_segment.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let major = major_segment.parse().ok()?;
    let minor = match segments.next() {
        None => None,
        Some(segment) if segment.eq_ignore_ascii_case("x") || segment == "*" => None,
        Some(segment) => {
            if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            Some(segment.parse().ok()?)
        }
    };
    Some(RuntimeVersion { major, minor })
}

fn detect_node_declaration(
    project_files: &[ProjectFile],
    manifests: &[PackageManifest],
) -> Option<RuntimeDeclaration> {
    if let Some(declaration) = [".nvmrc", ".node-version"]
        .iter()
        .find_map(|name| version_file_declaration(project_files, name, Runtime::Node))
    {
        return Some(declaration);
    }
    for manifest in manifests {
        let Ok(json) = serde_json::from_str::<Value>(&manifest.content) else {
            continue;
        };
        let Some(spec) = json
            .get("engines")
            .and_then(|engines| engines.get("node"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        return Some(RuntimeDeclaration {
            runtime: Runtime::Node,
            source_label: format!("{} engines.node", manifest.relative_path),
            spec: spec.to_string(),
            relative_path: manifest.relative_path.clone(),
            absolute_path: manifest.absolute_path.to_string_lossy().to_string(),
            line: find_line(&manifest.content, "\"node\""),
            content: manifest.content.clone(),
            kind: RuntimeDeclarationKind::CompatibilityRange,
        });
    }
    None
}

fn detect_python_declaration(project_files: &[ProjectFile]) -> Option<RuntimeDeclaration> {
    if let Some(declaration) =
        version_file_declaration(project_files, ".python-version", Runtime::Python)
    {
        return Some(declaration);
    }
    let (file, content) = read_named_project_file(project_files, "pyproject.toml")?;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("requires-python") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let spec = rest.trim().trim_matches('"').trim_matches('\'').trim();
        if spec.is_empty() {
            continue;
        }
        return Some(RuntimeDeclaration {
            runtime: Runtime::Python,
            source_label: format!("{} requires-python", file.relative_path),
            spec: spec.to_string(),
            relative_path: file.relative_path.clone(),
            absolute_path: file.absolute_path.to_string_lossy().to_string(),
            line: Some(index as u32 + 1),
            content: content.clone(),
            kind: RuntimeDeclarationKind::CompatibilityRange,
        });
    }
    None
}

fn detect_php_declaration(project_files: &[ProjectFile]) -> Option<RuntimeDeclaration> {
    let (file, content) = read_named_project_file(project_files, "composer.json")?;
    let json = serde_json::from_str::<Value>(&content).ok()?;
    let spec = json
        .get("require")
        .and_then(|require| require.get("php"))
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if spec.is_empty() {
        return None;
    }
    Some(RuntimeDeclaration {
        runtime: Runtime::Php,
        source_label: format!("{} require.php", file.relative_path),
        spec,
        relative_path: file.relative_path.clone(),
        absolute_path: file.absolute_path.to_string_lossy().to_string(),
        line: find_line(&content, "\"php\""),
        content,
        kind: RuntimeDeclarationKind::CompatibilityRange,
    })
}

/// Find a project file by basename, preferring one at the scanned root over
/// nested copies, and read it as UTF-8 text through the bounded inventory
/// reader.
fn read_named_project_file<'a>(
    project_files: &'a [ProjectFile],
    file_name: &str,
) -> Option<(&'a ProjectFile, String)> {
    let nested_suffix = format!("/{}", file_name);
    let file = project_files
        .iter()
        .find(|file| file.relative_path == file_name)
        .or_else(|| {
            project_files
                .iter()
                .find(|file| file.relative_path.ends_with(&nested_suffix))
        })?;
    let bytes = read_project_file(file, CONFIG_FILE_MAX_BYTES)?;
    let content = String::from_utf8(bytes).ok()?;
    Some((file, content))
}

/// Read a single-value version file (`.nvmrc`, `.node-version`,
/// `.python-version`): the first non-empty, non-comment line is the spec.
/// Non-numeric aliases such as `lts/hydrogen` yield no version and are
/// skipped downstream by `minimum_admitted_version`.
fn version_file_declaration(
    project_files: &[ProjectFile],
    file_name: &str,
    runtime: Runtime,
) -> Option<RuntimeDeclaration> {
    let nested_suffix = format!("/{}", file_name);
    let file = project_files
        .iter()
        .find(|file| file.relative_path == file_name)
        .or_else(|| {
            project_files
                .iter()
                .find(|file| file.relative_path.ends_with(&nested_suffix))
        })?;
    let bytes = read_project_file(file, VERSION_FILE_MAX_BYTES)?;
    let content = String::from_utf8(bytes).ok()?;
    let (index, spec) = content
        .lines()
        .enumerate()
        .map(|(index, line)| (index, line.trim()))
        .find(|(_, line)| !line.is_empty() && !line.starts_with('#'))?;
    Some(RuntimeDeclaration {
        runtime,
        source_label: file.relative_path.clone(),
        spec: spec.to_string(),
        relative_path: file.relative_path.clone(),
        absolute_path: file.absolute_path.to_string_lossy().to_string(),
        line: Some(index as u32 + 1),
        content: content.clone(),
        kind: RuntimeDeclarationKind::VersionSelector,
    })
}

#[cfg(test)]
mod tests {
    use super::{eol_status, minimum_admitted_version, EolStatus, Runtime, RuntimeVersion};
    use chrono::NaiveDate;

    fn version(major: u32, minor: Option<u32>) -> RuntimeVersion {
        RuntimeVersion { major, minor }
    }

    fn day(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn runtime_eol_tables_match_official_schedules() {
        let schedules = [
            // https://raw.githubusercontent.com/nodejs/Release/main/schedule.json (`end`)
            (
                Runtime::Node,
                [
                    (16, 0, "2023-09-11"),
                    (17, 0, "2022-06-01"),
                    (18, 0, "2025-04-30"),
                    (19, 0, "2023-06-01"),
                    (20, 0, "2026-04-30"),
                    (21, 0, "2024-06-01"),
                    (22, 0, "2027-04-30"),
                    (23, 0, "2025-06-01"),
                    (24, 0, "2028-04-30"),
                    (25, 0, "2026-06-01"),
                ]
                .as_slice(),
            ),
            // https://devguide.python.org/versions/ (3.11 publishes only a month)
            (
                Runtime::Python,
                [
                    (3, 7, "2023-06-27"),
                    (3, 8, "2024-10-07"),
                    (3, 9, "2025-10-31"),
                    (3, 10, "2026-10-01"),
                    (3, 11, "2027-10"),
                ]
                .as_slice(),
            ),
            // https://www.php.net/eol.php (8.0, 8.1)
            // https://www.php.net/supported-versions.php (8.2, 8.3 security support)
            (
                Runtime::Php,
                [
                    (8, 0, "2023-11-26"),
                    (8, 1, "2025-12-31"),
                    (8, 2, "2026-12-31"),
                    (8, 3, "2027-12-31"),
                ]
                .as_slice(),
            ),
        ];
        let mut mismatches = Vec::new();
        for (runtime, expected) in schedules {
            let actual = runtime.eol_table();
            assert_eq!(actual.len(), expected.len(), "{runtime:?} row count");
            for (entry, &(major, minor, eol)) in actual.iter().zip(expected) {
                let actual_eol = if eol.len() == 7 {
                    entry.eol.get(..7)
                } else {
                    Some(entry.eol)
                };
                if (entry.major, entry.minor, actual_eol) != (major, minor, Some(eol)) {
                    mismatches.push(format!(
                        "{runtime:?} {major}.{minor}: expected {eol}, got {}",
                        entry.eol
                    ));
                }
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn runtime_eol_range_minimum_resolution() {
        // Lower-bound comparators resolve to the version they admit.
        assert_eq!(minimum_admitted_version(">=18"), Some(version(18, None)));
        assert_eq!(
            minimum_admitted_version("^18.17.0"),
            Some(version(18, Some(17)))
        );
        assert_eq!(minimum_admitted_version("18.x"), Some(version(18, None)));
        assert_eq!(
            minimum_admitted_version("v20.11.1"),
            Some(version(20, Some(11)))
        );
        // Upper bounds never contribute; the branch minimum survives.
        assert_eq!(
            minimum_admitted_version(">=18 <21"),
            Some(version(18, None))
        );
        assert_eq!(
            minimum_admitted_version(">=3.8,<3.13"),
            Some(version(3, Some(8)))
        );
        // OR branches take the smallest branch minimum (npm and composer forms).
        assert_eq!(
            minimum_admitted_version("16 || >=18"),
            Some(version(16, None))
        );
        assert_eq!(
            minimum_admitted_version(">=7.4|>=8.0"),
            Some(version(7, Some(4)))
        );
        // Hyphen ranges admit their left edge.
        assert_eq!(minimum_admitted_version("16 - 18"), Some(version(16, None)));
        // AND-ed lower bounds take the tightest one.
        assert_eq!(
            minimum_admitted_version(">=18 >=20"),
            Some(version(20, None))
        );
        // No determinable lower bound means no verdict.
        assert_eq!(minimum_admitted_version("*"), None);
        assert_eq!(minimum_admitted_version("<21"), None);
        assert_eq!(minimum_admitted_version("lts/hydrogen"), None);
    }

    #[test]
    fn runtime_eol_status_respects_dates_and_table_bounds() {
        let today = day("2026-07-04");

        // Node 18 (EOL 2025-04-30) is past end of life; Node 24 is not.
        assert!(matches!(
            eol_status(Runtime::Node, version(18, None), today),
            Some(EolStatus::PastEol(entry)) if entry.major == 18
        ));
        assert!(eol_status(Runtime::Node, version(24, None), today).is_none());
        // Strictly after the date: the EOL day itself does not fire yet.
        assert!(eol_status(Runtime::Node, version(20, None), day("2026-04-30")).is_none());
        assert!(eol_status(Runtime::Node, version(20, None), day("2026-05-01")).is_some());
        // Versions older than the oldest tracked line are end of life.
        assert!(matches!(
            eol_status(Runtime::Node, version(14, None), today),
            Some(EolStatus::PredatesTable(oldest)) if oldest.major == 16
        ));
        // Versions newer than the table have no verdict.
        assert!(eol_status(Runtime::Node, version(26, None), today).is_none());
        // Odd, non-LTS Node majors are past end of life.
        for odd in [17, 19, 21, 23, 25] {
            assert!(
                matches!(
                    eol_status(Runtime::Node, version(odd, None), today),
                    Some(EolStatus::PastEol(entry)) if entry.major == odd
                ),
                "Node {odd} must be reported past end of life"
            );
        }

        // Python matches per minor line and needs a known minor.
        assert!(matches!(
            eol_status(Runtime::Python, version(3, Some(9)), today),
            Some(EolStatus::PastEol(entry)) if entry.minor == 9
        ));
        assert!(eol_status(Runtime::Python, version(3, Some(12)), today).is_none());
        assert!(eol_status(Runtime::Python, version(3, None), today).is_none());
        assert!(matches!(
            eol_status(Runtime::Python, version(2, Some(7)), today),
            Some(EolStatus::PredatesTable(_))
        ));

        // PHP 8.1 ended 2025-12-31; 7.4 predates the table; 8.4 is fine.
        assert!(matches!(
            eol_status(Runtime::Php, version(8, Some(1)), today),
            Some(EolStatus::PastEol(entry)) if entry.minor == 1
        ));
        assert!(matches!(
            eol_status(Runtime::Php, version(7, Some(4)), today),
            Some(EolStatus::PredatesTable(_))
        ));
        assert!(eol_status(Runtime::Php, version(8, Some(4)), today).is_none());
    }
}
