//! Shared scan vocabulary for desktop, CLI, and hosted runtimes.

use serde::{Deserialize, Serialize};

/// Web Scan category filter serialized into `scans.scan_type` and `web_focus`.
/// This differs from the `web | code` subsystem discriminator used by events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    #[default]
    Health,
    Security,
    Accessibility,
    Polish,
}

impl ScanType {
    pub const ALL: [ScanType; 4] = [
        ScanType::Health,
        ScanType::Security,
        ScanType::Accessibility,
        ScanType::Polish,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ScanType::Health => "health",
            ScanType::Security => "security",
            ScanType::Accessibility => "accessibility",
            ScanType::Polish => "polish",
        }
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ScanType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ScanType::ALL
            .into_iter()
            .find(|scan_type| scan_type.as_str() == value)
            .ok_or_else(|| format!("unknown ScanType: {}", value))
    }
}

/// Status of an individual check
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    #[serde(rename = "not_applicable")]
    NotApplicable,
    Fail,
    Warn,
    Skipped,
}

/// Closed explanation for a verdict or a check that could not apply.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResultReason {
    Missing,
    Unreadable,
    Invalid,
    Expired,
    LegacyLocation,
    LongExpiry,
    ParserLimit,
    NotApplicable,
    Unavailable,
}

impl CheckStatus {
    /// Failures and warnings rank by severity, with failures first at equal severity.
    pub fn fix_priority(self, severity: Severity) -> Option<(u8, bool)> {
        match self {
            Self::Fail | Self::Warn => Some((severity.sort_rank(), self == Self::Warn)),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::NotApplicable => "not_applicable",
            Self::Fail => "fail",
            Self::Warn => "warn",
            Self::Skipped => "skipped",
        }
    }
}

impl std::str::FromStr for CheckStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pass" => Ok(Self::Pass),
            "not_applicable" => Ok(Self::NotApplicable),
            "fail" => Ok(Self::Fail),
            "warn" => Ok(Self::Warn),
            "skipped" => Ok(Self::Skipped),
            _ => Err(format!("unknown CheckStatus: {}", s)),
        }
    }
}

/// Why a check could not reach a verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Blocked,
    Unreachable,
    Declined,
    Inconclusive,
}

/// Issue severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    /// Declaration order = severity order (most severe first).
    pub const ALL: [Self; 4] = [Self::Critical, Self::High, Self::Medium, Self::Low];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    pub fn sort_rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }

    pub fn impact_rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    pub fn impact_rank_for_label(value: &str) -> u8 {
        value.parse::<Self>().map(Self::impact_rank).unwrap_or(0)
    }

    pub fn sort_rank_for_label(value: &str) -> u8 {
        value.parse::<Self>().map(Self::sort_rank).unwrap_or(4)
    }

    pub fn label_for_impact_rank(rank: u8) -> &'static str {
        match rank {
            4 => Self::Critical.as_str(),
            3 => Self::High.as_str(),
            2 => Self::Medium.as_str(),
            _ => Self::Low.as_str(),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            _ => Err(format!("unknown Severity: {}", s)),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How certain SiteCMD is that the reported condition was observed or
/// reliably inferred. Confidence grades the evidence, not whether the same
/// remediation is appropriate in every project context.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssueConfidence {
    Confirmed,
    #[default]
    High,
    NeedsReview,
}

impl IssueConfidence {
    /// Stable column/wire form; matches the serde snake_case spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::High => "high",
            Self::NeedsReview => "needs_review",
        }
    }
}

impl std::str::FromStr for IssueConfidence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "confirmed" => Ok(Self::Confirmed),
            "high" => Ok(Self::High),
            "needs_review" => Ok(Self::NeedsReview),
            _ => Err(format!("unknown IssueConfidence: {}", s)),
        }
    }
}

/// The product category of a finding, independent of its scan source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Security,
    DomainHttps,
    Email,
    Seo,
    AiVisibility,
    Performance,
    Accessibility,
    Privacy,
    Polish,
    Reliability,
}

impl Category {
    /// Canonical order for menus, filters, reports and score bars.
    pub const ALL: [Self; 10] = [
        Self::Security,
        Self::DomainHttps,
        Self::Email,
        Self::Seo,
        Self::AiVisibility,
        Self::Performance,
        Self::Accessibility,
        Self::Privacy,
        Self::Polish,
        Self::Reliability,
    ];

    /// Stable wire key accepted by category options.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::DomainHttps => "domain_https",
            Self::Email => "email",
            Self::Seo => "seo",
            Self::AiVisibility => "ai_visibility",
            Self::Performance => "performance",
            Self::Accessibility => "accessibility",
            Self::Privacy => "privacy",
            Self::Polish => "polish",
            Self::Reliability => "reliability",
        }
    }

    /// The display label shared by all product surfaces.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Security => "Security",
            Self::DomainHttps => "Domain and HTTPS",
            Self::Email => "Email",
            Self::Seo => "SEO",
            Self::AiVisibility => "AI visibility",
            Self::Performance => "Performance",
            Self::Accessibility => "Accessibility",
            Self::Privacy => "Privacy and policies",
            Self::Polish => "Polish",
            Self::Reliability => "Reliability",
        }
    }
}

impl std::str::FromStr for Category {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|category| category.key() == value)
            .ok_or_else(|| format!("Unknown category: {value}"))
    }
}

/// Result from a single check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub check_id: String,
    /// The engine's category table resolves this from `check_id`; checks never stamp it.
    #[serde(default)]
    pub category: Option<Category>,
    pub title: String,
    pub description: String,
    pub status: CheckStatus,
    #[serde(
        default,
        alias = "skip_reason",
        skip_serializing_if = "Option::is_none"
    )]
    pub skip_reason: Option<SkipReason>,
    /// The same finding is reported by an actionable detail on this route.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub covered: bool,
    pub severity: Severity,
    pub fix_prompt: Option<String>,
    pub manual_fix: Option<String>,
    pub raw_data: Option<serde_json::Value>,
    #[serde(default)]
    pub confidence: IssueConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_reason: Option<String>,
    /// One-line business impact statement for critical/high issues.
    /// Answers "what breaks if I ignore this?"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_it_matters: Option<String>,
}

impl CheckResult {
    /// A skip reason is present exactly when the check could not run.
    pub fn is_well_formed(&self) -> bool {
        self.skip_reason.is_some() == (self.status == CheckStatus::Skipped)
    }
}

/// The single lifecycle-status vocabulary for unified issues.
///
/// Serialized into the constrained issue-state column and generated IPC types.
/// Every scorer uses `is_inactive_for_scoring` as its active-set predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueStatus {
    New,
    Snoozed,
    Ignored,
    Blocked,
    Verified,
    Regressed,
}

impl IssueStatus {
    pub const ALL: [IssueStatus; 6] = [
        IssueStatus::New,
        IssueStatus::Snoozed,
        IssueStatus::Ignored,
        IssueStatus::Blocked,
        IssueStatus::Verified,
        IssueStatus::Regressed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            IssueStatus::New => "new",
            IssueStatus::Snoozed => "snoozed",
            IssueStatus::Ignored => "ignored",
            IssueStatus::Blocked => "blocked",
            IssueStatus::Verified => "verified",
            IssueStatus::Regressed => "regressed",
        }
    }

    /// Statuses that remove an issue from the active list and the score.
    /// `Regressed` stays active: a verified issue that re-failed must count
    /// again. Mirrored by the MCP server's DISMISSED_STATUSES (guardrail-pinned)
    /// and the frontend's active-issue filter (generated-manifest-pinned).
    pub fn is_inactive_for_scoring(self) -> bool {
        matches!(
            self,
            IssueStatus::Snoozed
                | IssueStatus::Ignored
                | IssueStatus::Blocked
                | IssueStatus::Verified
        )
    }

    /// Resolve expired snoozes back to `New` at `now_ms`.
    pub fn effective(self, snooze_until: Option<i64>, now_ms: i64) -> IssueStatus {
        if self == IssueStatus::Snoozed && snooze_until.is_some_and(|until| until <= now_ms) {
            IssueStatus::New
        } else {
            self
        }
    }
}

impl std::fmt::Display for IssueStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IssueStatus {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        IssueStatus::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
            .ok_or_else(|| format!("unknown IssueStatus: {}", value))
    }
}

/// Evidence source for a verified lifecycle row.
/// User claims remain distinct from scan-observed absence in local and
/// connected lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedBy {
    /// The user said the issue was fixed. Nothing looked.
    UserClaim,
    /// A local scan re-ran the check and stopped reporting the issue.
    LocalScan,
}

impl VerifiedBy {
    pub const ALL: [VerifiedBy; 2] = [VerifiedBy::UserClaim, VerifiedBy::LocalScan];

    pub fn as_str(self) -> &'static str {
        match self {
            VerifiedBy::UserClaim => "user_claim",
            VerifiedBy::LocalScan => "local_scan",
        }
    }

    /// Whether observation proved the issue absent. Only observed absence may
    /// make a later recurrence a regression.
    pub fn proves_absence(self) -> bool {
        matches!(self, VerifiedBy::LocalScan)
    }
}

impl std::fmt::Display for VerifiedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for VerifiedBy {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        VerifiedBy::ALL
            .into_iter()
            .find(|verified_by| verified_by.as_str() == value)
            .ok_or_else(|| format!("unknown VerifiedBy: {}", value))
    }
}

/// The unit published by a measurement-class check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementUnit {
    #[serde(rename = "ms")]
    Milliseconds,
    Ratio,
}

impl MeasurementUnit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Milliseconds => "ms",
            Self::Ratio => "ratio",
        }
    }
}

#[cfg(test)]
mod check_status_tests {
    use super::{CheckResult, CheckStatus, SkipReason};

    #[test]
    fn not_applicable_round_trips() {
        // Not-applicable statuses must retain their canonical wire spelling.
        assert_eq!(
            serde_json::to_string(&CheckStatus::NotApplicable).unwrap(),
            "\"not_applicable\""
        );
        assert_eq!(
            "not_applicable".parse::<CheckStatus>(),
            Ok(CheckStatus::NotApplicable)
        );
        assert_eq!(CheckStatus::NotApplicable.as_str(), "not_applicable");
        assert_eq!(
            serde_json::from_str::<CheckStatus>("\"not_applicable\"").unwrap(),
            CheckStatus::NotApplicable
        );
    }

    #[test]
    fn skip_reasons_round_trip_in_snake_case() {
        // Skip reasons must preserve the closed wire vocabulary.
        for (reason, spelling) in [
            (SkipReason::Blocked, "blocked"),
            (SkipReason::Unreachable, "unreachable"),
            (SkipReason::Declined, "declined"),
            (SkipReason::Inconclusive, "inconclusive"),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), spelling);
            assert_eq!(
                serde_json::from_value::<SkipReason>(spelling.into()).unwrap(),
                reason
            );
        }
    }

    #[test]
    fn skip_reason_is_present_exactly_for_skipped_results() {
        // Missing skip reasons and reasons on completed verdicts must be rejected.
        let mut result: CheckResult = serde_json::from_value(serde_json::json!({
            "checkId": "security.csp", "category": "security",
            "title": "CSP", "description": "CSP result", "status": "pass",
            "severity": "low"
        }))
        .unwrap();
        assert_eq!(result.skip_reason, None);
        assert!(serde_json::to_value(&result)
            .unwrap()
            .get("skipReason")
            .is_none());
        for status in [
            CheckStatus::Pass,
            CheckStatus::NotApplicable,
            CheckStatus::Fail,
            CheckStatus::Warn,
            CheckStatus::Skipped,
        ] {
            result.status = status;
            result.skip_reason = None;
            assert_eq!(result.is_well_formed(), status != CheckStatus::Skipped);
            for reason in [
                SkipReason::Blocked,
                SkipReason::Unreachable,
                SkipReason::Declined,
                SkipReason::Inconclusive,
            ] {
                result.skip_reason = Some(reason);
                assert_eq!(result.is_well_formed(), status == CheckStatus::Skipped);
                let wire = serde_json::to_value(&result).unwrap();
                assert_eq!(wire["skipReason"], serde_json::to_value(reason).unwrap());
                assert_eq!(
                    serde_json::from_value::<CheckResult>(wire)
                        .unwrap()
                        .skip_reason,
                    Some(reason)
                );
            }
        }
    }
}

#[cfg(test)]
mod severity_tests {
    use super::Severity;

    #[test]
    fn severity_string_helpers_are_canonical() {
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::High.label(), "High");
        assert!(Severity::Critical.sort_rank() < Severity::High.sort_rank());
        assert!(Severity::Critical.impact_rank() > Severity::High.impact_rank());
        assert_eq!(Severity::impact_rank_for_label("critical"), 4);
        assert_eq!(Severity::sort_rank_for_label("critical"), 0);
        assert_eq!(Severity::sort_rank_for_label("unknown"), 4);
        assert_eq!(Severity::label_for_impact_rank(3), "high");
    }
}

#[cfg(test)]
mod category_tests {
    use super::Category;

    #[test]
    fn the_list_is_the_ten_categories_in_order() {
        // A category is added, dropped, renamed or reordered.
        assert_eq!(
            Category::ALL.map(Category::key),
            [
                "security",
                "domain_https",
                "email",
                "seo",
                "ai_visibility",
                "performance",
                "accessibility",
                "privacy",
                "polish",
                "reliability"
            ]
        );
        assert_eq!(
            Category::ALL.map(Category::label),
            [
                "Security",
                "Domain and HTTPS",
                "Email",
                "SEO",
                "AI visibility",
                "Performance",
                "Accessibility",
                "Privacy and policies",
                "Polish",
                "Reliability"
            ]
        );
    }

    #[test]
    fn keys_round_trip_and_old_words_are_refused() {
        // An old word or loose spelling is accepted as a category key.
        for c in Category::ALL {
            assert_eq!(c.key().parse::<Category>(), Ok(c));
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.key())
            );
            assert_eq!(
                serde_json::from_str::<Category>(&format!("\"{}\"", c.key())).unwrap(),
                c
            );
        }
        for word in [
            "compliance",
            "config",
            "code_quality",
            "Security",
            "domain-https",
            "uptime",
            "health",
            "",
            " seo",
            "seo ",
        ] {
            assert!(word.parse::<Category>().is_err(), "{word}");
            assert!(
                serde_json::from_str::<Category>(&format!("\"{word}\"")).is_err(),
                "{word}"
            );
        }
    }
}

#[cfg(test)]
mod scan_type_tests {
    use super::ScanType;

    #[test]
    fn scan_type_wire_names_are_unchanged() {
        // A wire label that changes when it leaves the engine.
        assert_eq!(
            ScanType::ALL.map(ScanType::as_str),
            ["health", "security", "accessibility", "polish"]
        );
        let polish = serde_json::from_str::<ScanType>(r#""polish""#).unwrap();
        assert_eq!(polish, ScanType::Polish);
        assert_eq!(serde_json::to_string(&polish).unwrap(), r#""polish""#);
    }
}
