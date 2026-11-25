//! Standalone serialization for check and score types shared with Connect.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::score::{CategoryScore, ScoreBreakdown, ScoreSnapshot};
use crate::vocab::{Category, CheckResult, CheckStatus, IssueConfidence, Severity, SkipReason};

#[derive(Serialize, Deserialize)]
#[serde(remote = "CheckResult", deny_unknown_fields)]
struct CheckResultWire {
    check_id: String,
    category: Option<Category>,
    title: String,
    description: String,
    status: CheckStatus,
    skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    covered: bool,
    severity: Severity,
    fix_prompt: Option<String>,
    manual_fix: Option<String>,
    raw_data: Option<serde_json::Value>,
    confidence: IssueConfidence,
    confidence_reason: Option<String>,
    why_it_matters: Option<String>,
}

pub(super) mod check_results {
    use serde::{Deserializer, Serializer};

    use super::{CheckResult, CheckResultWire, Deserialize, Serialize};

    #[derive(Serialize)]
    struct ResultRef<'a>(#[serde(with = "CheckResultWire")] &'a CheckResult);

    #[derive(Deserialize)]
    struct ResultValue(#[serde(with = "CheckResultWire")] CheckResult);

    pub(in crate::engine_abi) fn serialize<S: Serializer>(
        results: &[CheckResult],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(results.iter().map(ResultRef))
    }

    pub(in crate::engine_abi) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<CheckResult>, D::Error> {
        let values = Vec::<ResultValue>::deserialize(deserializer)?;
        Ok(values.into_iter().map(|value| value.0).collect())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ScoreBreakdown", deny_unknown_fields)]
struct ScoreBreakdownWire {
    base: f64,
    critical_points: f64,
    high_points: f64,
    medium_points: f64,
    low_points: f64,
    eff_critical: f64,
    eff_high: f64,
    eff_medium: f64,
    eff_low: f64,
    floor_applied: bool,
    ceiling_applied: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ScoreSnapshot", deny_unknown_fields)]
pub(super) struct ScoreSnapshotWire {
    overall: f64,
    per_category: HashMap<String, f64>,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    exploitable_capped: bool,
    #[serde(with = "ScoreBreakdownWire")]
    breakdown: ScoreBreakdown,
    computed_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "CategoryScore", deny_unknown_fields)]
struct CategoryScoreWire {
    category: Category,
    score: u32,
    issues_total: u32,
    issues_critical: u32,
    issues_high: u32,
    issues_medium: u32,
    issues_low: u32,
    issues_passed: u32,
}

pub(super) mod category_scores {
    use serde::{Deserializer, Serializer};

    use super::{CategoryScore, CategoryScoreWire, Deserialize, Serialize};

    #[derive(Serialize)]
    struct ScoreRef<'a>(#[serde(with = "CategoryScoreWire")] &'a CategoryScore);

    #[derive(Deserialize)]
    struct ScoreValue(#[serde(with = "CategoryScoreWire")] CategoryScore);

    pub(in crate::engine_abi) fn serialize<S: Serializer>(
        scores: &Option<Vec<CategoryScore>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        scores
            .as_ref()
            .map(|rows| rows.iter().map(ScoreRef).collect::<Vec<_>>())
            .serialize(serializer)
    }

    pub(in crate::engine_abi) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<CategoryScore>>, D::Error> {
        let rows = Option::<Vec<ScoreValue>>::deserialize(deserializer)?;
        Ok(rows.map(|rows| rows.into_iter().map(|row| row.0).collect()))
    }
}
