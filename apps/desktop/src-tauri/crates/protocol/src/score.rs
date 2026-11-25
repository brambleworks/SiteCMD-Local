//! Score results for display and storage.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::vocab::Category;

/// Confidence-weighted score deductions and effective counts by severity.
/// This is produced with the score to prevent UI reimplementation or drift;
/// the exploitable cap remains on `ScoreSnapshot`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreBreakdown {
    /// The starting score every deduction is subtracted from (always 100.0).
    pub base: f64,
    /// Points lost to the critical tier (confidence-weighted).
    pub critical_points: f64,
    /// Points lost to the high tier.
    pub high_points: f64,
    /// Points lost to the medium tier.
    pub medium_points: f64,
    /// Points lost to the low tier.
    pub low_points: f64,
    /// Confidence-weighted effective critical count the deduction used.
    pub eff_critical: f64,
    /// Confidence-weighted effective high count.
    pub eff_high: f64,
    /// Confidence-weighted effective medium count.
    pub eff_medium: f64,
    /// Confidence-weighted effective low count.
    pub eff_low: f64,
    /// Whether the protective floor raised the final score.
    pub floor_applied: bool,
    /// Whether the open-issue ceiling lowered the final score.
    pub ceiling_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreSnapshot {
    pub overall: f64,
    pub per_category: HashMap<String, f64>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    /// Whether an active finding met the mechanical critical-score cap gates.
    #[serde(default)]
    pub exploitable_capped: bool,
    /// Points lost per tier, defaulted so older persisted payloads deserialize.
    #[serde(default)]
    pub breakdown: ScoreBreakdown,
    pub computed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: Category,
    pub score: u32,
    pub issues_total: u32,
    pub issues_critical: u32,
    pub issues_high: u32,
    pub issues_medium: u32,
    pub issues_low: u32,
    pub issues_passed: u32,
}
