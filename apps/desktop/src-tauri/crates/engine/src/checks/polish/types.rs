//! Shared Polish Scan signal types.

use serde::{Deserialize, Serialize};

/// Base-point weight for a polish signal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SignalWeight {
    High,
    Medium,
    LowMedium,
    Low,
}

impl SignalWeight {
    /// Base point value for this weight tier.
    pub fn points(self) -> u32 {
        match self {
            SignalWeight::High => 15,
            SignalWeight::Medium => 8,
            SignalWeight::LowMedium => 5,
            SignalWeight::Low => 3,
        }
    }
}

/// Signal category - groups related signals for scoring bonuses.
///
/// When 3+ signals fire in the same category, a 1.25x multiplier applies
/// to that category's contribution. This rewards detection confidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    CssArchitecture,
    HtmlQuality,
    AiAesthetic,
    CopyContent,
    MetaInfrastructure,
    FrameworkDefaults,
}

/// Result from a single polish signal evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolishResult {
    /// Unique signal identifier (e.g. "inline-style-density")
    pub id: String,
    /// Human-readable signal name
    pub name: String,
    /// Whether this signal was detected / triggered
    pub fired: bool,
    /// Weight tier
    pub weight: SignalWeight,
    /// Points contributed (0 if not fired)
    pub points: u32,
    /// Which category this signal belongs to
    pub category: SignalCategory,
    /// One-line description of what was found (or "not detected")
    pub detail: String,
    /// Structured detection data for UI display
    pub data: serde_json::Value,
}

impl PolishResult {
    /// Convenience constructor for a signal that fired.
    pub fn fired(
        id: &str,
        name: &str,
        weight: SignalWeight,
        category: SignalCategory,
        detail: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            fired: true,
            weight,
            points: weight.points(),
            category,
            detail,
            data,
        }
    }

    /// Convenience constructor for a signal that did not fire.
    pub fn clear(id: &str, name: &str, weight: SignalWeight, category: SignalCategory) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            fired: false,
            weight,
            points: 0,
            category,
            detail: "Not detected".to_string(),
            data: serde_json::Value::Null,
        }
    }
}
