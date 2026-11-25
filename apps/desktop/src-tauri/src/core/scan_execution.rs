//! Top-level scan intent, admission, and retry identity.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::core::scan_types::ScanType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanExecutionMode {
    Full,
    Web,
    Code,
}

impl ScanExecutionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Web => "web",
            Self::Code => "code",
        }
    }
}

impl fmt::Display for ScanExecutionMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ScanExecutionMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "full" => Ok(Self::Full),
            "web" => Ok(Self::Web),
            "code" => Ok(Self::Code),
            other => Err(format!("unknown scan execution mode: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTrigger {
    Manual,
    Tray,
    Scheduled,
    Verification,
    Background,
    Migration,
}

impl ScanTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Tray => "tray",
            Self::Scheduled => "scheduled",
            Self::Verification => "verification",
            Self::Background => "background",
            Self::Migration => "migration",
        }
    }
}

impl FromStr for ScanTrigger {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "manual" => Ok(Self::Manual),
            "tray" => Ok(Self::Tray),
            "scheduled" => Ok(Self::Scheduled),
            "verification" => Ok(Self::Verification),
            "background" => Ok(Self::Background),
            "migration" => Ok(Self::Migration),
            other => Err(format!("unknown scan trigger: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanAdmissionClass {
    GeneralScan,
    BoundedVerification,
    SystemExempt,
}

impl ScanAdmissionClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeneralScan => "general_scan",
            Self::BoundedVerification => "bounded_verification",
            Self::SystemExempt => "system_exempt",
        }
    }
}

impl FromStr for ScanAdmissionClass {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "general_scan" => Ok(Self::GeneralScan),
            "bounded_verification" => Ok(Self::BoundedVerification),
            "system_exempt" => Ok(Self::SystemExempt),
            other => Err(format!("unknown scan admission class: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanExecutionStatus {
    Planned,
    Running,
    Complete,
    Partial,
    Failed,
    Cancelled,
}

impl ScanExecutionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Partial | Self::Failed | Self::Cancelled
        )
    }
}

impl FromStr for ScanExecutionStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "planned" => Ok(Self::Planned),
            "running" => Ok(Self::Running),
            "complete" => Ok(Self::Complete),
            "partial" => Ok(Self::Partial),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("unknown scan execution status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanComponentStatus {
    Planned,
    Running,
    Complete,
    Failed,
    Cancelled,
    Skipped,
}

impl ScanComponentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
        }
    }

    pub const fn is_unsettled(self) -> bool {
        matches!(self, Self::Planned | Self::Running)
    }
}

impl FromStr for ScanComponentStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "planned" => Ok(Self::Planned),
            "running" => Ok(Self::Running),
            "complete" => Ok(Self::Complete),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "skipped" => Ok(Self::Skipped),
            other => Err(format!("unknown scan component status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanExecutionRecord {
    pub id: i64,
    pub project_id: Option<i64>,
    pub environment_id: Option<i64>,
    pub environment_url: Option<String>,
    pub environment_scope_key: String,
    pub requested_mode: ScanExecutionMode,
    pub web_focus: Option<ScanType>,
    pub trigger: ScanTrigger,
    pub admission_class: ScanAdmissionClass,
    pub status: ScanExecutionStatus,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub score_snapshot_id: Option<i64>,
    pub failure_summary: Option<String>,
    pub web_status: Option<ScanComponentStatus>,
    pub web_detail: Option<String>,
    pub code_status: Option<ScanComponentStatus>,
    pub code_detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewScanExecution {
    pub project_id: Option<i64>,
    pub environment_id: Option<i64>,
    pub environment_url: Option<String>,
    pub environment_scope_key: String,
    pub requested_mode: ScanExecutionMode,
    pub web_focus: Option<ScanType>,
    pub trigger: ScanTrigger,
    pub admission_class: ScanAdmissionClass,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub now_ms: i64,
    pub web_status: Option<ScanComponentStatus>,
    pub web_detail: Option<String>,
    pub code_status: Option<ScanComponentStatus>,
    pub code_detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanAdmissionOutcome {
    pub execution: ScanExecutionRecord,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScanAdmissionError {
    #[error("scan action key was already used for a different request")]
    IdempotencyConflict,
    #[error("scan action key is outside the supported retry window; start a new action")]
    IdempotencyStale,
    #[error("invalid scan execution request: {0}")]
    InvalidRequest(String),
    #[error("scan admission storage failed: {0}")]
    Storage(String),
}
