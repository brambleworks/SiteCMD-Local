use serde::{Deserialize, Serialize};

/// Which package ecosystem a dependency belongs to
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Composer,
    WordPress,
    Drupal,
    Python,
    Ruby,
    Go,
    Rust,
}

impl Ecosystem {
    /// Human-readable label
    pub fn label(&self) -> &str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Composer => "Composer",
            Ecosystem::WordPress => "WordPress",
            Ecosystem::Drupal => "Drupal",
            Ecosystem::Python => "Python",
            Ecosystem::Ruby => "Ruby",
            Ecosystem::Go => "Go",
            Ecosystem::Rust => "Rust",
        }
    }
}

/// A package found in a local project directory
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub source: String,
    pub is_dev: bool,
    /// Declaring workspace paths; `.` is the root and empty means single-package.
    #[serde(default)]
    pub workspace_members: Vec<String>,
}

/// What kind of version bump an update represents
impl Default for InstalledPackage {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: String::new(),
            ecosystem: Ecosystem::Npm,
            source: String::new(),
            is_dev: false,
            workspace_members: Vec::new(),
        }
    }
}
