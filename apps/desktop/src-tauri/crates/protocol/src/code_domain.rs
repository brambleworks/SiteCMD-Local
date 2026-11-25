//! The domain labels carried by source scan findings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum CodeScanDomain {
    Database,
    AiSafety,
    Security,
    Architecture,
    Operations,
    SupplyChain,
    AiScaffolding,
}

impl CodeScanDomain {
    /// Stable wire and display value. Must remain log-free because `Display`
    /// can run while the logger holds a non-reentrant writer lock.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::AiSafety => "ai-safety",
            Self::Security => "security",
            Self::Architecture => "architecture",
            Self::Operations => "operations",
            Self::SupplyChain => "supply-chain",
            Self::AiScaffolding => "ai-scaffolding",
        }
    }
}

impl std::fmt::Display for CodeScanDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CodeScanDomain {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "database" => Ok(Self::Database),
            "ai-safety" => Ok(Self::AiSafety),
            "security" => Ok(Self::Security),
            "architecture" => Ok(Self::Architecture),
            "operations" => Ok(Self::Operations),
            "supply-chain" => Ok(Self::SupplyChain),
            "ai-scaffolding" => Ok(Self::AiScaffolding),
            _ => Err(format!("Unknown code scan domain: {}", value)),
        }
    }
}
