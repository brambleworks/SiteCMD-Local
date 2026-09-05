//! External service clients and credential-safe integration types.

pub mod bing;
pub mod cloudflare;
pub mod github;
pub mod github_issues;
pub mod github_oauth;
pub mod google_analytics;
pub mod google_oauth;
pub mod issue_tracker;
pub mod jira;
pub mod pagespeed;
pub mod plausible;
pub mod search_console;
pub mod uptimerobot;
pub mod validation;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Types of integrations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum IntegrationType {
    Plausible,
    Cloudflare,
    UptimeRobot,
    GoogleAnalytics,
    GoogleSearchConsole,
    BingWebmaster,
    GitHub,
    Jira,
}

impl std::str::FromStr for IntegrationType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plausible" => Ok(Self::Plausible),
            "cloudflare" => Ok(Self::Cloudflare),
            "uptimerobot" => Ok(Self::UptimeRobot),
            "googleanalytics" => Ok(Self::GoogleAnalytics),
            "googlesearchconsole" => Ok(Self::GoogleSearchConsole),
            "bingwebmaster" => Ok(Self::BingWebmaster),
            "github" => Ok(Self::GitHub),
            "jira" => Ok(Self::Jira),
            other => Err(format!("unknown integration type: {}", other)),
        }
    }
}

impl IntegrationType {
    /// Human display name for confirmation-dialog copy and toasts, kept in sync
    /// with the frontend service `name` fields in `integration-services.ts`.
    pub fn display_name(&self) -> &'static str {
        match self {
            IntegrationType::Plausible => "Plausible Analytics",
            IntegrationType::Cloudflare => "Cloudflare",
            IntegrationType::UptimeRobot => "UptimeRobot",
            IntegrationType::GoogleAnalytics => "Google Analytics (GA4)",
            IntegrationType::GoogleSearchConsole => "Google Search Console",
            IntegrationType::BingWebmaster => "Bing Webmaster Tools",
            IntegrationType::GitHub => "GitHub",
            IntegrationType::Jira => "Jira",
        }
    }
}

/// Integration config stored per project
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct IntegrationConfig {
    pub integration_type: IntegrationType,
    pub api_key: Option<String>,
    pub site_id: Option<String>, // Plausible site ID, Cloudflare zone ID, etc.
    #[ts(type = "unknown")]
    pub extra: Option<serde_json::Value>, // Additional config (OAuth tokens, etc.)
    pub enabled: bool,
}

/// Common response for integration data
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct IntegrationData {
    pub integration_type: IntegrationType,
    #[ts(type = "unknown")]
    pub data: serde_json::Value,
    pub fetched_at: String,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::IntegrationType;

    #[test]
    fn display_name_covers_every_type_and_round_trips_from_the_stored_token() {
        // The stored token (as parsed by FromStr) must resolve to a human name
        // so the disconnect confirmation never shows the bare type id.
        let cases = [
            ("plausible", "Plausible Analytics"),
            ("cloudflare", "Cloudflare"),
            ("uptimerobot", "UptimeRobot"),
            ("googleanalytics", "Google Analytics (GA4)"),
            ("googlesearchconsole", "Google Search Console"),
            ("bingwebmaster", "Bing Webmaster Tools"),
            ("github", "GitHub"),
            ("jira", "Jira"),
        ];
        for (token, expected) in cases {
            let itype: IntegrationType = token.parse().expect("known token parses");
            assert_eq!(itype.display_name(), expected, "token {token}");
        }
    }
}
