//! Technology stack wire data.

use serde::{Deserialize, Serialize};

/// Technology stack detected from headers and HTML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectedStack {
    /// Web server (nginx, apache, cloudflare, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Server-side framework or runtime (express, php, asp.net, next.js, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// CMS (wordpress, drupal, shopify, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cms: Option<String>,
    /// Frontend JS framework (react, vue, angular, svelte, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub js_framework: Option<String>,
    /// CSS framework (tailwind, bootstrap, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub css_framework: Option<String>,
    /// CDN / hosting platform
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdn: Option<String>,
    /// The platform that serves the site, where an answer names it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosting: Option<String>,
    /// Whose nameservers answer for the site's domain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_provider: Option<String>,
    /// Additional detected technologies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other: Vec<String>,
}

impl DetectedStack {
    pub fn is_empty(&self) -> bool {
        self.server.is_none()
            && self.framework.is_none()
            && self.cms.is_none()
            && self.js_framework.is_none()
            && self.css_framework.is_none()
            && self.cdn.is_none()
            && self.hosting.is_none()
            && self.dns_provider.is_none()
            && self.other.is_empty()
    }

    /// Convert to a flat map for display and JSON serialization
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Human-readable summary for AI prompts
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref s) = self.server {
            parts.push(format!("Server: {}", s));
        }
        if let Some(ref f) = self.framework {
            parts.push(format!("Framework: {}", f));
        }
        if let Some(ref c) = self.cms {
            parts.push(format!("CMS: {}", c));
        }
        if let Some(ref j) = self.js_framework {
            parts.push(format!("JS: {}", j));
        }
        if let Some(ref c) = self.css_framework {
            parts.push(format!("CSS: {}", c));
        }
        if let Some(ref c) = self.cdn {
            parts.push(format!("CDN/Hosting: {}", c));
        }
        if let Some(ref h) = self.hosting {
            parts.push(format!("Hosting: {}", h));
        }
        if let Some(ref d) = self.dns_provider {
            parts.push(format!("DNS: {}", d));
        }
        for o in &self.other {
            parts.push(o.clone());
        }
        if parts.is_empty() {
            "Unknown".into()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DetectedStack;

    #[test]
    fn detected_stack_omits_empty_fields() {
        // A wire label that changes when it leaves the engine.
        let stack = DetectedStack {
            framework: Some("next.js".into()),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&stack).unwrap(),
            r#"{"framework":"next.js"}"#
        );
    }

    #[test]
    fn detected_stack_serializes_all_nine_wire_fields() {
        // A stack field can change its wire name or disappear from JSON.
        let stack = DetectedStack {
            server: Some("nginx".into()),
            framework: Some("next.js".into()),
            cms: Some("wordpress".into()),
            js_framework: Some("react".into()),
            css_framework: Some("tailwind".into()),
            cdn: Some("cloudflare".into()),
            hosting: Some("vercel".into()),
            dns_provider: Some("route53".into()),
            other: vec!["jquery".into(), "alpine.js".into()],
        };
        assert_eq!(
            serde_json::to_string(&stack).unwrap(),
            concat!(
                r#"{"server":"nginx","framework":"next.js","cms":"wordpress","#,
                r#""js_framework":"react","css_framework":"tailwind","cdn":"cloudflare","#,
                r#""hosting":"vercel","dns_provider":"route53","other":["jquery","alpine.js"]}"#
            )
        );
    }

    #[test]
    fn detected_stack_defaults_when_wire_fields_are_absent() {
        // A previously valid empty stack can fail to deserialize.
        assert_eq!(
            serde_json::from_str::<DetectedStack>("{}").unwrap(),
            DetectedStack::default()
        );
    }
}
