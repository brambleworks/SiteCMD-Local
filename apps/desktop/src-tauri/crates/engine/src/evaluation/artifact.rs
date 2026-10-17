//! The page artifact a runtime hands the engine, the refusal it answers when the artifact is unusable, and the facts a request carries.

use serde::{Deserialize, Serialize};

use crate::header_lines::{lines_of, HeaderLines};
use crate::manifest::RuntimeFact;
use crate::page::PageContext;

/// Stable wire representation of a fetched document.
/// Runtime-only `PageContext` fields stay outside the cross-runtime contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageArtifact {
    /// The URL the body came from, after redirects. Route identity and every
    /// origin-scoped verdict derive from this, never from what was requested.
    pub url: String,
    /// URL requested before redirects. `None` means redirect checks must
    /// decline; defaulting to the final URL would create a false pass.
    #[serde(default)]
    pub requested_url: Option<String>,
    pub status_code: u16,
    /// The negotiated protocol as the transport reported it ("HTTP/2.0").
    /// Optional because a runtime that cannot observe it must say so rather
    /// than assert a default: `performance.http2` grades this field.
    #[serde(default)]
    pub http_version: Option<String>,
    #[serde(default)]
    pub is_localhost: bool,
    /// Strict loopback only. Separate from `is_localhost` because the TLS
    /// bypass decision is narrower than the preview-posture one.
    #[serde(default)]
    pub is_strict_localhost: bool,
    /// Response headers in arrival order, preserving repeated fields.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Caller-supplied clock basis for deterministic time-dependent verdicts.
    pub evaluation_time: chrono::DateTime<chrono::Utc>,
}

/// Structured request refusal for the wasm boundary. Errors may name headers
/// but never echo their potentially sensitive values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationError {
    /// The artifact's URL did not parse, so no verdict has an origin.
    Url,
    /// A response-header name is not a valid HTTP field name.
    HeaderName { name: String },
    /// A response-header value is not a valid HTTP field value.
    HeaderValue { name: String },
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url => write!(formatter, "page artifact url did not parse"),
            Self::HeaderName { name } => {
                write!(formatter, "response header name is not valid: {name}")
            }
            Self::HeaderValue { name } => {
                write!(formatter, "response header value is not valid: {name}")
            }
        }
    }
}

impl std::error::Error for EvaluationError {}

impl PageArtifact {
    /// Rebuild the portable page record the checks read.
    pub fn page_context(&self) -> Result<PageContext, EvaluationError> {
        self.clone().into_page_context()
    }

    /// Build the portable page record the checks read, moving the body rather than copying it.
    ///
    /// `append` rather than `insert`, so a document that really did carry two
    /// `Set-Cookie` headers presents both to the cookie verdicts.
    pub fn into_page_context(self) -> Result<PageContext, EvaluationError> {
        self.into_page_context_with(HeaderLines::Separate)
    }

    /// Build the page record with the runtime's response header line form.
    pub fn into_page_context_with(
        self,
        lines: HeaderLines,
    ) -> Result<PageContext, EvaluationError> {
        let url = url::Url::parse(&self.url).map_err(|_| EvaluationError::Url)?;
        let mut response_headers = http::HeaderMap::new();
        for (name, value) in &self.headers {
            let header_name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| EvaluationError::HeaderName { name: name.clone() })?;
            let values = if lines == HeaderLines::Joined {
                lines_of(header_name.as_str(), value)
            } else {
                vec![value.as_str()]
            };
            for value in values {
                let header_value = http::header::HeaderValue::from_str(value)
                    .map_err(|_| EvaluationError::HeaderValue { name: name.clone() })?;
                response_headers.append(header_name.clone(), header_value);
            }
        }
        Ok(PageContext {
            url,
            response_headers,
            status_code: self.status_code,
            body: self.body,
            is_localhost: self.is_localhost,
            is_strict_localhost: self.is_strict_localhost,
            http_version: self.http_version,
            body_lower_cache: std::sync::OnceLock::new(),
            evaluation_time: self.evaluation_time,
        })
    }
}

pub(super) fn facts_in_order(
    fetch: bool,
    resolver: bool,
    tls: bool,
    browser: bool,
    vulnerability: bool,
) -> Vec<RuntimeFact> {
    let mut facts = vec![RuntimeFact::PageArtifact];
    // Declaration order, matching the enum, so two requests carrying the same
    // facts always list them the same way.
    if fetch {
        facts.push(RuntimeFact::Fetch);
    }
    if resolver {
        facts.push(RuntimeFact::Resolver);
    }
    if tls {
        facts.push(RuntimeFact::TlsFacts);
    }
    if browser {
        facts.push(RuntimeFact::Browser);
    }
    if fetch {
        facts.push(RuntimeFact::Rdap);
    }
    if vulnerability {
        facts.push(RuntimeFact::VulnerabilityCorpus);
    }
    facts
}
