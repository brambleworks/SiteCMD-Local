//! Release versions and provenance carried by observations.

use serde::{Deserialize, Serialize};

/// Canonical-form version for identities and digests. Increment when
/// canonicalization changes.
pub const CANONICALIZER_VERSION: u16 = crate::route::CANONICALIZER_VERSION as u16;

/// The fingerprint schema version the protocol envelope carries.
pub const FINGERPRINT_SCHEMA: u16 = 1;

/// Version for page discovery, ordering, and bounds, independent of check
/// semantics in the capability manifest.
pub const CRAWL_PROFILE: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLayer {
    Transport,
    Browser,
    Code,
}
impl ExecutionLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Browser => "browser",
            Self::Code => "code",
        }
    }
}

/// Runtime facts that may affect a verdict beyond the check implementation.
/// Missing fields mean the producer does not know the value; cross-vantage
/// comparisons must declare every dimension they rely on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProfile {
    /// The browser that produced browser-lane results, or `None` when the run
    /// had no browser at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_engine: Option<String>,
    /// Exact browser build used by the run. Reported for server-side mapping
    /// to a certified compatibility epoch, but not compared directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_build: Option<String>,
    /// Corpus-certified browser compatibility epoch. Desktop producers leave
    /// this unset because only the hosted runner owns the certification data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_epoch: Option<String>,
    /// The pinned axe-core version, stated only when axe actually ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axe_version: Option<String>,
    /// Which resolver answered DNS questions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    /// The HTTP client profile that fetched pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// The TLS client profile that performed handshakes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client: Option<String>,
    /// The trust anchors chain validation ran against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_authority: Option<String>,
    /// The scan profile the run executed under (its focus or mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_profile: Option<String>,
    /// Which layers the run executed. A layer that did not run cannot be read
    /// as absence of what it would have found.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers_run: Vec<String>,
}

/// What a build states about itself, stamped onto every observation it
/// produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseStamp {
    /// The release the producing runtime ships as.
    pub engine_release: String,
    /// The capability manifest that governed the run.
    pub manifest_digest: String,
    pub canonicalizer: u16,
    pub crawl_profile: u16,
    pub execution: ExecutionProfile,
}
