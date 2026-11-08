//! Generated capability manifest for check semantics and comparability.
//!
//! Registry entries define each check's contract, lane, class, scope, and
//! execution-profile requirements.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod registry;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

/// Manifest entry-schema version, independent of content revisions.
pub const SCHEMA_VERSION: u16 = 2;

/// Which execution lane can produce the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedLane {
    /// Pure verdict code in the portable artifact, over an already-fetched
    /// page. Identical on every runtime by construction.
    Artifact,
    /// Portable verdict code fed by a transport adapter (fetches, resolver,
    /// TLS facts). The verdict is shared; the adapters are corpus-pinned.
    ProbeAdapter,
    /// Needs a real browser: axe rules and the browser-observed vitals.
    Browser,
    /// The hosted runner cannot produce this check today. Either the verdict
    /// code has not finished the engine extraction or the check needs
    /// something the hosted runtime does not have. Never comparable across
    /// vantages.
    Unsupported,
}

/// How a change between two comparable observations is attributed, and
/// whether the check takes part in the lifecycle at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckClass {
    /// A function of its inputs. A change means the site changed.
    Deterministic,
    /// A vantage-dependent sample that remains outside the issue lifecycle.
    Measurement,
    /// A result that can change solely as `evaluation_time` advances.
    ClockDependent,
    /// A verdict that can change when its external corpus changes.
    ExternalCorpus,
}

/// The unit published by a measurement-class check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementUnit {
    #[serde(rename = "ms")]
    Milliseconds,
    Ratio,
}

impl MeasurementUnit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Milliseconds => "ms",
            Self::Ratio => "ratio",
        }
    }
}

/// What has to be covered before an absence of findings means anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckScope {
    /// About one route. Covered when that route ran.
    Page,
    /// About the origin. Covered as entry-page pairs; one route is enough.
    Origin,
    /// About the route set as a whole (duplicate titles across pages). Only
    /// covered when the complete required route set ran, so a partial scan
    /// cannot claim session-level absence.
    Session,
}

/// Runtime capability required to execute a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFact {
    /// The fetched document and its response headers.
    PageArtifact,
    /// Additional HTTP requests (probe paths, subresources, alternate hosts).
    Fetch,
    /// DNS record lookups.
    Resolver,
    /// Peer-certificate facts from a TLS handshake.
    TlsFacts,
    /// The negotiated HTTP protocol from the entry page connection.
    NegotiatedProtocol,
    /// A real browser session.
    Browser,
    /// Registration data from RDAP.
    Rdap,
    /// A vulnerability corpus query.
    VulnerabilityCorpus,
}

/// An execution-profile dimension that must match before two observations of
/// the check compare. Empty means the contract alone decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareDimension {
    /// Chromium vs WebKit vs WebView2. Real behavior differences already
    /// exist across desktop platforms.
    BrowserEngine,
    /// The corpus-certified compatibility epoch for the browser build. Exact
    /// builds are recorded for forensics and never compared directly, so an
    /// unnoticed browser update cannot verify a finding fixed.
    BrowserEpoch,
    /// The pinned axe-core version. Rule semantics move between versions.
    AxeVersion,
    /// The HTTP client profile that fetched the page. Protocol negotiation
    /// and content-encoding are functions of the client, so two adapters can
    /// disagree against an unchanged server.
    TransportProfile,
    /// The trust anchors chain validation ran against.
    TrustAuthority,
    /// The TLS client profile. The negotiated version is a function of the
    /// client hello, so Chromium and rustls can negotiate differently against
    /// an unchanged server.
    TlsClientProfile,
}

/// One registry row: everything about a check that is authored rather than
/// derived. Rows are `const`, so the whole registry is a compile-time table.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// The check id, or for a family the id PREFIX its dynamic ids carry.
    pub check: &'static str,
    pub lane: HostedLane,
    pub class: CheckClass,
    pub measurement_unit: Option<MeasurementUnit>,
    pub scope: CheckScope,
    /// Manual semantic revision. Bump for verdict or threshold changes; leave
    /// unchanged for refactors, copy, or evidence-source changes.
    pub revision: u16,
    /// External facts folded into the contract hash, such as axe-core version.
    pub contract_extra: &'static [&'static str],
    requires: Option<&'static [RuntimeFact]>,
    compare_on: Option<&'static [CompareDimension]>,
    /// Complete projection inputs for deterministic cross-vantage equivalence.
    /// Empty disables equivalence for this check.
    pub equivalence_inputs: &'static [&'static str],
    /// True when `check` is an id prefix covering dynamically named ids
    /// rather than one id.
    pub family: bool,
}

impl Entry {
    /// A page-scoped deterministic check in the portable artifact: the shape
    /// most checks have. Every other row is this with overrides.
    pub const fn new(check: &'static str) -> Self {
        Self {
            check,
            lane: HostedLane::Artifact,
            class: CheckClass::Deterministic,
            measurement_unit: None,
            scope: CheckScope::Page,
            revision: 1,
            contract_extra: &[],
            requires: None,
            compare_on: None,
            equivalence_inputs: &[],
            family: false,
        }
    }

    pub const fn probe(mut self) -> Self {
        self.lane = HostedLane::ProbeAdapter;
        self
    }

    pub const fn browser(mut self) -> Self {
        self.lane = HostedLane::Browser;
        self
    }

    pub const fn unsupported(mut self) -> Self {
        self.lane = HostedLane::Unsupported;
        self
    }

    pub const fn origin(mut self) -> Self {
        self.scope = CheckScope::Origin;
        self
    }

    pub const fn session(mut self) -> Self {
        self.scope = CheckScope::Session;
        self
    }

    pub const fn measurement(mut self, unit: MeasurementUnit) -> Self {
        self.class = CheckClass::Measurement;
        self.measurement_unit = Some(unit);
        self
    }

    pub const fn clock_dependent(mut self) -> Self {
        self.class = CheckClass::ClockDependent;
        self
    }

    pub const fn external_corpus(mut self) -> Self {
        self.class = CheckClass::ExternalCorpus;
        self
    }

    pub const fn needs(mut self, requires: &'static [RuntimeFact]) -> Self {
        self.requires = Some(requires);
        self
    }

    pub const fn compare_on(mut self, dimensions: &'static [CompareDimension]) -> Self {
        self.compare_on = Some(dimensions);
        self
    }

    pub const fn revision(mut self, revision: u16) -> Self {
        self.revision = revision;
        self
    }

    pub const fn contract_extra(mut self, extra: &'static [&'static str]) -> Self {
        self.contract_extra = extra;
        self
    }

    pub const fn family(mut self) -> Self {
        self.family = true;
        self
    }

    /// The runtime facts the check needs. Declared rows win; the rest follow
    /// from the lane, because a lane IS a statement about what the runtime
    /// must supply.
    pub fn resolved_requires(&self) -> Vec<RuntimeFact> {
        if let Some(declared) = self.requires {
            return declared.to_vec();
        }
        match self.lane {
            HostedLane::Artifact => vec![RuntimeFact::PageArtifact],
            HostedLane::ProbeAdapter => vec![RuntimeFact::PageArtifact, RuntimeFact::Fetch],
            HostedLane::Browser => vec![RuntimeFact::Browser],
            HostedLane::Unsupported => vec![],
        }
    }

    /// Required profile matches, inferred from the lane unless declared.
    pub fn resolved_compare_on(&self) -> Vec<CompareDimension> {
        if let Some(declared) = self.compare_on {
            return declared.to_vec();
        }
        match self.lane {
            HostedLane::Browser => vec![
                CompareDimension::BrowserEngine,
                CompareDimension::BrowserEpoch,
            ],
            _ => vec![],
        }
    }

    /// Semantic compatibility hash over identity, revision, and declared
    /// external dependencies.
    ///
    /// Source and corpus contents are excluded so comments, renames, and added
    /// test cases do not break result comparability.
    pub fn contract(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.check.as_bytes());
        hasher.update([UNIT_SEPARATOR]);
        hasher.update(self.revision.to_string().as_bytes());
        if let Some(unit) = self.measurement_unit {
            hasher.update([UNIT_SEPARATOR]);
            hasher.update(unit.as_str().as_bytes());
        }
        for extra in self.contract_extra {
            hasher.update([UNIT_SEPARATOR]);
            hasher.update(extra.as_bytes());
        }
        short_hex(&hasher.finalize())
    }

    /// The published form of the row, with everything derivable derived.
    pub fn resolve(&self) -> ManifestEntry {
        ManifestEntry {
            check: self.check.to_string(),
            contract: self.contract(),
            hosted: self.lane,
            class: self.class,
            measurement_unit: self.measurement_unit,
            scope: self.scope,
            requires: self.resolved_requires(),
            compare_on: self.resolved_compare_on(),
            equivalence_inputs: self
                .equivalence_inputs
                .iter()
                .map(|f| f.to_string())
                .collect(),
            family: self.family,
        }
    }
}

const UNIT_SEPARATOR: u8 = 0x1f;

/// First eight digest bytes for readable operational identifiers.
fn short_hex(digest: &[u8]) -> String {
    hex::encode(&digest[..8])
}

/// One published manifest entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub check: String,
    pub contract: String,
    pub hosted: HostedLane,
    pub class: CheckClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_unit: Option<MeasurementUnit>,
    pub scope: CheckScope,
    pub requires: Vec<RuntimeFact>,
    pub compare_on: Vec<CompareDimension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalence_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub family: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// The published document. Identified by [`CapabilityManifest::digest`],
/// which every observation envelope carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub schema_version: u16,
    pub manifest_digest: String,
    pub entries: Vec<ManifestEntry>,
}

impl CapabilityManifest {
    /// Look a check id up, resolving a dynamic id (`accessibility.axe.label`)
    /// to its family entry. An exact entry always wins over a family whose
    /// prefix it happens to match.
    pub fn entry(&self, check_id: &str) -> Option<&ManifestEntry> {
        if let Some(exact) = self.entries.iter().find(|entry| entry.check == check_id) {
            return Some(exact);
        }
        self.entries
            .iter()
            .filter(|entry| entry.family && check_id.starts_with(&entry.check))
            // Longest matching prefix, so nesting one family inside another
            // resolves to the more specific one.
            .max_by_key(|entry| entry.check.len())
    }

    pub fn digest(&self) -> &str {
        &self.manifest_digest
    }
}

/// Build the manifest from the registry. Every runtime runs this same code
/// over the same table, so the digest is a property of the engine build and
/// not of whoever generated the file.
pub fn capability_manifest() -> CapabilityManifest {
    let mut entries: Vec<ManifestEntry> = registry::entries().map(Entry::resolve).collect();
    entries.sort_by(|a, b| a.check.cmp(&b.check));
    let manifest_digest = document_digest(SCHEMA_VERSION, &entries);
    CapabilityManifest {
        schema_version: SCHEMA_VERSION,
        manifest_digest,
        entries,
    }
}

/// Hash canonical schema and sorted entries so formatting cannot change identity.
fn document_digest(schema_version: u16, entries: &[ManifestEntry]) -> String {
    // Serialize a struct so field order and hashes do not depend on
    // serde_json's preserve_order feature.
    #[derive(Serialize)]
    struct CanonicalDocument<'a> {
        schema_version: u16,
        entries: &'a [ManifestEntry],
    }

    let canonical = CanonicalDocument {
        schema_version,
        entries,
    };
    let mut hasher = Sha256::new();
    hasher.update(
        serde_json::to_string(&canonical)
            .expect("manifest serializes")
            .as_bytes(),
    );
    short_hex(&hasher.finalize())
}
