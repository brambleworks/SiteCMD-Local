//! Connected payload types excluding source, raw paths, and evidence.

pub mod fingerprint;
pub mod payload;
pub mod snapshot;
pub mod wire;

pub use fingerprint::{ProjectFingerprintKey, FINGERPRINT_KEY_LEN};
pub use payload::{
    ClientGroupState, CodeIdentity, CorrelationPair, CorrelationPairs, DesktopSubmission,
    DismissalPolicy, Environment, FindingSource, GroupEntry, GroupMode, GroupSubmission,
    LastKnownOccurrence, LastKnownWebOccurrence, Snapshots, WebIdentity,
};
pub use snapshot::{
    CodeBasis, CodeBasisKind, CodeOccurrence, CodePairIdentity, CodeProvenance, CodeSnapshot,
    CodeVersions, DesktopProvenanceKind, MeasurementSample, WebOccurrence, WebSnapshot,
    WebVersions, WireCoverage, WireCoverageException,
};

/// Wire schema version, bumped only for breaking protocol changes.
pub const SCHEMA_VERSION: u16 = 1;

/// Version of the project fingerprint key currently emitted by producers.
pub const FINGERPRINT_KEY_VERSION: u16 = 1;

/// Fingerprint identity schema carried beside the payload schema. Baselines
/// from different identity schemas are not comparable.
pub use crate::release::FINGERPRINT_SCHEMA;
