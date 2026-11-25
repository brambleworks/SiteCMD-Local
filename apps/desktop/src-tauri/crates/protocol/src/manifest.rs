//! Capability manifest identifiers.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::sync::wire::{hex, wire_value};

/// Manifest entry-schema version, independent of content revisions.
pub const SCHEMA_VERSION: u16 = 2;

wire_value!(ManifestDigest, |v: &str| hex(v, 16, 16));
