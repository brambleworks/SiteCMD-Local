//! Constrained textual wire values validate input before construction.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! wire_value {
    ($name:ident, secret, $valid:expr) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(***)"))
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.0);
            }
        }
        impl zeroize::ZeroizeOnDrop for $name {}
        wire_value!(@common $name, $valid);
    };
    ($name:ident, $valid:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.as_str().fmt(f)
            }
        }
        wire_value!(@common $name, $valid);
    };
    (@common $name:ident, $valid:expr) => {
        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                let value = Self(value);
                if !($valid)(value.as_str()) {
                    return Err(concat!("invalid ", stringify!($name)).into());
                }
                Ok(value)
            }
        }
        impl TryFrom<&str> for $name {
            type Error = String;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_owned())
            }
        }
        impl std::str::FromStr for $name {
            type Err = String;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value)
            }
        }
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl std::ops::Deref for $name {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }
        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other.as_str()
            }
        }
        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }
        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

#[path = "wire_grammar.rs"]
mod grammar;
pub(crate) use grammar::hex;
use grammar::*;
pub(crate) use wire_value;

pub use crate::manifest::ManifestDigest;

wire_value!(Identifier, |v: &str| fact(v, 128));
wire_value!(CheckId, check_id);
wire_value!(AuthorityId, |v: &str| fact(v, 256));
wire_value!(Digest, |v: &str| hex(v, 64, 64));
wire_value!(CommitSha, |v: &str| hex(v, 7, 64));
wire_value!(HeadSha, |v: &str| hex(v, 40, 40));
wire_value!(RoutePath, canonical_route);
wire_value!(FindingIdentity, finding_identity);
wire_value!(RepositorySlug, repository_slug);
wire_value!(RepositoryId, |v: &str| !v.is_empty()
    && v.len() <= 20
    && v.bytes().all(|b| b.is_ascii_digit()));
wire_value!(GitRef, git_ref);
wire_value!(WorkflowRef, workflow_ref);
wire_value!(Timestamp, timestamp);
wire_value!(SitecmdBranch, |v: &str| v
    .strip_prefix("sitecmd/")
    .is_some_and(|s| git_ref(s)
        && token(s, 247, b"._/-")
        && s.starts_with(
            |c: char| c.is_ascii_lowercase() || c.is_ascii_digit()
        )
        && !s.bytes().any(|b| b.is_ascii_uppercase())));
wire_value!(OutcomeCode, |v: &str| matches!(
    v,
    "stale_base"
        | "build_failed"
        | "unsupported"
        | "no_template"
        | "patch_rejected"
        | "push_failed"
        | "brief_rejected"
        | "issue_failed"
        | "applied"
        | "issue_opened"
        | "secrets_missing"
));
wire_value!(FindingOutcome, |v: &str| matches!(
    v,
    "applied" | "issue_opened" | "unsupported" | "no_template"
));
wire_value!(ClaimPurpose, |v: &str| matches!(v, "execute" | "publish"));
wire_value!(OrderingKind, |v: &str| matches!(
    v,
    "publish_sequence" | "publish_attestation"
));
wire_value!(SeverityThreshold, |v: &str| matches!(
    v,
    "critical" | "high" | "medium" | "low"
));
wire_value!(DeploymentTarget, |v: &str| fact(v, 128));
wire_value!(DeviceCode, secret, |v: &str| token(v, 256, b"_-"));

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
