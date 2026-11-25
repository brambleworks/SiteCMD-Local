import { describe, expect, it } from "vitest";
import { syncPayloadFailures } from "./lib/guardrail-sync-payload-rules.mjs";

const SYNC_DIR = "apps/desktop/src-tauri/crates/protocol/src/sync";
const FINGERPRINT = `${SYNC_DIR}/fingerprint.rs`;
const MODULE = `${SYNC_DIR}/mod.rs`;

function sources() {
  return {
    [FINGERPRINT]: `use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
type HmacSha256 = Hmac<Sha256>;
pub const FINGERPRINT_KEY_LEN: usize = 32;
const CODE_LOCATION_DOMAIN: &str = "sitecmd-fp-v1|code|";
const KEY_COMMITMENT_DOMAIN: &str = "sitecmd-fpk-commit|";
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectFingerprintKey {
    bytes: [u8; FINGERPRINT_KEY_LEN],
}
impl ProjectFingerprintKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, usize> {
        <[u8; FINGERPRINT_KEY_LEN]>::try_from(bytes).map(Self::from_bytes).map_err(|_| bytes.len())
    }
    pub fn commitment(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(KEY_COMMITMENT_DOMAIN.as_bytes());
        hasher.update(self.bytes);
        hex::encode(hasher.finalize())
    }
    pub fn location_hash(&self, producer_rule: &str, relative_path: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.bytes).expect("32 bytes");
        mac.update(CODE_LOCATION_DOMAIN.as_bytes());
        mac.update(producer_rule.as_bytes());
        mac.update(b"|");
        mac.update(relative_path.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}
impl std::fmt::Debug for ProjectFingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProjectFingerprintKey([redacted; {FINGERPRINT_KEY_LEN}])")
    }
}`,
    [MODULE]: `pub mod fingerprint;
pub const SCHEMA_VERSION: u16 = 1;
pub struct WebOccurrence {
    pub check: String,
    pub route: String,
    pub severity: Severity,
}`,
  };
}

function run(overrides = {}) {
  const files = { ...sources(), ...overrides };
  const read = (file) => files[file] ?? "";
  const exists = (file) => file in files;
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(dir) && predicate(file));
  return syncPayloadFailures(read, exists, listFiles);
}

describe("sync payload guardrail", () => {
  it("passes on a module where every rule holds", () => {
    expect(run()).toEqual([]);
  });

  it("catches a serializable fingerprint key", () => {
    const broken = sources()[FINGERPRINT].replace(
      "#[derive(Clone, PartialEq, Eq)]",
      "#[derive(Clone, PartialEq, Eq, Serialize)]",
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("serializable");
  });

  it("catches a hand-written Serialize impl for the key", () => {
    const broken = `${sources()[FINGERPRINT]}
impl Serialize for ProjectFingerprintKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_bytes(&self.bytes) }
}`;
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("serializable");
  });

  it("catches a derived Debug that would print key bytes", () => {
    const broken = sources()[FINGERPRINT].replace(
      "#[derive(Clone, PartialEq, Eq)]",
      "#[derive(Clone, Debug, PartialEq, Eq)]",
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("derive Debug");
  });

  it("catches a Display impl on the key", () => {
    const broken = `${sources()[FINGERPRINT]}
impl std::fmt::Display for ProjectFingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "key") }
}`;
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("Display");
  });

  it("catches a public key field", () => {
    const broken = sources()[FINGERPRINT].replace(
      "bytes: [u8; FINGERPRINT_KEY_LEN],",
      "pub bytes: [u8; FINGERPRINT_KEY_LEN],",
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("private");
  });

  it("catches a line number entering code identity", () => {
    const broken = sources()[FINGERPRINT].replace(
      "pub fn location_hash(&self, producer_rule: &str, relative_path: &str) -> String",
      "pub fn location_hash(&self, producer_rule: &str, relative_path: &str, line: u32) -> String",
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("line number");
  });

  it("catches the keyed MAC degrading to a bare digest", () => {
    const broken = sources()[FINGERPRINT].replace(
      `        let mut mac = HmacSha256::new_from_slice(&self.bytes).expect("32 bytes");
        mac.update(CODE_LOCATION_DOMAIN.as_bytes());`,
      `        let mut mac = Sha256::new();
        mac.update(CODE_LOCATION_DOMAIN.as_bytes());`,
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("KEYED MAC");
  });

  it("catches a missing delimiter between rule and path", () => {
    const broken = sources()[FINGERPRINT].replace('        mac.update(b"|");\n', "");
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("delimit");
  });

  it("catches a silently changed code-location domain", () => {
    const broken = sources()[FINGERPRINT].replace("sitecmd-fp-v1|code|", "sitecmd-fp|code|");
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("domain string");
  });

  it("catches the two domains collapsing into one", () => {
    const broken = sources()[FINGERPRINT].replace(
      'const KEY_COMMITMENT_DOMAIN: &str = "sitecmd-fpk-commit|";',
      'const KEY_COMMITMENT_DOMAIN: &str = "sitecmd-fp-v1|code|";',
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("distinct");
  });

  it("catches from_slice becoming infallible", () => {
    const broken = sources()[FINGERPRINT].replace(
      "pub fn from_slice(bytes: &[u8]) -> Result<Self, usize>",
      "pub fn from_slice(bytes: &[u8]) -> Self",
    );
    expect(run({ [FINGERPRINT]: broken }).join("\n")).toContain("fallible");
  });

  it("catches a banned member reaching a wire type", () => {
    for (const member of ["raw_data", "file_path", "fix_prompt", "line_number", "description"]) {
      const broken = sources()[MODULE].replace(
        "    pub severity: Severity,",
        `    pub severity: Severity,\n    pub ${member}: String,`,
      );
      expect(run({ [MODULE]: broken }).join("\n")).toContain(member);
    }
  });

  it("allows banned names inside comments, which have to explain the ban", () => {
    const documented = `// raw_data and detail_json never sync.
//! The fix_prompt is local-only.
${sources()[MODULE]}`;
    expect(run({ [MODULE]: documented })).toEqual([]);
  });

  it("reports when the module is missing instead of passing vacuously", () => {
    const files = sources();
    delete files[FINGERPRINT];
    const read = (file) => files[file] ?? "";
    const exists = (file) => file in files;
    const listFiles = (dir, predicate) =>
      Object.keys(files).filter((file) => file.startsWith(dir) && predicate(file));
    expect(syncPayloadFailures(read, exists, listFiles).join("\n")).toContain("is missing");
  });
});
