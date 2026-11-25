import { publicRustSources } from "./guardrail-protocol-contents-rules.mjs";
import { connectedRequestFailures } from "./guardrail-connected-request-rules.mjs";
import { stripComments } from "./guardrail-source-text.mjs";

const SYNC_DIR = "apps/desktop/src-tauri/crates/protocol/src/sync";
const FINGERPRINT = `${SYNC_DIR}/fingerprint.rs`;
const MODULE = `${SYNC_DIR}/mod.rs`;

// Protocol-level field ban for finding content and local source geography.
const BANNED_WIRE_MEMBERS = [
  "raw_data",
  "detail_json",
  "fix_prompt",
  "manual_fix",
  "why_it_matters",
  "confidence_reason",
  "description",
  "title",
  "evidence",
  "excerpt",
  "snippet",
  "file_path",
  "absolute_path",
  "line_number",
];

// Read the contiguous Rust attribute block without unsafe nested regex quantifiers.
function attributeBlockAbove(source, marker) {
  const at = source.indexOf(marker);
  if (at === -1) return "";
  let head = source.slice(0, at);
  const attrs = [];
  for (;;) {
    const trimmed = head.trimEnd();
    if (!trimmed.endsWith("]")) break;
    const open = trimmed.lastIndexOf("#[");
    if (open === -1) break;
    attrs.unshift(trimmed.slice(open));
    head = trimmed.slice(0, open);
  }
  return attrs.join("\n");
}

/**
 * @param {(file: string) => string} read
 * @param {(file: string) => boolean} exists
 * @param {(dir: string, predicate: (file: string) => boolean) => string[]} listFiles
 */
export function syncPayloadFailures(read, exists, listFiles) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const source = (file) => (exists(file) ? stripComments(read(file), file) : "");

  const fingerprint = source(FINGERPRINT);
  check(
    fingerprint.length > 0,
    `${FINGERPRINT} is missing; the sync payload's privacy guardrail has nothing to check. Update guardrail-sync-payload-rules.mjs if the module moved.`,
  );

  // The key type must remain impossible to serialize.
  const keyAttributes = attributeBlockAbove(fingerprint, "pub struct ProjectFingerprintKey");
  check(
    !/#\[derive\([^)]*Serialize[^)]*\)\]/.test(keyAttributes) &&
      !/impl\s+Serialize\s+for\s+ProjectFingerprintKey/.test(fingerprint),
    `${FINGERPRINT} must never make ProjectFingerprintKey serializable: a key that can be serialized can be added to a payload by an edit that meant no harm, and the compiler refusing is stronger than a review catching it.`,
  );
  check(
    !/impl\s+std::fmt::Display\s+for\s+ProjectFingerprintKey/.test(fingerprint),
    `${FINGERPRINT} must never give ProjectFingerprintKey a Display impl; the only ways out of the type are its two one-way digests.`,
  );
  check(
    !/#\[derive\([^)]*Debug[^)]*\)\]/.test(keyAttributes),
    `${FINGERPRINT} must not derive Debug on ProjectFingerprintKey; a derived Debug prints the key bytes into whatever log or panic message is nearest.`,
  );
  check(
    /impl std::fmt::Debug for ProjectFingerprintKey/.test(fingerprint) &&
      /redacted/.test(fingerprint),
    `${FINGERPRINT} must keep the manual, redacting Debug impl for ProjectFingerprintKey.`,
  );
  check(
    /pub struct ProjectFingerprintKey \{\s*bytes: \[u8; FINGERPRINT_KEY_LEN\],\s*\}/.test(
      fingerprint,
    ),
    `${FINGERPRINT} must keep the key bytes private and fixed-length: a public field is a copy anyone can take, and a variable length lets a derived or typed-in "key" through the door the random-bytes rule holds shut.`,
  );

  // Identity is (rule, path), keyed, delimited, and version-domained.
  check(
    /pub fn location_hash\(&self, producer_rule: &str, relative_path: &str\) -> String/.test(
      fingerprint,
    ),
    `${FINGERPRINT} must keep location_hash taking exactly the producer rule and the relative path. A line number in the input makes identity die on every neighbouring edit, so every ordinary change reads as one finding fixed and another discovered and verification never converges.`,
  );
  check(
    /HmacSha256::new_from_slice/.test(fingerprint) &&
      !/pub fn location_hash[\s\S]{0,600}?Sha256::new\(\)/.test(fingerprint),
    `${FINGERPRINT} must compute location_hash as a KEYED MAC, never a bare digest: rule ids and file paths are low-entropy enough that an unkeyed hash is reversible by dictionary, which is the entire reason code locations are hashed at all.`,
  );
  check(
    /mac\.update\(b"\|"\)/.test(fingerprint),
    `${FINGERPRINT} must delimit the producer rule from the relative path; without it ("ab", "c") and ("a", "bc") hash identically and two unrelated findings share one identity.`,
  );
  check(
    /const CODE_LOCATION_DOMAIN: &str = "sitecmd-fp-v1\|code\|";/.test(fingerprint),
    `${FINGERPRINT} must keep the versioned code-location domain string; changing what gets hashed is a new domain, never a silent reinterpretation of digests already stored.`,
  );
  check(
    /const KEY_COMMITMENT_DOMAIN: &str = "sitecmd-fpk-commit\|";/.test(fingerprint) &&
      !/CODE_LOCATION_DOMAIN.*KEY_COMMITMENT_DOMAIN|KEY_COMMITMENT_DOMAIN: &str = "sitecmd-fp-v1/.test(
        fingerprint,
      ),
    `${FINGERPRINT} must keep the commitment domain distinct from the fingerprint domain; one key minting the same value for two kinds of thing lets a value produced in one context be replayed as identity in another.`,
  );
  check(
    /pub fn from_slice\(bytes: &\[u8\]\) -> Result<Self, usize>/.test(fingerprint),
    `${FINGERPRINT} must keep from_slice fallible: a wrong-length key is a corrupted keychain entry or a mangled export, and padding it produces stable-looking digests that match nothing for the life of the site.`,
  );

  check(
    /pub const SCHEMA_VERSION/.test(source(MODULE)),
    `${MODULE} must declare the payload SCHEMA_VERSION; a wire contract with no version cannot be migrated without breaking every producer at once.`,
  );

  // Every wire type in the module tree, checked against the ban.
  const syncFiles = listFiles(SYNC_DIR, (file) => file.endsWith(".rs"));
  check(
    syncFiles.length > 0,
    "sync-payload guardrail found no sources under the sync module; update guardrail-sync-payload-rules.mjs if it moved.",
  );
  for (const file of syncFiles) {
    if (file.endsWith("_tests.rs")) continue;
    const code = source(file);
    for (const member of BANNED_WIRE_MEMBERS) {
      check(
        !new RegExp(`^\\s*(?:pub )?${member}\\s*:`, "m").test(code),
        `${file} declares a \`${member}\` field. Source code, file contents, raw paths, line numbers, code-scan evidence, issue descriptions, and fix prompts never sync; the payload types are where that is enforced, so adding one here is adding it to the wire.`,
      );
    }
  }

  return failures;
}

export function connectedServicePayloadFailures(read, exists, listFiles) {
  const files = publicRustSources(listFiles);
  return [
    ...syncPayloadFailures(read, exists, listFiles),
    ...connectedRequestFailures(files, read),
  ];
}
