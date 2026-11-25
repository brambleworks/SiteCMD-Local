const VOCAB_SOURCE = "apps/desktop/src-tauri/crates/protocol/src/vocab.rs";
const SCAN_TYPES = "apps/desktop/src-tauri/src/core/scan_types.rs";

const SEVERITY_HELPER_PINS = [
  "pub fn as_str",
  "pub fn label",
  "pub fn sort_rank",
  "pub fn sort_rank_for_label",
  "severity_string_helpers_are_canonical",
];

const CATEGORY_HELPER_PINS = [
  "pub enum Category",
  "pub const fn label",
  "pub const fn key",
  "the_list_is_the_ten_categories_in_order",
];

export function protocolVocabFailures(read) {
  const vocabSource = read(VOCAB_SOURCE);
  const failures = [];
  const missingSeverity = SEVERITY_HELPER_PINS.filter((pin) => !vocabSource.includes(pin));
  if (missingSeverity.length > 0) {
    failures.push(
      `${VOCAB_SOURCE} must keep the canonical Severity helper surface (missing: ${missingSeverity.join(", ")}); the desktop and hosted scorer both resolve severity strings/ranks through it.`,
    );
  }
  const missingCategory = CATEGORY_HELPER_PINS.filter((pin) => !vocabSource.includes(pin));
  if (missingCategory.length > 0) {
    failures.push(
      `${VOCAB_SOURCE} must keep the canonical Category helper surface (missing: ${missingCategory.join(", ")}).`,
    );
  }
  const scanTypes = read(SCAN_TYPES);
  if (
    !/pub use sitecmd_protocol::vocab::\{[^}]*CheckStatus[\s\S]{0,120}Severity[^}]*\}/.test(
      scanTypes,
    )
  ) {
    failures.push(
      `${SCAN_TYPES} must re-export the protocol vocabulary (pub use sitecmd_protocol::vocab::{CheckResult, CheckStatus, ..., Severity}) so core::scan_types stays the CLI's single import path.`,
    );
  }
  return failures;
}
