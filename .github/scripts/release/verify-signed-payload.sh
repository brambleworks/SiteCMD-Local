set -euo pipefail
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
test "$(sha256_file release-candidate/manifest.json)" = \
  "$EXPECTED_CANDIDATE_HASH"
dir="payload/$TARGET"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dir" && sha256sum -c SHA256SUMS)
else
  (cd "$dir" && shasum -a 256 -c SHA256SUMS)
fi
test "$(jq -r '.target' "$dir/fragment.json")" = "$TARGET"
test "$(jq -r '.candidate_hash' "$dir/fragment.json")" = "$EXPECTED_CANDIDATE_HASH"
test "$(jq -r '.source_commit' "$dir/fragment.json")" = "$EXPECTED_SOURCE_COMMIT"
# A CLI-only leg has no updater bundle: only its archive and provenance to check.
filename=$(jq -r '.filename // empty' "$dir/fragment.json")
if [ -n "$filename" ]; then
  test "$(sha256_file "$dir/$filename")" = \
    "$(jq -r '.artifact_sha256' "$dir/fragment.json")"
fi

# Normalize jq CRLF before GNU base64 decoding.
jq -r '.plugins.updater.pubkey' apps/desktop/src-tauri/tauri.conf.json | \
  tr -d '\r' | base64 --decode > updater-public-key.pub
verifier=".github/updater-verifier/target/release/sitecmd-updater-verifier"
if [ -x "${verifier}.exe" ]; then verifier="${verifier}.exe"; fi
if [ -n "$filename" ]; then
  tr -d '\r' < "$dir/$filename.sig" | base64 --decode > updater-signature.sig
  "$verifier" updater-public-key.pub "$dir/$filename" updater-signature.sig
fi

cli_archive=$(jq -r '.cli_archive' "$dir/fragment.json")
tr -d '\r' < "$dir/$cli_archive.sig" | base64 --decode > cli-signature.sig
"$verifier" updater-public-key.pub "$dir/$cli_archive" cli-signature.sig

# The release-wide checksum manifest carries the same key and names this leg's bytes.
tr -d '\r' < payload/SHA256SUMS.sig | base64 --decode > checksum-signature.sig
cmp -s checksum-signature.sig payload/SHA256SUMS.minisig
"$verifier" updater-public-key.pub payload/SHA256SUMS checksum-signature.sig
verify_listed() {
  expected=$(awk -v name="$(basename "$1")" '$2 == name { print $1 }' payload/SHA256SUMS)
  test -n "$expected"
  test "$(sha256_file "$1")" = "$expected"
}
if [ -n "$filename" ]; then
  verify_listed "$dir/$filename"
fi
verify_listed "$dir/$cli_archive"
dmg_name=$(jq -r '.dmg_name // empty' "$dir/fragment.json")
if [ -n "$dmg_name" ]; then verify_listed "$dir/$dmg_name"; fi
