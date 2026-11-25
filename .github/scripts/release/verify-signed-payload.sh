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
test "$(sha256_file engine.lock)" = \
  "$(jq -r '.engine_lock_sha256' release-candidate/manifest.json)"
dir="payload/$TARGET"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dir" && sha256sum -c SHA256SUMS)
else
  (cd "$dir" && shasum -a 256 -c SHA256SUMS)
fi
test "$(jq -r '.target' "$dir/fragment.json")" = "$TARGET"
test "$(jq -r '.candidate_hash' "$dir/fragment.json")" = "$EXPECTED_CANDIDATE_HASH"
test "$(jq -r '.source_commit' "$dir/fragment.json")" = "$EXPECTED_SOURCE_COMMIT"
public_key=".github/actions/setup-sitecmd/updater-public-key.pub"
verifier=".github/updater-verifier/target/release/sitecmd-updater-verifier"
if [ -x "${verifier}.exe" ]; then verifier="${verifier}.exe"; fi

cli_archive=$(jq -r '.cli_archive' "$dir/fragment.json")
tr -d '\r' < "$dir/$cli_archive.sig" | base64 --decode > cli-signature.sig
"$verifier" "$public_key" "$dir/$cli_archive" cli-signature.sig

# The release-wide checksum manifest carries the same key and names this leg's bytes.
tr -d '\r' < payload/SHA256SUMS.sig | base64 --decode > checksum-signature.sig
cmp -s checksum-signature.sig payload/SHA256SUMS.minisig
"$verifier" "$public_key" payload/SHA256SUMS checksum-signature.sig
verify_listed() {
  expected=$(awk -v name="$(basename "$1")" '$2 == name { print $1 }' payload/SHA256SUMS)
  test -n "$expected"
  test "$(sha256_file "$1")" = "$expected"
}
verify_listed "$dir/$cli_archive"
