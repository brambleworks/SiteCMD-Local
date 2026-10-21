set -euo pipefail
VERSION="${GITHUB_REF_NAME#v}"
SRC="apps/desktop/src-tauri"
DIST="$SRC/target/cli-dist"
mkdir -p "$DIST"

build_cli() {
  (cd "$SRC" && cargo build --manifest-path crates/cli/Cargo.toml \
    --release --locked --target "$1")
}
case "$TARGET" in
  darwin-universal)
    # Match the app's universal macOS architecture.
    build_cli aarch64-apple-darwin
    build_cli x86_64-apple-darwin
    lipo -create \
      "$SRC/target/aarch64-apple-darwin/release/sitecmd_cli" \
      "$SRC/target/x86_64-apple-darwin/release/sitecmd_cli" \
      -output "$DIST/sitecmd"
    ;;
  windows-x86_64)
    build_cli "$RUST_TARGET"
    cp "$SRC/target/$RUST_TARGET/release/sitecmd_cli.exe" "$DIST/sitecmd.exe"
    ;;
  *)
    build_cli "$RUST_TARGET"
    cp "$SRC/target/$RUST_TARGET/release/sitecmd_cli" "$DIST/sitecmd"
    ;;
esac

if [[ "$TARGET" == darwin-* ]]; then
  : "${APPLE_CERTIFICATE:?macOS CLI signing requires APPLE_CERTIFICATE}"
  : "${APPLE_SIGNING_IDENTITY:?macOS CLI signing requires APPLE_SIGNING_IDENTITY}"
  codesign --force --options runtime --timestamp \
    --sign "$APPLE_SIGNING_IDENTITY" "$DIST/sitecmd"

  NOTARY_DIR="$RUNNER_TEMP/cli-notarization"
  mkdir -p "$NOTARY_DIR"
  NOTARY_AUTH=(--key "$RUNNER_TEMP/asc_api_key.p8"
    --key-id "${APPLE_API_KEY_ID:?CLI notarization requires APPLE_API_KEY_ID}"
    --issuer "${APPLE_API_ISSUER:?CLI notarization requires APPLE_API_ISSUER}")
  ditto -c -k "$DIST/sitecmd" "$NOTARY_DIR/sitecmd.zip"
  submit_exit=0
  xcrun notarytool submit "$NOTARY_DIR/sitecmd.zip" \
    "${NOTARY_AUTH[@]}" --wait --output-format json \
    > "$NOTARY_DIR/submission.json" || submit_exit=$?
  if ! submission_id=$(jq -er '.id | strings | select(length > 0)' "$NOTARY_DIR/submission.json"); then
    echo "::error::CLI notarization returned no submission id."
    exit 1
  fi
  printf '%s\n' "$submission_id" > "$NOTARY_DIR/submission-id.txt"
  xcrun notarytool log "$submission_id" "${NOTARY_AUTH[@]}" "$NOTARY_DIR/notary-log.json"
  if [ "$submit_exit" -ne 0 ] || [ "$(jq -r '.status' "$NOTARY_DIR/submission.json")" != "Accepted" ]; then
    echo "::error::CLI notarization was not accepted; see submission $submission_id and its notary log."
    exit 1
  fi
fi
if [ "$TARGET" = "windows-x86_64" ] && [ -n "${AZURE_SIGN_ENDPOINT:-}" ] \
  && [ -n "${AZURE_CLIENT_ID:-}" ]; then
  artifact-signing-cli -e "$AZURE_SIGN_ENDPOINT" -a "$AZURE_SIGN_ACCOUNT" \
    -c "$AZURE_SIGN_PROFILE" "$DIST/sitecmd.exe"
fi

# Execute the artifact and verify its tag version before upload.
BIN="$DIST/sitecmd"
if [ "$TARGET" = "windows-x86_64" ]; then BIN="$DIST/sitecmd.exe"; fi
GOT=$("$BIN" --version)
if [ "$GOT" != "sitecmd $VERSION" ]; then
  echo "::error::CLI --version printed '$GOT', expected 'sitecmd $VERSION'"
  exit 1
fi

LICENSE_TARGET="$RUST_TARGET"
if [ "$TARGET" = "darwin-universal" ]; then
  LICENSE_TARGET="aarch64-apple-darwin"
fi
cargo license --manifest-path "$SRC/crates/cli/Cargo.toml" \
  --avoid-dev-deps --filter-platform "$LICENSE_TARGET" --tsv \
  --output "$DIST/THIRD_PARTY_LICENSES.tsv"
test -s "$DIST/THIRD_PARTY_LICENSES.tsv"
cp "$GITHUB_WORKSPACE/LICENSE" "$GITHUB_WORKSPACE/NOTICE" \
  "$GITHUB_WORKSPACE/THIRD_PARTY_NOTICES" \
  "$GITHUB_WORKSPACE/THIRD_PARTY_DEPENDENCIES.json" \
  "$GITHUB_WORKSPACE/THIRD_PARTY_LICENSES.txt" "$DIST/"
CLI_LEGAL_FILES=(LICENSE NOTICE THIRD_PARTY_NOTICES THIRD_PARTY_DEPENDENCIES.json THIRD_PARTY_LICENSES.txt THIRD_PARTY_LICENSES.tsv)

# Package as `sitecmd` with its notices and the checksum install.sh verifies.
case "$TARGET" in
  windows-x86_64)
    ARCHIVE="sitecmd-cli_${VERSION}_${TARGET}.zip"
    (cd "$DIST" && 7z a -bd "$GITHUB_WORKSPACE/$ARCHIVE" \
      sitecmd.exe "${CLI_LEGAL_FILES[@]}" >/dev/null)
    ;;
  *)
    ARCHIVE="sitecmd-cli_${VERSION}_${TARGET}.tar.gz"
    tar -C "$DIST" -czf "$ARCHIVE" sitecmd "${CLI_LEGAL_FILES[@]}"
    ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
else
  shasum -a 256 "$ARCHIVE" > "${ARCHIVE}.sha256"
fi
echo "archive=$ARCHIVE" >> "$GITHUB_OUTPUT"
echo "version=$VERSION" >> "$GITHUB_OUTPUT"
