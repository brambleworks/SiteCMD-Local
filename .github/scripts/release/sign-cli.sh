set -euo pipefail
VERSION="${GITHUB_REF_NAME#v}"
DIST="$RUNNER_TEMP/cli-dist"

BIN="$DIST/sitecmd"
if [ "$TARGET" = "windows-x86_64" ]; then BIN="$DIST/sitecmd.exe"; fi
test -f "$BIN" && test ! -L "$BIN" || exit 1
chmod +x "$BIN"

if [[ "$TARGET" == darwin-* ]]; then
  : "${APPLE_CERTIFICATE:?macOS CLI signing requires APPLE_CERTIFICATE}"
  : "${APPLE_SIGNING_IDENTITY:?macOS CLI signing requires APPLE_SIGNING_IDENTITY}"
  KC="$RUNNER_TEMP/sitecmd-signing.keychain-db"
  CERT="$RUNNER_TEMP/sitecmd-signing.p12"
  API_KEY="$RUNNER_TEMP/asc_api_key.p8"
  trap 'rm -f "$CERT" "$API_KEY"; security delete-keychain "$KC" >/dev/null 2>&1 || true' EXIT
  (umask 077
    printf '%s' "$APPLE_CERTIFICATE" | tr -d '\r' | base64 --decode > "$CERT"
    printf '%s' "$APPLE_API_KEY_P8_B64" | tr -d '\r' | base64 --decode > "$API_KEY"
  )
  security create-keychain -p "$KEYCHAIN_PASSWORD" "$KC"
  security set-keychain-settings -lut 21600 "$KC"
  security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KC"
  security import "$CERT" -k "$KC" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KC" >/dev/null
  rm -f "$CERT"
  codesign --force --options runtime --timestamp --keychain "$KC" \
    --sign "$APPLE_SIGNING_IDENTITY" "$DIST/sitecmd"

  team_id=$(codesign -dv --verbose=4 "$DIST/sitecmd" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2}')
  test -n "$team_id"
  test "$team_id" = "$APPLE_TEAM_ID"
  printf 'team_id=%s\n' "$team_id" >> "$GITHUB_OUTPUT"

  NOTARY_DIR="$RUNNER_TEMP/cli-notarization"
  mkdir -p "$NOTARY_DIR"
  NOTARY_AUTH=(--key "$API_KEY"
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
