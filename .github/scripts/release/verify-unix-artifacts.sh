set -euo pipefail
dir="payload/$TARGET"
cli_archive=$(jq -r '.cli_archive' "$dir/fragment.json")
mkdir cli-check
tar -C cli-check -xzf "$dir/$cli_archive"
for legal_file in LICENSE NOTICE THIRD_PARTY_NOTICES THIRD_PARTY_DEPENDENCIES.json THIRD_PARTY_LICENSES.txt THIRD_PARTY_LICENSES.tsv; do
  test -s "cli-check/$legal_file"
done
if [ "$TARGET" = "darwin-universal" ]; then
  codesign --verify --strict cli-check/sitecmd
  # Apple's check for non-app code consults online notarization tickets.
  codesign -vvvv -R="notarized" --check-notarization cli-check/sitecmd
  filename=$(jq -r '.filename' "$dir/fragment.json")
  dmg_name=$(jq -r '.dmg_name' "$dir/fragment.json")
  mkdir app-check
  tar -C app-check -xzf "$dir/$filename"
  app=$(find app-check -maxdepth 1 -type d -name '*.app' -print -quit)
  test -n "$app"
  codesign --verify --deep --strict "$app"
  spctl -a -vv -t exec "$app"
  codesign --verify --strict "$dir/$dmg_name"
  xcrun stapler validate "$dir/$dmg_name"
  cli_team=$(codesign -dv --verbose=4 cli-check/sitecmd 2>&1 | \
    awk -F= '/^TeamIdentifier=/{print $2}')
  app_team=$(codesign -dv --verbose=4 "$app" 2>&1 | \
    awk -F= '/^TeamIdentifier=/{print $2}')
  test -n "$cli_team"
  test "$cli_team" = "$app_team"
fi
test "$(cli-check/sitecmd --version)" = "sitecmd $EXPECTED_VERSION"
