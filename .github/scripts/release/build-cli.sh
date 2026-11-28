set -euo pipefail
VERSION="${GITHUB_REF_NAME#v}"
SRC="apps/desktop/src-tauri"
DIST="$SRC/target/cli-dist"
mkdir -p "$DIST"
export SITECMD_ENGINE_WASM="$GITHUB_WORKSPACE/engine/local-engine.wasm"
unset SITECMD_ENGINE_UNPINNED
test -s "$SITECMD_ENGINE_WASM"
test -s "$GITHUB_WORKSPACE/engine.lock"
test -s "$GITHUB_WORKSPACE/engine/local-engine.wasm.LICENSES.txt"

build_cli() {
  (cd "$SRC" && cargo build --manifest-path crates/cli/Cargo.toml \
    --release --locked --target "$1")
}
case "$TARGET" in
  darwin-universal)
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

# Check the tag version on the credential-free build runner.
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
