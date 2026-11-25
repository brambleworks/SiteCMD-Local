set -euo pipefail
test "$(sha256sum release-candidate/manifest.json | awk '{print $1}')" = \
  "$EXPECTED_CANDIDATE_HASH"
test "$(jq -r '.source_commit' release-candidate/manifest.json)" = \
  "$EXPECTED_SOURCE_COMMIT"

safe_name() {
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'
}

mkdir -p signing-input
: > cli-signing-plan.tsv
count=0
for fragment in unsigned/unsigned-platform-*/fragment.json; do
  src=$(dirname "$fragment")
  if find "$src" -maxdepth 1 -type l | grep -q .; then
    echo "::error::Signer input contains a symbolic link: $src"
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$src" && sha256sum -c SHA256SUMS)
  else
    (cd "$src" && shasum -a 256 -c SHA256SUMS)
  fi

  target=$(jq -r '.target' "$fragment")
  case "$target" in
    darwin-universal|linux-x86_64|linux-aarch64|windows-x86_64) ;;
    *) echo "::error::Unexpected CLI signer target: $target"; exit 1 ;;
  esac
  if ! jq -e 'keys - ["target", "cli_archive", "signer_identity"] == []' "$fragment" >/dev/null; then
    echo "::error::Unexpected fields in CLI signer input for $target."
    exit 1
  fi
  cli_archive=$(jq -r '.cli_archive' "$fragment")
  safe_name "$cli_archive"
  test -f "$src/$cli_archive" && test ! -L "$src/$cli_archive"
  test -f "$src/${cli_archive}.sha256" && test ! -L "$src/${cli_archive}.sha256"

  dst="signing-input/$target"
  if [ -e "$dst" ]; then
    echo "::error::Duplicate CLI signer target: $target"
    exit 1
  fi
  mkdir "$dst"
  cp "$src/$cli_archive" "$src/${cli_archive}.sha256" "$dst/"
  cp "$fragment" "$dst/fragment.json"
  printf '%s\t%s\n' "$target" "$cli_archive" >> cli-signing-plan.tsv
  count=$((count + 1))
done
test "$count" -eq 4
