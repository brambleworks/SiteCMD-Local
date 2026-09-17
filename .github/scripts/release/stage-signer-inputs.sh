set -euo pipefail
test "$(sha256sum release-candidate/manifest.json | awk '{print $1}')" = \
  "$EXPECTED_CANDIDATE_HASH"
test "$(jq -r '.source_commit' release-candidate/manifest.json)" = \
  "$EXPECTED_SOURCE_COMMIT"

safe_name() {
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'
}

mkdir -p signing-input
: > signing-plan.tsv
: > cli-signing-plan.tsv
count=0
cli_count=0
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
  filename=$(jq -r '.filename // empty' "$fragment")
  cli_archive=$(jq -r '.cli_archive' "$fragment")
  dmg_name=$(jq -r '.dmg_name // empty' "$fragment")
  if [ -n "$filename" ]; then
    case "$target" in
      darwin-universal|linux-x86_64|windows-x86_64) ;;
      *) echo "::error::Unexpected signer target: $target"; exit 1 ;;
    esac
    safe_name "$filename"
    if [ -n "$dmg_name" ]; then safe_name "$dmg_name"; fi
    test -f "$src/$filename" && test ! -L "$src/$filename"
    if [ -n "$dmg_name" ]; then
      test -f "$src/$dmg_name" && test ! -L "$src/$dmg_name"
    fi
  else
    # A CLI-only leg ships no updater bundle, so only its archive is signed.
    case "$target" in
      linux-aarch64) ;;
      *) echo "::error::Unexpected CLI-only signer target: $target"; exit 1 ;;
    esac
    if [ -n "$dmg_name" ]; then
      echo "::error::CLI-only signer target $target carries a DMG: $dmg_name"
      exit 1
    fi
  fi
  safe_name "$cli_archive"
  test -f "$src/$cli_archive" && test ! -L "$src/$cli_archive"
  test -f "$src/${cli_archive}.sha256" && test ! -L "$src/${cli_archive}.sha256"

  dst="signing-input/$target"
  mkdir -p "$dst"
  cp "$src/$cli_archive" "$src/${cli_archive}.sha256" "$dst/"
  cp "$fragment" "$dst/fragment.json"
  if [ -n "$filename" ]; then
    cp "$src/$filename" "$dst/"
    if [ -n "$dmg_name" ]; then cp "$src/$dmg_name" "$dst/"; fi
    printf '%s\t%s\t%s\n' "$target" "$filename" "$cli_archive" >> signing-plan.tsv
    count=$((count + 1))
  else
    printf '%s\t%s\n' "$target" "$cli_archive" >> cli-signing-plan.tsv
    cli_count=$((cli_count + 1))
  fi
done
test "$count" -eq 3
test "$cli_count" -eq 1
