set -euo pipefail
mkdir -p signed-release-payload

stage_payload() {
  local src="signing-input/$1" dst="signed-release-payload/$1"
  mkdir -p "$dst"
  cp "$src"/* "$dst/"
  : > "$dst/SHA256SUMS"
  for file in "$dst"/*; do
    [ "$(basename "$file")" = "SHA256SUMS" ] && continue
    hash=$(sha256sum "$file" | awk '{print $1}')
    printf '%s  %s\n' "$hash" "$(basename "$file")" >> "$dst/SHA256SUMS"
  done
}

while IFS=$'\t' read -r target cli_archive; do
  src="signing-input/$target"
  test -s "$src/$cli_archive.sig"
  jq \
    --arg candidate_hash "$CANDIDATE_HASH" \
    --arg source_commit "$SOURCE_COMMIT" \
    '. + {candidate_hash: $candidate_hash, source_commit: $source_commit}' \
    "$src/fragment.json" > "$src/fragment.signed.json"
  mv "$src/fragment.signed.json" "$src/fragment.json"
  stage_payload "$target"
done < cli-signing-plan.tsv

for manifest in SHA256SUMS SHA256SUMS.sig SHA256SUMS.minisig; do
  test -s "signing-input/$manifest"
  cp "signing-input/$manifest" "signed-release-payload/$manifest"
done
