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

while IFS=$'\t' read -r target filename cli_archive; do
  src="signing-input/$target"
  sig_file="$src/$filename.sig"
  cli_sig_file="$src/$cli_archive.sig"
  test -s "$sig_file"
  test -s "$cli_sig_file"
  artifact_hash=$(sha256sum "$src/$filename" | awk '{print $1}')
  signature=$(cat "$sig_file")
  jq \
    --arg signature "$signature" \
    --arg artifact_sha256 "$artifact_hash" \
    --arg candidate_hash "$CANDIDATE_HASH" \
    --arg source_commit "$SOURCE_COMMIT" \
    '. + {
      signature: $signature,
      artifact_sha256: $artifact_sha256,
      candidate_hash: $candidate_hash,
      source_commit: $source_commit
    }' "$src/fragment.json" > "$src/fragment.signed.json"
  mv "$src/fragment.signed.json" "$src/fragment.json"
  stage_payload "$target"
done < signing-plan.tsv

# A CLI-only leg has no updater bundle, so its fragment carries provenance only.
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
