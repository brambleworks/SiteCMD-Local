set -euo pipefail
VERSION="${TAG_NAME#v}"
CLI_VERSION=$(node --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { VERSION_FILES } from "./tools/scripts/lib/version-files.mjs";
  const cli = VERSION_FILES[0];
  const version = cli.read(readFileSync(cli.file, "utf8"));
  if (!version) throw new Error("Cannot read the CLI version.");
  console.log(version);
')
if [ "$VERSION" != "$CLI_VERSION" ]; then
  echo "::error::Tag version $VERSION does not match the protected source version $CLI_VERSION."
  exit 1
fi

TAG_COMMIT=$(git rev-list -n 1 "$TAG_NAME")
if [ "$TAG_COMMIT" != "$SOURCE_COMMIT" ]; then
  echo "::error::Tag resolves to $TAG_COMMIT, but the workflow source commit is $SOURCE_COMMIT."
  exit 1
fi

# Read notes from the changelog, not the signed tag body.
NOTES=$(node ./tools/scripts/check-changelog-notes.mjs --release-notes "$VERSION")
if [ -z "$NOTES" ]; then
  echo "::error::Release $VERSION has no changelog notes."
  exit 1
fi
PUB_DATE=$(git for-each-ref \
  --format='%(taggerdate:iso-strict)' "refs/tags/$TAG_NAME")
if [ -z "$PUB_DATE" ]; then
  echo "::error::Release tag has no stable tagger date."
  exit 1
fi

mkdir -p release-candidate
WORKFLOW_SHA=$(sha256sum .github/workflows/release.yml | awk '{print $1}')
PNPM_LOCK_SHA=$(sha256sum pnpm-lock.yaml | awk '{print $1}')
CARGO_LOCK_SHA=$(sha256sum apps/desktop/src-tauri/Cargo.lock | awk '{print $1}')
ENGINE_LOCK_SHA=$(sha256sum engine.lock | awk '{print $1}')
ENGINE_VERSION=$(jq -er '.version' engine.lock)
ENGINE_SHA256=$(jq -er '.sha256' engine.lock)
jq -n \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg tag "$TAG_NAME" \
  --arg version "$VERSION" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg default_branch "$DEFAULT_BRANCH" \
  --arg workflow_ref "$WORKFLOW_REF" \
  --arg workflow_sha256 "$WORKFLOW_SHA" \
  --arg pnpm_lock_sha256 "$PNPM_LOCK_SHA" \
  --arg cargo_lock_sha256 "$CARGO_LOCK_SHA" \
  --arg engine_lock_sha256 "$ENGINE_LOCK_SHA" \
  --arg engine_version "$ENGINE_VERSION" \
  --arg engine_sha256 "$ENGINE_SHA256" \
  --arg pub_date "$PUB_DATE" \
  --arg notes "$NOTES" \
  '{
    schema_version: 1,
    repository: $repository,
    run_id: $run_id,
    tag: $tag,
    version: $version,
    source_commit: $source_commit,
    default_branch: $default_branch,
    workflow_ref: $workflow_ref,
    workflow_sha256: $workflow_sha256,
    pnpm_lock_sha256: $pnpm_lock_sha256,
    cargo_lock_sha256: $cargo_lock_sha256,
    engine_lock_sha256: $engine_lock_sha256,
    engine_version: $engine_version,
    engine_sha256: $engine_sha256,
    preflight: "passed",
    pub_date: $pub_date,
    notes: $notes
  }' > release-candidate/manifest.json

CANDIDATE_HASH=$(sha256sum release-candidate/manifest.json | awk '{print $1}')
printf '%s  manifest.json\n' "$CANDIDATE_HASH" > release-candidate/SHA256SUMS
{
  echo "candidate_hash=$CANDIDATE_HASH"
  echo "source_commit=$SOURCE_COMMIT"
  echo "version=$VERSION"
} >> "$GITHUB_OUTPUT"
{
  echo "## Production release approval"
  echo
  echo "| Field | Immutable value |"
  echo "| --- | --- |"
  echo "| Tag | \`$TAG_NAME\` |"
  echo "| Version | \`$VERSION\` |"
  echo "| Protected source commit | \`$SOURCE_COMMIT\` |"
  echo "| Candidate manifest SHA-256 | \`$CANDIDATE_HASH\` |"
  echo "| Engine version | \`$ENGINE_VERSION\` |"
  echo "| Engine SHA-256 | \`$ENGINE_SHA256\` |"
  echo "| Workflow SHA-256 | \`$WORKFLOW_SHA\` |"
  echo
  echo "Approve the pending \`release-signing\` deployment only after checking these values and the manifest artifact."
} >> "$GITHUB_STEP_SUMMARY"
