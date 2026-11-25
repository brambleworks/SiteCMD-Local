#!/usr/bin/env bash
set -euo pipefail

title="Dependency advisory audit failed"
body="The weekly dependency advisory audit failed. See $RUN_URL for the audit output."
issue=$(gh issue list --repo "$GH_REPO" --state open --limit 100 \
  --search "\"$title\" in:title" --json number,title \
  --jq '[.[] | select(.title == "Dependency advisory audit failed")][0].number // empty')
if [[ -n "$issue" ]]; then
  gh issue edit "$issue" --repo "$GH_REPO" --body "$body"
else
  gh issue create --repo "$GH_REPO" --title "$title" --body "$body"
fi
