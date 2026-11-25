#!/usr/bin/env bash
set -euo pipefail

install_dir="${SITECMD_INSTALL_DIR:-${RUNNER_TEMP}/sitecmd-bin}"
if [[ "$install_dir" == *$'\r'* || "$install_dir" == *$'\n'* ]]; then
  echo "SiteCMD install-dir must fit on one PATH entry." >&2
  exit 2
fi
printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
