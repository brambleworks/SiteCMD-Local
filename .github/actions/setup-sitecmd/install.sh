#!/usr/bin/env bash
set -euo pipefail

action_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
version=${SITECMD_VERSION:-}
install_dir=${SITECMD_INSTALL_DIR:-${RUNNER_TEMP:-/tmp}/sitecmd-bin}

if [[ -z "$version" ]]; then
  repository_root=$(cd "$action_dir/../../.." && pwd)
  version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' \
    "$repository_root/apps/desktop/src-tauri/Cargo.toml" | head -n 1)
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "SiteCMD setup requires an exact release version, got: ${version:-<empty>}" >&2
  exit 2
fi
if [[ -z "$install_dir" ]]; then
  echo "SiteCMD setup could not determine an installation directory." >&2
  exit 2
fi
case "$(uname -s) $(uname -m)" in
  "Linux x86_64") target="linux-x86_64" ;;
  "Linux aarch64" | "Linux arm64") target="linux-aarch64" ;;
  *)
    echo "The GitHub Actions setup currently supports Linux x86_64 and arm64 runners only." >&2
    exit 2
    ;;
esac
for command in curl base64 minisign tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command is unavailable: $command" >&2
    exit 2
  fi
done

archive="sitecmd-cli_${version}_${target}.tar.gz"
release_url="https://releases.sitecmd.com/v${version}"
temporary_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/sitecmd-setup.XXXXXX")
install_candidate=
cleanup() {
  rm -rf "$temporary_dir"
  if [[ -n "$install_candidate" ]]; then
    rm -f "$install_candidate"
  fi
}
trap cleanup EXIT

curl --fail --silent --show-error --location --retry 3 \
  --proto '=https' --tlsv1.2 \
  --output "$temporary_dir/$archive" "$release_url/$archive"
curl --fail --silent --show-error --location --retry 3 \
  --proto '=https' --tlsv1.2 \
  --output "$temporary_dir/$archive.sig" "$release_url/$archive.sig"

tr -d '\r\n' < "$temporary_dir/$archive.sig" | \
  base64 --decode > "$temporary_dir/$archive.minisig"
minisign -Vm "$temporary_dir/$archive" \
  -x "$temporary_dir/$archive.minisig" \
  -p "$action_dir/updater-public-key.pub"

mkdir -p "$temporary_dir/unpacked" "$install_dir"
tar -C "$temporary_dir/unpacked" -xzf "$temporary_dir/$archive"
test -x "$temporary_dir/unpacked/sitecmd"
actual_version=$("$temporary_dir/unpacked/sitecmd" --version)
if [[ "$actual_version" != "sitecmd $version" ]]; then
  echo "Downloaded CLI reported '$actual_version', expected 'sitecmd $version'." >&2
  exit 1
fi
install_candidate=$(mktemp "$install_dir/.sitecmd.XXXXXX")
install -m 0755 "$temporary_dir/unpacked/sitecmd" "$install_candidate"
mv "$install_candidate" "$install_dir/sitecmd"
install_candidate=
