set -euo pipefail

install_dir="$RUNNER_TEMP/minisign"
mkdir -p "$install_dir"
cd "$install_dir"
curl --fail --silent --show-error --location --output minisign.tar.gz \
  https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz
printf '%s  minisign.tar.gz\n' '9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73' | \
  sha256sum -c -
tar -xzf minisign.tar.gz --strip-components=2 minisign-linux/x86_64/minisign
printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
