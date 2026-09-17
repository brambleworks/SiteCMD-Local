set -euo pipefail
# Publish the verified CLI binaries to npm as @sitecmd/cli plus one platform
# package per target. Runs only after publish-release has the version live on
# releases.sitecmd.com, re-verifies each payload directory's checksums, and
# skips any package version npm already has, so a re-run repairs a partial
# publication instead of conflicting with it. The binaries are the exact
# signed release artifacts; nothing is rebuilt here.

test -n "$VERSION"
NPM_DIR="packaging/npm"
mkdir -p "${RUNNER_TEMP:-/tmp}"
STAGE=$(mktemp -d "${RUNNER_TEMP:-/tmp}/sitecmd-npm.XXXXXX")

stamp_version() {
  (cd "$1" && npm pkg set version="$VERSION" >/dev/null)
}

publish_package() {
  local dir=$1 name
  name=$(node -e "console.log(require('$PWD/$dir/package.json').name)")
  if npm view "${name}@${VERSION}" version >/dev/null 2>&1; then
    echo "npm already has ${name}@${VERSION}; leaving it as published."
    return 0
  fi
  (cd "$dir" && npm publish --provenance --access public)
}

stage_platform() {
  local pkg=$1 target=$2 bin=$3
  local dir="payload/$target"
  local archive="sitecmd-cli_${VERSION}_${target}"
  (cd "$dir" && sha256sum -c SHA256SUMS >/dev/null)
  local extract="$STAGE/$target"
  mkdir -p "$extract"
  if [ "$target" = "windows-x86_64" ]; then
    unzip -q "$dir/${archive}.zip" -d "$extract"
  else
    tar -xzf "$dir/${archive}.tar.gz" -C "$extract"
  fi
  local pkg_dir="$NPM_DIR/$pkg"
  install -m 0755 "$extract/$bin" "$pkg_dir/bin/$bin"
  cp "$extract/LICENSE" "$extract/NOTICE" "$extract/THIRD_PARTY_NOTICES" \
    "$extract/THIRD_PARTY_DEPENDENCIES.json" \
    "$extract/THIRD_PARTY_LICENSES.txt" "$extract/THIRD_PARTY_LICENSES.tsv" \
    "$pkg_dir/"
  stamp_version "$pkg_dir"
  publish_package "$pkg_dir"
}

stage_platform cli-darwin-universal darwin-universal sitecmd
stage_platform cli-linux-x64 linux-x86_64 sitecmd
stage_platform cli-linux-arm64 linux-aarch64 sitecmd
stage_platform cli-win32-x64 windows-x86_64 sitecmd.exe

# The launcher package pins its platform packages to this exact version so a
# lockfile resolves one coherent release.
MAIN="$NPM_DIR/cli"
cp LICENSE NOTICE "$MAIN/"
stamp_version "$MAIN"
for dep in cli-darwin-universal cli-linux-x64 cli-linux-arm64 cli-win32-x64; do
  (cd "$MAIN" && npm pkg set "optionalDependencies.@sitecmd/${dep}=${VERSION}" >/dev/null)
done
publish_package "$MAIN"
