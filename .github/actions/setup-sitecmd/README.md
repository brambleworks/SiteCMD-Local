# Set up the SiteCMD CLI

Downloads an exact Linux x86_64 or arm64 CLI release, verifies its minisign signature
against the updater trust root committed with the action, checks the binary's
reported version, and adds it to `PATH`.

Pin the action to the full commit for the SiteCMD release you trust. A mutable
branch such as `main` is not a supply-chain boundary.

```yaml
permissions:
  contents: read

steps:
  - uses: brambleworks/SiteCMD-Local/.github/actions/setup-sitecmd@<full-release-commit-sha>
    with:
      version: <version>
  - run: sitecmd audit . --fail-on high --format sarif --output sitecmd.sarif
  - uses: github/codeql-action/upload-sarif@<full-commit-sha>
    with:
      sarif_file: sitecmd.sarif
```

The release pipeline publishes the archive and its `.sig` sidecar together.
The action refuses an unsigned archive, a signature from another key, a
non-exact version, or a binary whose `--version` output does not match.
