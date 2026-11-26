# Release workflow helpers

These Bash scripts hold the substantial build, signing, and verification steps
called by `release.yml`. They run from the repository root and receive all
inputs through each workflow step's `env` block.

The credentialed publication logic remains inline in the workflow. Its job does
not check out repository code, so publishing cannot execute a script from the
source tree.

To test the payload, build, and verification scripts, run:

```bash
pnpm exec vitest run tools/scripts/release-payload-scripts.test.mjs tools/scripts/release-cli-notarization.test.mjs
```
