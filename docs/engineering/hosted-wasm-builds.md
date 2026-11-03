# Hosted WASM builds

Build the check engine and scorer from the repository root:

```sh
node tools/scripts/build-checks-wasm.mjs --out /tmp/hosted-wasm/checks
node tools/scripts/build-scorer-wasm.mjs --out /tmp/hosted-wasm/scorer
```

The scripts write the WASM artifact, test corpora, artifact record, and supporting
data files: `browser-assets.json` for checks and `check-categories.json` for the
scorer. The checks output also includes `capability_manifest.json`; the record's
`capability_manifest_sha256` hashes that file's exact bytes, while `manifest_digest`
identifies the manifest content according to the engine's manifest contract.

To reproduce the vendored bytes, use the source revision, Rust toolchain, target,
profile, features, and `rustflags` recorded in `checks-artifact.json` or
`scorer-artifact.json`. The scorer uses the default, empty feature set. Both builds
use the `wasm-release` profile, optimized for hosted execution speed, and record
these exact flags:

```text
--remap-path-prefix=<CARGO_HOME>=/cargo
--remap-path-prefix=<REPO_ROOT>=/sitecmd
```

Replace `<CARGO_HOME>` with the absolute Cargo home (`CARGO_HOME`, or `~/.cargo`
when unset or empty) and `<REPO_ROOT>` with the absolute checkout root. The scripts
pass the expanded flags in `CARGO_ENCODED_RUSTFLAGS`, separated by `\x1f`, for the
WASM build. These flags replace the caller's `RUSTFLAGS`,
`CARGO_ENCODED_RUSTFLAGS`, and configured rustflags for these builds. The scripts
refuse a Cargo home inside the checkout because overlapping remaps produce
different registry paths. The WASM build uses `--locked` to prevent lockfile updates.

Before writing the vendored set, the scripts reject local Cargo home, checkout,
or user home paths in the artifact. The guard skips empty paths, filesystem roots,
and the portable placeholders `/cargo` and `/sitecmd`. A match must end at a path
boundary: the next byte cannot be an ASCII letter, digit, `.`, `_`, or `-`.
For single-segment paths such as `/src` and `/build`, the preceding byte must also
be NUL, marking the start of a string rather than a segment within another path.

The scripts read the artifact from
`apps/desktop/src-tauri/target/wasm32-unknown-unknown/wasm-release/sitecmd_engine_wasm.wasm`;
they do not read output from a redirected Cargo target directory.

Dirty build inputs are refused unless `--allow-dirty` is supplied. Such records
append `-dirty` to `engine_commit`; reproducing them also requires the same
uncommitted changes. A digest mismatch requires checking all recorded build
inputs, including the path remapping flags.

## DMARC resolver facts

DMARC policy discovery follows [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html).
The Author Domain remains the engine's existing registrable-domain target.
`ResolverPlan.dmarc_txt_name` names its initial TXT question, and
`dmarc_tree_walk_names` lists the possible parent TXT questions in discovery order.
An adapter that gathers facts before evaluation must gather every listed name;
evaluation ignores answers discovery does not reach.
Each question must pass through the adapter's existing DNS accounting and request
envelope. Do not hide recursive resolver work inside a single budgeted question.

Return the initial answer as `ResolverFacts.dmarc_txt` and each answered parent
question as a `{ name, txt }` entry in `dmarc_tree_walk`. An omitted parent answer
is unavailable evidence, so evaluation skips when discovery needs that answer.
Older facts still deserialize, but hosted consumers must gather the new facts
before deploying this engine to preserve missing-policy findings. Native adapters
drive `DmarcStep::NeedsTxt` one question at a time until `NeedsMx` or `Done`.

The maximum is eight DMARC TXT questions, including the initial question, plus
one MX question at the Author Domain. For targets with 2, 3, and 13 labels, the
respective maxima are 3, 4, and 9 DNS questions. URL host labels removed by
`registrable_domain_for_url` do not contribute to these counts. No other email or
registration check changes its target.
