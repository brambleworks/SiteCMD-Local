# Verify the engine boundary

SiteCMD's promise is that your code never reaches SiteCMD, and the only place anything code-derived leaves your machine is your own repository, on your explicit autofix command, in requests the open host builds and checks.

## 1. Read the host

Only [`sitecmd-engine-host`](../../apps/desktop/src-tauri/crates/engine-host/)
depends on Wasmtime. It defines no imports and refuses modules that ask for
any. In an audit, the host walks the project in
[`src/core/project_listing.rs`](../../apps/desktop/src-tauri/src/core/project_listing.rs).
It sends the listing and the `AuditHostFacts` built in
[`src/core/engine_facts/`](../../apps/desktop/src-tauri/src/core/engine_facts/) to
the module.

The host handles the module's requests in
[`src/wants.rs`](../../apps/desktop/src-tauri/crates/engine-host/src/wants.rs) and
the [audit session](../../apps/desktop/src-tauri/src/core/audit/audit_session.rs).

- `analyze_files` runs engine analysis on file snapshots the host already read.
- `file` reads eligible text by path from the listing.
- `offered_file` reads eligible text by its host-assigned file ID.
- `git_tracked` checks which listed paths are in the Git index.
- `git_tracked_offers` checks which offered file IDs refer to files in the Git index.
- `path_presence` probes validated paths under the project root for metadata only, even for paths outside the listing.
- `database_schema` reads schema metadata for a local database the host offered.

The module returns findings to the host, which formats the report.

## 2. Inspect the shipped module

The CLI runs the precompiled `local-engine.cwasm`. The
[loader](../../apps/desktop/src-tauri/crates/engine-host/src/load.rs) checks
the embedded original `.wasm` against the pin, deserializes the precompiled
module, and checks imports on the deserialized module.

`sitecmd engine info` prints the module version, SHA-256, import count, and
exports. `sitecmd engine info --save engine.wasm` writes out the original
`.wasm` bytes after the digest check.
To check that the import list is empty, run this in a Node.js REPL in the
directory where you saved the file:

```js
const bytes = require("node:fs").readFileSync("engine.wasm");
console.log(WebAssembly.Module.imports(new WebAssembly.Module(bytes)));
```

It prints `[]`. The module on SiteCMD's releases host has the same bytes.
Compare its SHA-256 with the digest that `sitecmd engine info` prints.

## 3. Trace the requests

Every request comes from open code:

- Connect's API handles sign-in, hosted scans, connected submissions,
  `deploy`, `gate`, and autofix jobs.
- The host fetches the localhost page for a local site scan.
- The host contacts local databases only with `--inspect-local-databases`.
- The Action's publish workflow runs `sitecmd autofix publish-job` when you
  request autofix publication. The job sends pull requests and issues to your
  own GitHub repository.
- `sitecmd connect` uses `api.github.com` to fetch the repository's public key
  and write encrypted repository secrets for the connection export and
  passphrase. The requests use a GitHub token.
- Attested CI submissions and autofix jobs such as `run-job` request an OIDC
  token from `actions.githubusercontent.com` or
  `*.actions.githubusercontent.com`. The request carries GitHub Actions'
  request token and audience.

Neither GitHub request carries source code.

[sitecmd.com/trust](https://sitecmd.com/trust) lists the hosts.

## 4. Inspect what the host sends

Module output reaches the network only through open request builders. For a
code submission, the host computes `location_hash` as an HMAC over the producer
rule ID and relative path, never the line number, with a key the module never
sees. The host gets the producer rule ID from the public
`identity::code_producer_rule_id` mapping and computes `instance_count` itself.
A check ID must appear in the `engine_info` inventory. Severity and confidence
use closed enums.

`sitecmd connected --dry-run` prints the exact serialized bytes for the
snapshot it builds without sending them. `CodeOccurrence` contains a check ID,
a location hash, a count, a severity, a confidence, and a provenance.

For an autofix publish job, the host builds the GitHub requests. It checks
that patches apply to files in the listing, redacts and sanitizes the issue
body, and checks the body against file content given to the module. It refuses
to publish an issue body that contains file lines beyond the patch's own lines.
