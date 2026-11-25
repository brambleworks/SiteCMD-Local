# Release smoke test

## Preconditions

- The release workflow is green for the exact commit and tag under review.
- Candidate hashes, CLI signatures, and platform
  signatures have passed the release verification jobs.
- Testers have the exact signed artifacts produced by that workflow. A local
  development build is not a substitute.
- Use a verified site in the account for the disposable test URL
  (`SITECMD_TEST_URL`) and an authorized source repository. Neither contains
  customer data or credentials.

Use the [manual testing runbook](../qa/manual-testing-runbook.md) for deeper
product review. This pass is the final artifact-level sanity check.

## CLI distribution

Install the signed CLI through the public installer or the signed Windows
archive. Do not use a locally compiled binary.

```bash
sitecmd --version
sitecmd login
sitecmd scan --url "$SITECMD_TEST_URL" --output text
sitecmd audit . --format summary
```

Confirm:

- the reported version matches the release tag
- the web scan returns findings and a score
- the code audit walks only the selected repository
- text, JSON, and GitHub output formats remain machine-readable where selected
- `--fail-on` returns the documented nonzero status against a controlled
  failing fixture and exits zero after the fixture is fixed or suppressed
- an invalid URL, missing directory, and invalid option fail with concise help
  and no panic or stack trace
- the public installer refuses a modified archive or signature
