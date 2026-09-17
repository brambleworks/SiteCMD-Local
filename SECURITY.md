# Security Policy

## Supported versions

Security fixes are provided for the latest public SiteCMD release. Older releases may not receive fixes.

| Version               | Supported |
| --------------------- | --------- |
| Latest public release | Yes       |
| Earlier releases      | No        |

The connected service has no versions to support: it runs one deployed version, and a fix reaches every user when it ships.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

1. Preferred: [open a private vulnerability report on GitHub](https://github.com/brambleworks/SiteCMD-Local/security/advisories/new). Private vulnerability reporting is enabled for this repository, and the report stays between you and the maintainers until a fix is coordinated.
2. Otherwise: email `security@sitecmd.com` with `SECURITY` in the subject line. Encrypt anything sensitive to the OpenPGP key committed at [`.github/security-contact-key.asc`](.github/security-contact-key.asc).

Fingerprint: `16608F9F6D2C5BDA357311C75209E4BCF71B88E0`

Include:

- the affected component and version
- the expected and observed behavior
- steps or a minimal proof of concept
- the practical impact
- any suggested mitigation

Do not include credentials, customer data, private source code, or unrelated scan findings. If sensitive supporting material is necessary, encrypt it to the key above or ask for a secure transfer method first.

We acknowledge reports within three business days, assess severity and scope, coordinate a fix when appropriate, and credit the reporter if requested. Please allow time for remediation before public disclosure.

## Scope

In scope, on the machine:

- The desktop app, the CLI, the MCP server, and the GitHub Action.
- The official update path and the release and signing infrastructure.
- Local credential handling, the privileged-command broker, and the outbound network policy.

In scope, in the connected service:

- The connected API, the hosted scanner, the deploy-webhook receivers, alert delivery, and hosted report links.
- Credential scoping: any way an installation token, CI token, webhook secret, report link, or single-use capability token grants more than its stated job.
- Tenant isolation: any way one account's sites, findings, baselines, or alerts become reachable from another.
- The hosted scanner's target validation, which accepts URLs and launches browsers and is therefore treated as a server-side request forgery and open-proxy boundary rather than an implementation detail.

**Privacy-boundary reports are security reports.** SiteCMD's stated boundary is that no source code, file contents, raw file paths, or code-scan evidence ever reaches a SiteCMD service, and that code locations travel only as keyed hashes under a key that stays on the user's machine. Report anything that breaks it, including a payload field that carries content the published schema does not describe, a code-location value that is not keyed, or a log, trace, or error report that captures material the boundary excludes. Those are handled as vulnerabilities even when nothing is exploitable in the usual sense, because the boundary is the product.

The boundaries themselves are documented at [sitecmd.com/trust](https://sitecmd.com/trust) and [sitecmd.com/privacy](https://sitecmd.com/privacy), and the app's complete outbound egress is enumerated in its network facts. A disagreement between those surfaces and what the software actually does is worth reporting even if you cannot show harm.

Out of scope:

- Automated scans of SiteCMD infrastructure without prior authorization, denial-of-service and load testing, and social engineering.
- Testing third-party services through SiteCMD, and scanning or connecting any site you do not own or have written permission to test. The scanner does what you point it at; pointing it at someone else is your act, not a finding.
- Reports that a local subscription label can be changed in a fork. The local
  workbench has no paid feature lock. Bypassing tenant, credential, or
  connected-service entitlement checks remains in scope because those protect
  hosted data and operations.

Good-faith research that follows this policy will not be treated as malicious activity. This statement does not authorize testing that violates applicable law or a third party's rights.
