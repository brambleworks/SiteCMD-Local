# Governance

SiteCMD is maintained by Brambleworks LLC. Brambleworks sets the product direction, appoints maintainers, owns the release infrastructure, and has final responsibility for repository and security decisions. Kyle Piontek, the founder of Brambleworks, is currently SiteCMD's sole maintainer.

## Decision-making

Maintainers use issues and discussions to gather evidence and explain material decisions. The responsible maintainer decides after considering user impact, privacy, security, compatibility, maintenance cost, and the accepted product direction.

Security-sensitive details may remain private until coordinated disclosure is safe. Engine source, commercial intelligence content, and service operations are managed outside the open-source repository.

## Changes

Every repository change is made on a short-lived branch, reviewed in a pull request, and merged only after required checks pass. Direct pushes and force pushes to the default branch are prohibited.

While SiteCMD has one maintainer, that maintainer necessarily authors and adjudicates changes. Automated review and deterministic checks provide additional scrutiny but are not represented as independent human approval. Sensitive paths will require a second human reviewer when another maintainer is appointed.

## External participation

Issues and discussion are welcome. Unsolicited code contributions are not accepted yet, and pull requests are limited to invited collaborators. Brambleworks may revisit this policy when there is demonstrated contribution demand and enough maintainer capacity to review and support external code responsibly.

See [CONTRIBUTING.md](CONTRIBUTING.md) for practical guidance and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.

## Releases

Only maintainers authorized by Brambleworks may approve or publish an official release. A release must come from a protected commit and pass the documented build, signing, verification, and human-approval process.

The Apache License 2.0 permits third parties to publish modified builds of the CLI source. Those builds are not official SiteCMD releases and may not imply endorsement or use SiteCMD trademarks beyond the license's limited descriptive allowance. The SiteCMD Engine Module License in [LICENSE](LICENSE) covers the embedded module.
