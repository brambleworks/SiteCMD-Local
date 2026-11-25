# SiteCMD Documentation

This directory contains maintained engineering notes, product references, QA runbooks, and operational guides.

Use `docs/` only for information that should be treated as current project truth. Generated plans, review transcripts, one-off audits, acceptance-test results, design exports, and other session artifacts stay outside Git. Promote a durable conclusion into the appropriate document instead of preserving the working transcript.

## Sections

- `engineering/` - architecture, tooling, naming conventions, and the connected-service implementation specifications (protocol and state, alert delivery, maintained surfaces). The business strategy records those specifications fulfill (the publication decision, the connected-service architecture, the commercial terms, and the paid intelligence architecture) are maintained privately in the SiteCMD-Web repository and are named here in plain text only.
- `operations/` - release and launch-smoke runbooks
- `product/` - product behavior and scanner accuracy
- `qa/` - scanner input and fuzz verification

## High-Signal Entry Points

- [Code Scan audit and rules](../README.md#code-scan-audit) (local CLI usage and rule inventory fields)
- [Connected service implementation specifications](engineering/connected-service/connected-protocol-spec.md) (protocol and state, alert delivery, and maintained surfaces)
- [Maintained-surface matrix](engineering/connected-service/maintained-surfaces.md)
- [Native workspace tests](qa/native-tests.md)
- [AI-assisted development](engineering/ai-assisted-development.md) (how coding agents are directed, and what automated review does and does not stand in for)
- [Public repository and release security](engineering/repository-release-security-spec.md)
- [Releasing SiteCMD](operations/releasing.md)

## Historical procedures

- [Public repository cutover](operations/publication-checklist.md) (historical: executed 2026-08-21 when the repository became public; kept as the record of the in-place rewrite and the settings it restored)
