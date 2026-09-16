# Fix Your First Issue

This guide is for the first real pass through SiteCMD, especially if you are working solo or with an AI coding tool.

## Pick the right first issue

Open `Issues` and choose something that is:

- important enough to matter
- narrow enough to finish quickly
- easy to verify afterward

Good first candidates:

- missing security headers
- broken canonical or metadata
- obvious broken links
- dependency updates with a clear package target

Less ideal first candidates:

- large design rewrites
- low-confidence polish findings
- anything you cannot verify afterward

## Read the issue like a task, not like a score

Before you change code, make sure you can answer:

- what is wrong
- why it matters
- where the fix probably lives
- how you will prove it is fixed

If you cannot answer those four things, stop and tighten the plan before you edit anything.

## Make one clean change

Use the issue detail to drive the work.

Depending on the issue, that may mean:

- editing app code
- updating metadata
- changing server config
- fixing a package version
- repairing a broken external or internal link

For an AI coding tool, connect it from **Integrations** or follow the [MCP setup guide](../../apps/mcp-server/README.md). Choose **Fix with your agent** on the issue, or ask the agent to open an attempt with `start_fix`. It reads `get_fix_brief` for the target and acceptance criteria before editing.

## Verify immediately

Do not assume the fix worked just because the code looks right.

Use the SiteCMD follow-up flow:

- For a live-site finding, deploy the change to the URL you scanned; source changes alone do not change that website.
- Use **Verify**, or have the agent call `request_verification` and poll `get_fix_status` while SiteCMD is running.
- Review the verdict and evidence. SiteCMD determines whether the issue cleared; the agent does not declare itself successful.
- Run a broader scan if needed. `compare_scans` compares Web Scans; use current findings and the verification verdict for Code Scan changes.

You want a clear before/after outcome, not a guess.

## Decide what happens next

After the first fix, one of these should be true:

- the issue is resolved
- the issue improved but still needs work
- the finding does not apply and you use **Block** with a reason, or suppress a reviewed Code Scan occurrence in project configuration

That decision matters. A trustworthy tool does not just point at problems. It helps you close the loop cleanly.

## If you linked a local repo

The first Full Scan should already include Code Scan when the project folder is linked.

Use the linked code findings to move from "the site looks wrong" to "here is the file or code path most likely causing it." If Code Scan did not run, open the project settings, confirm the folder is linked, and run another Full Scan.
