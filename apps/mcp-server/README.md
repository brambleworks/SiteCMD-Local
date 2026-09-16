# sitecmd-mcp

MCP server for [SiteCMD](https://sitecmd.com) - lets AI coding tools read scan results and fix issues directly.

## What it does

This MCP server gives your AI coding tool (Cursor, Claude Code, Windsurf, etc.) direct access to your SiteCMD scan results. Your AI can:

- See the SiteCMD Score and open-issue counts
- List open issues with ids, locations, and confidence
- Read one issue with evidence and its fix prompt
- Get ready-to-use fix prompts
- Track web scan history

## Setup

The SiteCMD desktop app registers this server for you: open Integrations and
connect your agent tool (Claude Code, Cursor, Codex, or Windsurf). Install
Node.js 22.22.1+ first. SiteCMD validates that runtime and writes a config for
the persistent copy of its bundled server; no separate MCP package is needed.

SiteCMD does not treat a matching config key as proof that the connection
works. It compares the full command, arguments, and database environment, then
runs a bounded read-only health check against the configured server and
database. A stale path, old arguments, missing Node runtime, unreadable
database, or startup failure appears as **Repair**, with the detected reason;
it is never shown as connected until that probe succeeds.

Manual setup (rarely needed) requires Node.js 22.22.1+. The desktop copies the
server into persistent application data each time it starts. Point your agent
at that stable copy, not the app bundle or installation directory.

| OS      | Persistent MCP script                                                                                                                         |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS   | `~/Library/Application Support/com.sitecmd.app/sitecmd-mcp/sitecmd-mcp.mjs`                                                                   |
| Linux   | `$XDG_DATA_HOME/com.sitecmd.app/sitecmd-mcp/sitecmd-mcp.mjs` when set; otherwise `~/.local/share/com.sitecmd.app/sitecmd-mcp/sitecmd-mcp.mjs` |
| Windows | `%LOCALAPPDATA%\com.sitecmd.app\sitecmd-mcp\sitecmd-mcp.mjs`; `%APPDATA%` is used when `%LOCALAPPDATA%` is unavailable                        |

Use absolute paths in the example below unless your editor explicitly supports
the variable syntax you choose. Shell forms such as `~` are not portable across
editor configurations.

```json
{
  "mcpServers": {
    "sitecmd": {
      "command": "node",
      "args": [
        "--disable-warning=ExperimentalWarning",
        "/absolute/path/to/com.sitecmd.app/sitecmd-mcp/sitecmd-mcp.mjs"
      ]
    }
  }
}
```

## Requirements

- **SiteCMD** must be installed and have run at least one scan
- **Node.js** 22.22.1+ for manual setup and automatic connection

SiteCMD requires a maintenance release whose built-in `node:sqlite` runtime
passes the server's full test suite. Its automatic connection flow verifies the
Node version and SQLite support before writing agent configuration. Reads work
while the app is closed. Scan, start-fix, and verification work needs the app
running. Scan and start-fix requests can queue while it is stopped and expire
after 24 hours. Poll their status rather than treating a queued request as a
completed action. The warning flag keeps Node's SQLite experimental warning
from appearing as an editor startup error.

The bundled MCP server follows the desktop and CLI release version. Its package
is private and is released only as a desktop resource, so the MCP handshake,
package metadata, and SiteCMD release are bumped together.

## Tools

| Tool                   | Description                                                                                                       |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `get_projects`         | List projects with ids, URLs, frameworks, and linked folders                                                      |
| `get_scan_score`       | Current SiteCMD Score and counts, plus the latest scan artifact score as historical diagnostics                   |
| `get_issues`           | Open issues with id, check id, source, confidence, and location; filter by min_severity, category, min_confidence |
| `get_issue`            | One check with evidence, occurrences, fix prompt, causes, and attempt                                             |
| `get_fix_prompts`      | Fix prompts (default 5, max 20), or one by check_id                                                               |
| `get_scan_history`     | Get scan artifact score history over time                                                                         |
| `get_dismissed_issues` | List issues dismissed in SiteCMD or suppressed by .sitecmd/config.json                                            |
| `compare_scans`        | Compare two web scans by id (default: the two most recent)                                                        |
| `how_to_rescan`        | Explain the CLI and desktop steps that produce a fresh scan; does not queue one                                   |
| `get_fix_brief`        | Get the fix brief for a fix attempt, with acceptance criteria                                                     |
| `start_fix`            | Queue a fix attempt for one check or an exact Code Scan location; the running desktop app creates the attempt     |
| `get_fix_status`       | Read a fix attempt's status, verify timing, and failure detail                                                    |
| `run_scan`             | Queue web (default), code, or full scanning; the desktop app must be running to process it                        |
| `get_scan_status`      | Read a queued scan request's status and, once fulfilled, its execution id                                         |
| `request_verification` | Tell SiteCMD a fix is done so it can re-run the check and verify                                                  |
| `list_fix_attempts`    | List open fix attempts (include_settled for verified and failed ones)                                             |

`request_scan` is a deprecated alias of `how_to_rescan`; it will be removed in the next major release.

`get_issues` no longer accepts `severity` (exact match) or `status`; use `min_severity`.

`get_issues` lists every open finding the SiteCMD Score counts, so dependency
and integration findings appear beside web and code scan findings. Each issue
names its source, and the counts add up to the open-issue total in
`get_scan_score`.

### Choosing a Code Scan occurrence

Read `get_issue` for the check's current locations, then pass the chosen
`relative_path` and one-based `line` to `start_fix` with the same project, URL,
and `check_id`. Use `line: null` for a finding without a line number.

A path without a line is accepted only when it has one open occurrence. If
the location is missing, ambiguous, resolved, or suppressed, SiteCMD returns an
error instead of choosing a different occurrence. The desktop rechecks the
target when it processes the request. Omitting both fields keeps the default
behavior: SiteCMD chooses an occurrence for the check.

### Correlation tools

These read v3-enriched correlation data and are all read-only.

| Tool                      | Description                                                          |
| ------------------------- | -------------------------------------------------------------------- |
| `get_active_correlations` | Active issue groups with causes, effects, events, and anomaly scores |
| `get_recent_events`       | Site events tied to check IDs within the last N days                 |
| `get_likely_causes`       | Direct and transitive likely causes for a check ID                   |
| `get_causal_graph`        | Active causal graph as a node-link payload for visualization         |
| `preview_deploy_risk`     | Predict which active issues may regress from a set of changed files  |
| `whatif_resolve`          | Downstream effects of hypothetically resolving a set of issues       |

Every correlation tool accepts `project_id` or `url`.

## Example usage

Once connected, just ask your AI:

- "What's my current SiteCMD Score?"
- "Show me the critical security issues on my site"
- "Fix the CSP header issue on example.com"
- "What issues should I fix first to improve my SiteCMD score?"

## Configuration

The server auto-detects the SiteCMD database location:

| OS      | Path                                                       |
| ------- | ---------------------------------------------------------- |
| macOS   | `~/Library/Application Support/com.sitecmd.app/sitecmd.db` |
| Linux   | `~/.local/share/com.sitecmd.app/sitecmd.db`                |
| Windows | `%LOCALAPPDATA%/com.sitecmd.app/sitecmd.db`                |

On Linux, `$XDG_DATA_HOME` replaces `~/.local/share` when set. On Windows, the
server falls back to `%APPDATA%` when `%LOCALAPPDATA%` is unavailable. Override
the resolved path with the `SITECMD_DB_PATH` environment variable if needed.

## Access and privacy

The server runs locally as the editor's user without a separate MCP API key.
Configuring it grants that editor access to every project in the selected
SiteCMD database. Project IDs and URLs filter queries; they do not enforce
project-level authorization. Editor tool approvals control when tools run.

The stdio connection is local, but findings, evidence, and source excerpts
returned to the editor may reach its model provider under the editor's data
settings. Review those settings before connecting sensitive projects.

Use `request_verification` and poll `get_fix_status` to verify a fix attempt.
`compare_scans` compares Web Scans only; it is not a Code Scan comparison or a
replacement for a fix attempt's verification result.

## Recovery

The MCP server is read-mostly. Its writes are bounded updates to existing
fix-attempt rows and inserts into the `agent_requests` queue the desktop
fulfils. `get_fix_brief` records the first time a brief is fetched,
`request_verification` records the agent summary and asks SiteCMD to verify
the attempt, and `start_fix`/`run_scan` insert one queued request each; the
desktop's own watcher claims and fulfils that row. None of these can touch
another table. If the database needs backup or restore during an incident,
follow the recovery runbook (`apps/mcp-server/recovery-runbook.md` in the
SiteCMD repository).

## License

Apache-2.0. See the repository root `LICENSE` file.
