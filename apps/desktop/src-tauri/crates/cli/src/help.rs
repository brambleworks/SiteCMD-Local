pub(crate) fn print_main_help() {
    eprintln!(
        "SiteCMD CLI - Local scanning and connected CI/CD pipelines\n\n\
Usage:\n  sitecmd <command> [options]\n\n\
Commands:\n  \
  init [url]              Initialize project with .sitecmd/ config\n  \
  audit <path>            Run Code Scan against a source checkout\n  \
  autofix                 Apply template fixes, or run a Connect fix job\n  \
  scan                    Run a scan and export to .sitecmd/\n  \
  fix                     Output fix prompts from last scan\n  \
  watch                   Monitor URL and rescan at intervals\n  \
  check                   Regression check (for git hooks)\n  \
  connected               Preview or submit a connected-service payload\n  \
  deploy                  Tell the connected service a deployment happened\n  \
  gate                    Fail the build on findings new against the baseline\n\n\
Options:\n  \
  --help, -h              Show this help\n  \
  --version, -V           Print the CLI version\n\n\
Run `sitecmd <command> --help` for command-specific options."
    );
}

pub(crate) fn print_scan_help() {
    eprintln!(
        "{}",
        concat!(
            "SiteCMD scan - Run a Web Scan\n\n",
            "Usage:\n  sitecmd scan [options]\n\n",
            "Options:\n",
            "  --url <URL>             URL to scan (or use .sitecmd/config.json)\n",
            "  --type <TYPE>           Scan type: health, security, accessibility, polish (default: health)\n",
            "  --diff                  Compare with last scan and show changes\n",
            "  --env <NAME>            Use a named environment URL from config\n",
            "  --fail-under <N>        Exit 1 if score < N (quality gate)\n",
            "  --fail-on <SEV>         Exit 1 if a failing issue is at or above SEV (critical, high, medium, low)\n",
            "  --json                  Output JSON to stdout (skips file export)\n",
            "  --output json           Alias for --json (legacy compat)\n",
            "  --timeout <SECS>        HTTP timeout per request (default: 30)\n",
            "  --categories <LIST>     Filter health scans: security, seo, performance,\n",
            "                          accessibility, compliance, config\n",
            "  --no-browser            Skip browser checks in browser-enabled source builds\n",
            "  --cwv                   Measure CWV (browser-enabled source builds only)\n",
            "  --help, -h              Show this help\n\n",
            "Exit codes:\n",
            "  0  Scan passed (or no threshold set)\n",
            "  1  Score below --fail-under, a failing issue at or above --fail-on, or a new critical issue in --diff mode\n",
            "  2  Scan error (network, invalid URL)\n\n",
            "Examples:\n",
            "  sitecmd scan\n",
            "  sitecmd scan --url https://example.com\n",
            "  sitecmd scan --type security --fail-under 90\n",
            "  sitecmd scan --json > results.json\n",
            "  sitecmd scan --diff",
        )
    );
}

pub(crate) fn print_init_help() {
    eprintln!(
        "SiteCMD init - Initialize a .sitecmd/ project\n\n\
Usage:\n  sitecmd init [url] [options]\n\n\
Options:\n  \
  --name <NAME>           Project name (default: directory name)\n  \
  --yes, -y               Non-interactive mode (use detected values)\n  \
  --no-deep-link          Skip opening the desktop app\n  \
  --help, -h              Show this help"
    );
}

pub(crate) fn print_fix_help() {
    eprintln!(
        "SiteCMD fix - Output fix prompts from last scan\n\n\
Usage:\n  sitecmd fix [options]\n\n\
Options:\n  \
  --all                   Show all matching issues (default: top issue only)\n  \
  --id <CHECK_ID>         Show fix for a specific check ID\n  \
  --type <TYPE>           Filter by issue type\n  \
  --category <CAT>        Filter by category\n  \
  --help, -h              Show this help"
    );
}

pub(crate) fn print_watch_help() {
    eprintln!(
        "SiteCMD watch - Monitor URL and rescan at intervals\n\n\
Usage:\n  sitecmd watch [options]\n\n\
Options:\n  \
  --url <URL>             URL to monitor\n  \
  --interval <SECS>       Rescan interval in seconds (default: 300)\n  \
  --env <NAME>            Use a named environment from config\n  \
  --help, -h              Show this help"
    );
}

pub(crate) fn print_check_help() {
    eprintln!(
        "SiteCMD check - Regression check for git hooks\n\n\
Usage:\n  sitecmd check [options]\n\n\
Options:\n  \
  --install               Install as a git pre-push hook\n  \
  --strict                Also fail on any new issue vs the last scan (always scans fresh)\n  \
  --fail-under <N>        Minimum score to pass (default: from config); --threshold is a deprecated alias\n  \
  --help, -h              Show this help"
    );
}

pub(crate) fn print_connected_help() {
    eprintln!(
        "SiteCMD connected - Preview or submit a connected-service payload\n\n\
Usage:\n  sitecmd connected --dry-run --connection-export <PATH> [options]\n  \
  sitecmd connected --submit --connection-export <PATH> \\\n    \
                    --deployment-id <ID> --commit <SHA> [options]\n\n\
Options:\n  \
  --dry-run               Print the exact payload without sending it\n  \
  --submit                Send this checkout's code evidence for a deployment\n  \
  --connection-export <PATH>\n                          Encrypted, credential-free connection export\n  \
  --passphrase-env <NAME> Read the export passphrase from this environment\n                          variable (default: SITECMD_CONNECTION_PASSPHRASE)\n  \
  --token-env <NAME>      Read the CI token from this environment variable\n                          (default: SITECMD_CI_TOKEN)\n  \
  --deployment-id <ID>    The provider's own identity for this deployment\n  \
  --commit <SHA>          The commit this deployment carries\n  \
  --ref <REF>             The ref it was deployed from\n  \
  --previous-sha <SHA>    The commit it replaced\n  \
  --target <NAME>         The provider's deployment target\n  \
  --deployed-at <TIME>    When the provider created the deployment\n  \
  --published             Explicitly assert this deployment reached production\n  \
  --ordering-authority <ID>\n                          Override the automatically read publish namespace\n  \
  --ordering-epoch <N>    Override the automatically read authority epoch\n  \
  --publish-sequence <N>  Ordinal allocated when publication succeeded\n  \
  --predecessor-deployment-id <ID>\n                          Exact deployment this publication replaced\n  \
  --path <PATH>           Project root to audit (default: working directory)\n  \
  --db <PATH>             Desktop database (or SITECMD_DB_PATH/default path)\n  \
  --help, -h              Show this help\n\n\
With no deployment named, --dry-run emits the DesktopSubmission serialization\n\
desktop sync uses, contacting nothing and reserving no submission sequence.\n\
With one named, it emits the CI submission before server-derived ordering. A\n\
send reads the site's ordering cursor and attaches the next causal publish fact\n\
unless explicit ordering flags were supplied; a dry run contacts nothing, so\n\
preview exact ordering only by supplying those advanced flags.\n\n\
A submission audits this checkout and sends its code findings bound to the\n\
deployment. In GitHub Actions it requires `permissions: id-token: write` and\n\
automatically presents GitHub's OIDC witness. A credential pinned to that\n\
repository's immutable id, workflow, and optional ref can then earn exact\n\
provenance. Other runners submit unattested presence evidence: they never mark\n\
anything fixed or move lifecycle state, and a credential that governs the\n\
site's publishing workflow is refused there rather than downgraded to it - use\n\
`sitecmd deploy` for the publish fact and submit the evidence after. CI runs\n\
carry no submission sequence; retry safety comes from a key derived from the\n\
payload."
    );
}

pub(crate) fn print_deploy_help() {
    eprintln!(
        "SiteCMD deploy - Tell the connected service a deployment happened\n\n\
Usage:\n  sitecmd deploy --site <ID> --deployment-id <ID> --commit <SHA> [options]\n\n\
Options:\n  \
  --site <ID>             The connected site this deployment belongs to\n  \
  --connection-export <PATH>\n                          Name the site from a connection export instead\n  \
  --passphrase-env <NAME> Read the export passphrase from this environment\n                          variable (default: SITECMD_CONNECTION_PASSPHRASE)\n  \
  --token-env <NAME>      Read the CI token from this environment variable\n                          (default: SITECMD_CI_TOKEN)\n  \
  --deployment-id <ID>    The provider's own identity for this deployment\n  \
  --commit <SHA>          The commit this deployment carries\n  \
  --ref <REF>             The ref it was deployed from\n  \
  --previous-sha <SHA>    The commit it replaced\n  \
  --target <NAME>         The provider's deployment target\n  \
  --deployed-at <TIME>    When the provider created the deployment\n  \
  --published             Explicitly assert this deployment reached production\n  \
  --ordering-authority <ID>\n                          Override the automatically read publish namespace\n  \
  --ordering-epoch <N>    Override the automatically read authority epoch\n  \
  --publish-sequence <N>  Ordinal allocated when publication succeeded\n  \
  --predecessor-deployment-id <ID>\n                          Exact deployment this publication replaced\n  \
  --help, -h              Show this help\n\n\
For a pipeline that deploys but runs no scanner. Prefer --site: this command\n\
never needs the project fingerprint key, and the connection export carries it.\n\
Redelivering a deployment converges on the record already stored, so a retried\n\
step is not an error; only the same id with different immutable facts is.\n\
The command reads the site's ordering cursor and attaches the next causal\n\
publish fact automatically. The explicit ordering flags are advanced overrides;\n\
only a matching authority epoch and causal sequence or exact predecessor can\n\
move the site's current head. Other deployments remain history."
    );
}

pub(crate) fn print_gate_help() {
    eprintln!(
        "SiteCMD gate - Fail the build on findings new against the connected baseline\n\n\
Usage:\n  sitecmd gate --connection-export <PATH> [options]\n\n\
Options:\n  \
  --connection-export <PATH>\n                          Encrypted, credential-free connection export\n  \
  --passphrase-env <NAME> Read the export passphrase from this environment\n                          variable (default: SITECMD_CONNECTION_PASSPHRASE)\n  \
  --token-env <NAME>      Read the CI token from this environment variable\n                          (default: SITECMD_CI_TOKEN)\n  \
  --fail-on <LEVEL>       Fail on new findings at or above this severity:\n                          critical, high (default), medium, low (--threshold is a deprecated alias)\n  \
  --strict                Also fail on findings the service cannot rule out\n                          as a detector or corpus change\n  \
  --path <PATH>           Project root to audit (default: working directory)\n  \
  --db <PATH>             Desktop database (or SITECMD_DB_PATH/default path)\n  \
  --help, -h              Show this help\n\n\
Audits the checkout, then asks the service which findings are new against the\n\
baseline. Exit code 1 means the merge is blocked, 2 means the gate could not\n\
run. The candidate is evaluated and discarded: gating never changes the\n\
baseline, so this is safe on every branch of every pull request."
    );
}
