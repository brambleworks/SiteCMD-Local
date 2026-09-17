import type { ScanType as SchedulableScanType } from "@/lib/types";
import type { Severity } from "@/lib/severity";

export type Trigger = "deploy" | "pr" | "schedule";
export type WorkflowScanType = SchedulableScanType | "code";
export type CodeThreshold = Severity;

const APP_VERSION = import.meta.env.VITE_APP_VERSION ?? "0.0.0";
const SOURCE_COMMIT = import.meta.env.VITE_SOURCE_COMMIT ?? "";
const CHECKOUT_ACTION_REF = "3d3c42e5aac5ba805825da76410c181273ba90b1";

function setupActionRef(sourceCommit: string, appVersion: string): string {
  return /^[0-9a-f]{40}$/i.test(sourceCommit) ? sourceCommit : `v${appVersion}`;
}

function getWorkflowScanLabel(scanType: WorkflowScanType): string {
  switch (scanType) {
    case "health":
      return "Web";
    case "security":
      return "Security";
    case "accessibility":
      return "Accessibility";
    case "polish":
      return "Polish";
    case "code":
      return "Code";
  }
}

function quoteWorkflowUrl(value: string): string {
  // JSON quoting is valid YAML and escaped braces cannot become expressions.
  return JSON.stringify(value.replaceAll("{", "%7B").replaceAll("}", "%7D"));
}

export function generateWorkflow(opts: {
  trigger: Trigger;
  scanType: WorkflowScanType;
  threshold: number;
  codeThreshold?: CodeThreshold;
  siteUrl?: string;
  appVersion?: string;
  sourceCommit?: string;
}): string {
  const {
    trigger,
    scanType,
    threshold,
    codeThreshold = "high",
    siteUrl,
    appVersion = APP_VERSION,
    sourceCommit = SOURCE_COMMIT,
  } = opts;
  const workflowScanLabel = getWorkflowScanLabel(scanType);
  const name = `SiteCMD ${workflowScanLabel} Scan`;

  let onBlock: string;
  let urlExpr: string;
  let ifLine = "";

  switch (trigger) {
    case "deploy":
      onBlock = `on:\n  deployment_status:\n    types: [success]`;
      urlExpr = siteUrl
        ? quoteWorkflowUrl(siteUrl)
        : `\${{ github.event.deployment_status.target_url }}`;
      ifLine = `    if: github.event.deployment_status.state == 'success'`;
      break;
    case "pr":
      onBlock = `on:\n  pull_request:\n    branches: [main]`;
      urlExpr = quoteWorkflowUrl(siteUrl ?? "https://your-staging-url.com");
      break;
    case "schedule":
      onBlock = `on:\n  schedule:\n    - cron: '0 6 * * *'\n  workflow_dispatch:`;
      urlExpr = quoteWorkflowUrl(siteUrl ?? "https://your-site.com");
      break;
  }

  const sourceCheckout =
    scanType === "code"
      ? `      - name: Check out source
        uses: actions/checkout@${CHECKOUT_ACTION_REF}${
          trigger === "deploy"
            ? `
        with:
          ref: \${{ github.event.deployment.sha }}`
            : ""
        }

`
      : "";
  const command =
    scanType === "code"
      ? `sitecmd audit . --format github --fail-on ${codeThreshold}`
      : `sitecmd scan \\
            --url "$SITECMD_SCAN_URL" \\
            --type ${scanType} \\
            --fail-under ${threshold}`;
  const scanEnvironment =
    scanType === "code"
      ? ""
      : `        env:
          SITECMD_SCAN_URL: ${urlExpr}
`;

  return `name: ${name}

${onBlock}

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
${ifLine ? ifLine + "\n" : ""}    steps:
${sourceCheckout}      - name: Install SiteCMD CLI
        uses: brambleworks/SiteCMD-Local/.github/actions/setup-sitecmd@${setupActionRef(sourceCommit, appVersion)}
        with:
          version: "${appVersion}"

      - name: Run ${workflowScanLabel} Scan
${scanEnvironment}        run: |
          ${command}
`;
}
