import { describe, expect, it } from "vitest";
import { generateWorkflow } from "./cicd-workflow";

describe("generateWorkflow", () => {
  it("installs the exact signed CLI through an immutable action ref", () => {
    const yaml = generateWorkflow({
      trigger: "deploy",
      scanType: "health",
      threshold: 80,
      appVersion: "1.5.4",
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
    });

    expect(yaml).toMatch(
      /uses: brambleworks\/SiteCMD-Local\/\.github\/actions\/setup-sitecmd@[0-9a-f]{40}/,
    );
    expect(yaml).toContain('version: "1.5.4"');
    expect(yaml).toContain("permissions:\n  contents: read");
    expect(yaml).not.toContain("curl");
    expect(yaml).not.toContain("@main");
    expect(yaml).not.toMatch(/cargo install/);
    expect(yaml).not.toMatch(/sitecmd_cli/);
  });

  it("runs the documented scan subcommand with the quality-gate flags", () => {
    const yaml = generateWorkflow({
      trigger: "pr",
      scanType: "security",
      threshold: 90,
      siteUrl: "https://staging.example.com",
    });

    expect(yaml).toContain("sitecmd scan");
    expect(yaml).toContain('SITECMD_SCAN_URL: "https://staging.example.com"');
    expect(yaml).toContain('--url "$SITECMD_SCAN_URL"');
    expect(yaml).toContain("--type security");
    expect(yaml).toContain("--fail-under 90");
  });

  it("falls back to the deployment URL expression when no site URL is linked", () => {
    const yaml = generateWorkflow({
      trigger: "deploy",
      scanType: "health",
      threshold: 75,
    });

    expect(yaml).toContain("SITECMD_SCAN_URL: ${{ github.event.deployment_status.target_url }}");
    expect(yaml).toContain('--url "$SITECMD_SCAN_URL"');
    expect(yaml).toContain("if: github.event.deployment_status.state == 'success'");

    const runBlock = yaml.slice(yaml.indexOf("        run: |"));
    expect(runBlock).not.toContain("github.event.deployment_status.target_url");
  });

  it("quotes static URLs as data instead of generated workflow syntax", () => {
    const yaml = generateWorkflow({
      trigger: "pr",
      scanType: "health",
      threshold: 80,
      siteUrl: 'https://example.com/a"b\nrun: echo injected',
    });

    expect(yaml).toContain('SITECMD_SCAN_URL: "https://example.com/a\\"b\\nrun: echo injected"');
    expect(yaml).toContain('--url "$SITECMD_SCAN_URL"');
    expect(yaml).not.toContain("\nrun: echo injected\n");
  });

  it("does not interpret expression-shaped text inside a static URL", () => {
    const yaml = generateWorkflow({
      trigger: "schedule",
      scanType: "health",
      threshold: 80,
      siteUrl: "https://example.com/${{ github.token }}",
    });

    expect(yaml).toContain('SITECMD_SCAN_URL: "https://example.com/$%7B%7B github.token %7D%7D"');
    expect(yaml).not.toContain("${{ github.token }}");
  });

  it("generates a free Code Scan gate over the checked-out source", () => {
    const yaml = generateWorkflow({
      trigger: "pr",
      scanType: "code",
      threshold: 80,
      codeThreshold: "high",
    });

    expect(yaml).toContain("uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1");
    expect(yaml).toContain("sitecmd audit . --format github --fail-on high");
    expect(yaml).not.toContain("sitecmd gate");
    expect(yaml).not.toContain("SITECMD_LICENSE");
  });
});
