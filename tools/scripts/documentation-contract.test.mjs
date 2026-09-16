import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (file) => readFileSync(path.join(ROOT, file), "utf8");
const prose = (file) => read(file).replace(/\s+/g, " ");
const NATIVE = "apps/desktop/src-tauri";

describe("maintained desktop documentation", () => {
  it("keeps local scan access consistent with generated product facts", () => {
    const facts = JSON.parse(read("product-facts.json"));
    expect(facts.commercialModel.localWorkbench).toBe("free_complete");
    const architecture = prose("docs/engineering/unified-scan-architecture.md");
    expect(architecture).toContain("Local scans have no plan-based quota");
    expect(architecture).not.toContain("consumes one quota unit");
    expect(prose("docs/engineering/issue-and-alert-architecture.md")).not.toContain(
      "access-tier sanitization",
    );
  });

  it("documents the native scorer's security cap instead of promising no caps", () => {
    const scorer = read(`${NATIVE}/crates/engine/src/scoring/calculator.rs`);
    const cap = /EXPLOITABLE_SCORE_CAP: f64 = ([\d.]+)/.exec(scorer)?.[1];
    expect(cap).toBeTruthy();
    const product = prose("apps/desktop/PRODUCT.md");
    expect(product).toContain(`caps it at ${Number(cap)}`);
    expect(product).not.toContain("no hard caps");
    expect(product).not.toContain("never tanks");
  });

  it("points diagnostics readers at the Settings section that owns the controls", () => {
    const settings = read("apps/desktop/src/components/settings/SettingsPage.tsx");
    const privacy = settings.slice(settings.indexOf('id: "privacy-diagnostics"'));
    const label = /label: "([^"]+)"/.exec(privacy)?.[1];
    expect(label).toBeTruthy();
    for (const file of [
      "docs/engineering/observability.md",
      "docs/engineering/performance-baseline.md",
    ]) {
      expect(read(file), file).toContain(label);
      expect(read(file), file).not.toContain("Settings -> Data");
      expect(read(file), file).not.toContain("Go to `Data`");
    }
  });

  it("keeps the manual MCP launch consistent with the desktop launcher", () => {
    const launcher = read(`${NATIVE}/src/core/agent_tools.rs`);
    const minimum = /MCP_MINIMUM_NODE_VERSION_LABEL: &str = "([^"]+)"/.exec(launcher)?.[1];
    const flag = /"(--disable-warning=[^"]+)"/.exec(launcher)?.[1];
    expect(minimum).toBeTruthy();
    expect(flag).toBeTruthy();
    expect(JSON.parse(read("apps/mcp-server/package.json")).engines.node).toBe(`>=${minimum}`);
    const doc = read("apps/mcp-server/README.md");
    const example = JSON.parse(doc.split("```json\n")[1].split("\n```")[0]);
    expect(example.mcpServers.sitecmd.args[0]).toBe(flag);
    expect(example.mcpServers.sitecmd.args[1]).toContain("com.sitecmd.app/sitecmd-mcp/");
    expect(doc).toContain(`Node.js ${minimum}+`);
    expect(prose("apps/mcp-server/README.md")).toContain("every project in the selected");
  });

  it("documents an optional browser build against the standalone CLI package", () => {
    const manifest = read(`${NATIVE}/crates/cli/Cargo.toml`);
    const packageName = /name = "([^"]+)"/.exec(manifest)?.[1];
    expect(manifest).toContain('browser = ["sitecmd-runtime/browser"]');
    const boundary = read("docs/engineering/native-runtime-boundary.md");
    expect(boundary).toContain(`cargo build --locked --release -p ${packageName}`);
    expect(boundary).toContain("--features browser");
    expect(boundary).toContain(`cd ${NATIVE}`);
  });

  it("names existing scripts in the contributor setup and quality gates", () => {
    const scripts = Object.keys(JSON.parse(read("package.json")).scripts);
    const commands = [...read("CONTRIBUTING.md").matchAll(/`pnpm ([a-z][a-z0-9:-]*)/g)];
    expect(commands.length).toBeGreaterThan(5);
    for (const [, command] of commands) {
      if (command === "install") continue;
      expect(scripts, command).toContain(command);
    }
  });

  for (const file of ["README.md", "CONTRIBUTING.md", "docs/README.md"]) {
    it(`resolves local file links in ${file}`, () => {
      for (const fragment of read(file).split("](").slice(1)) {
        const target = fragment.split(")")[0].split(" ")[0];
        if (target.startsWith("https:") || target.startsWith("mailto:")) continue;
        const [relative, anchor] = target.split("#");
        const destination = relative ? path.join(path.dirname(file), relative) : file;
        expect(existsSync(path.join(ROOT, destination)), target).toBe(true);
        if (!anchor || !destination.endsWith(".md")) continue;
        const headings = read(destination)
          .split("\n")
          .filter((line) => line.startsWith("#"))
          .map((line) =>
            line
              .replace(/^#+ /, "")
              .toLowerCase()
              .replace(/[^a-z0-9 -]/g, "")
              .replaceAll(" ", "-"),
          );
        expect(headings, target).toContain(anchor);
      }
    });
  }
});
