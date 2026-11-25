// Bug: Public copy can misstate scan access, the open-source boundary, or what releases ship.
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

const read = (file) => readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
const prose = (file) => read(file).replace(/\s+/g, " ");
const SCAN_ACCESS =
  "The CLI in this repository audits code and checks a site on your own computer with no account. Scans of public sites run on SiteCMD's hosted scanner, which the CLI calls when you're signed in.";

it("publishes free local scans and a paid connected service", () => {
  const readme = read("README.md");
  expect(readme).toContain("Local Code Scan is free");
  expect(readme).toContain("The paid product is the connected service");
  expect(readme).not.toContain("consumes one quota unit");
});

it.each([
  [
    "CLI table",
    "Code Scan and checks of a site on your own computer, hosted scans of your sites, machine-readable reports, git hooks, and connected CI gates | No for code audits and local sites; yes for public sites",
  ],
  [
    "privacy boundary",
    "The filesystem and network boundaries are in this source. Every file the code audit reads, every request the CLI makes and every byte it can send are decided by code here. SiteCMD's checks run in a compiled engine module with no imports, so it can't reach the network, your files or anything else on your machine; it sees only what this code hands it. [docs/engineering/engine-boundary.md](docs/engineering/engine-boundary.md) shows how to check that yourself.",
  ],
  [
    "source boundary",
    "The code that reads your files and makes network requests is here under Apache-2.0. SiteCMD's checks aren't: on your machine they run inside a sandboxed engine module compiled from SiteCMD's private source, and site scans run on SiteCMD's infrastructure.",
  ],
  [
    "release license",
    "Brambleworks-authored source in this repository is licensed under the [Apache License 2.0](LICENSE). Release builds embed SiteCMD's engine module, which isn't in this repository and is licensed under the SiteCMD Engine Module License; see LICENSE. Bundled third-party material retains its own license; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).",
  ],
])("pins the README %s claim", (_claim, approved) => {
  expect(prose("README.md")).toContain(approved);
});

// Bug: An old commercial claim can survive after replacing the scan access paragraph.
it("uses exactly the approved scan access paragraph below the CLI table", () => {
  const section = read("README.md").split("## What ships")[1].split("## Install and try it")[0];
  const afterTable = section.slice(section.lastIndexOf("\n|")).split("\n\n").slice(1).join("\n\n");
  expect(afterTable.trim().replace(/\s+/g, " ")).toBe(SCAN_ACCESS);
});

it.each([
  [
    "CONTRIBUTING.md",
    "The checks are compiled into the module from SiteCMD's private source, so changes to checks aren't accepted here.",
  ],
  [
    "CONTRIBUTING.md",
    "**Connected-service internals.** The hosted scanner, the connected API, and the delivery workers run on SiteCMD infrastructure, and their code is private.",
  ],
  [
    "CONTRIBUTING.md",
    "Fix-guide content is separately licensed commercial content and is authored privately, not in this one.",
  ],
  [
    "docs/engineering/connected-service/connected-protocol-spec.md",
    "**Check ids sync in the clear.** An id names a check SiteCMD ships, never anything from the user's code or site.",
  ],
])("pins the published boundary in %s (%#)", (file, approved) => {
  expect(prose(file)).toContain(approved);
});

// Bug: The threat model can attribute retired client behavior to the Terms.
it("distinguishes hosted cancellation terms from local CLI behavior", () => {
  const section =
    read("docs/engineering/entitlement-threat-model.md")
      .split("## Subscription lapse")[1]
      ?.split("\n## ")[0] ?? "";
  const copy = section.replace(/\s+/g, " ");
  expect.soft(copy).toContain("the end of the free trial or the paid period");
  expect.soft(copy).toContain("SiteCMD stops watching your sites when the subscription ends");
  expect.soft(copy).toContain("without checking subscription status");
  expect.soft(copy).toContain("the service enforces entitlement");
  expect.soft(section).not.toContain("catalog::store");
});

it.each([
  "Public-site scans require sign-in.",
  "Local sites run 8 checks.",
  "`--cwv` and `--no-browser` are gone.",
  "The desktop app and the MCP server are retired.",
])("records the release change %s", (entry) => {
  const unreleased = prose("CHANGELOG.md").split("## [Unreleased]")[1].split(" ## [")[0];
  expect(unreleased).toContain(entry);
});
