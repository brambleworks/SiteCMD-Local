// Bug: Public guidance can omit the checks that make the engine boundary verifiable.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { gitEnv } from "./lib/git-env.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (file) => readFileSync(path.join(ROOT, file), "utf8");
const prose = (file) => read(file).replace(/\s+/g, " ");
const NATIVE = "apps/desktop/src-tauri";
const ENGINE_BOUNDARY = "docs/engineering/engine-boundary.md";
const PENDING_MARKER = /Pending signature/i;

const QUANTITY = String.raw`(?<![\w.])(?:\d[\d,]*|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million)(?!\w|\.\d)`;
const CHECK_COUNT_PROSE = new RegExp(
  String.raw`${QUANTITY}[^.!?;|]{0,60}\bchecks?\b|\b(?:checks|check count|check total)\s*(?::|=|number|total|are|is)\s*${QUANTITY}`,
  "gi",
);
const COUNT_CELL = new RegExp(String.raw`^${QUANTITY}\+?$`, "i");
const CHECK_LABEL = /\b(?:checks|check count|check total)\b|\bcheck$/i;

function tableCells(line) {
  return line
    .trim()
    .replace(/^\||\|$/g, "")
    .split("|")
    .map((cell) => cell.replace(/[*_`]/g, "").trim());
}

function checkCountClaims(source) {
  const prose = source
    .split("\n")
    .filter((line) => !line.includes("|"))
    .join("\n")
    .replace(/\s+/g, " ");
  const claims = prose.match(CHECK_COUNT_PROSE) ?? [];
  const lines = source.split("\n");
  let countColumns = [];
  for (const [index, line] of lines.entries()) {
    if (!line.includes("|")) {
      countColumns = [];
      continue;
    }
    const cells = tableCells(line);
    const next = tableCells(lines[index + 1] ?? "");
    if (next.length === cells.length && next.every((cell) => /^:?-{3,}:?$/.test(cell))) {
      countColumns = cells.map((cell) => CHECK_LABEL.test(cell));
      continue;
    }
    if (
      cells.some((cell) => cell.search(CHECK_COUNT_PROSE) >= 0) ||
      cells.some((cell, column) => countColumns[column] && COUNT_CELL.test(cell)) ||
      (cells.some((cell) => CHECK_LABEL.test(cell)) && cells.some((cell) => COUNT_CELL.test(cell)))
    ) {
      claims.push(line);
    }
  }
  return claims;
}

describe("maintained CLI documentation", () => {
  it("readme_has_no_check_count_table", () => {
    expect(checkCountClaims(read("README.md"))).toEqual([]);
  });

  // Bug: A different table or a prose count can bypass a check for the old heading.
  it.each([
    "| Lane | Checks |\n| --- | ---: |\n| Local | 8 |",
    "Category | Check count\n--- | ---\nCode Scan | 174",
    "| Web Scan checks | 157 |",
    "| Lane | Coverage |\n| --- | --- |\n| Local | 8 checks |",
    "| Lane | Checks performed |\n| --- | ---: |\n| Local | 8 |",
    "The CLI runs 157 Web Scan checks.",
    "There are eight local checks.",
    "Local checks: 8.",
    "The checks number 1,024.",
    "It runs\n8 checks.",
  ])("rejects a README check-count claim (%#)", (source) => {
    expect(checkCountClaims(source)).not.toEqual([]);
  });

  // Bug: A count matcher can reject versions or other quantities mentioned near checks.
  it.each([
    "Checks of a site on your own computer.",
    "Rust 1.95.0 for the MSRV\nchecks mirrored by CI.",
    "| Check | Severity |\n| --- | --- |\n| TLS 1.3 | High |",
  ])("allows README copy without check counts (%#)", (source) => {
    expect(checkCountClaims(source)).toEqual([]);
  });

  it("engine_boundary_doc_names_every_check", () => {
    const boundary = prose(ENGINE_BOUNDARY);
    for (const check of [
      "sitecmd-engine-host",
      "sitecmd engine info",
      "--save",
      "connected --dry-run",
      "location_hash",
      "instance_count",
      "engine_info",
    ]) {
      expect(boundary).toContain(check);
    }
    expect(boundary).toContain(
      "your code never reaches SiteCMD, and the only place anything code-derived leaves your machine is your own repository, on your explicit autofix command, in requests the open host builds and checks.",
    );
  });

  // Bug: The documented wants can drift independently of the closed ABI enum.
  it("documents the request kinds declared in the Want enum", () => {
    const source = read(`${NATIVE}/crates/protocol/src/engine_abi/types.rs`);
    const declaration = source.split("pub enum Want {\n")[1].split("\n}")[0];
    const kinds = [...declaration.matchAll(/^ {4}([A-Z]\w*) \{/gm)].map(([, variant]) =>
      variant.replace(/[A-Z]/g, (letter, offset) => (offset ? "_" : "") + letter.toLowerCase()),
    );
    expect(kinds.length).toBeGreaterThan(0);
    const documented = [...read(ENGINE_BOUNDARY).matchAll(/^- `([a-z_]+)` /gm)].map(
      ([, kind]) => kind,
    );
    expect(documented.sort()).toEqual(kinds.sort());
  });

  // Bug: Omitting a route or mislabeling its payload makes the network boundary incomplete.
  it("documents every request destination and the data GitHub receives", () => {
    const boundary = prose(ENGINE_BOUNDARY).split("## 3. Trace the requests")[1].split("## 4. ")[0];
    for (const destination of [
      "Connect's API",
      "the localhost page",
      "local databases only with `--inspect-local-databases`",
      "your own GitHub repository",
      "`sitecmd connect`",
      "`api.github.com`",
      "encrypted repository secrets",
      "connection export and passphrase",
      "`actions.githubusercontent.com`",
      "`*.actions.githubusercontent.com`",
      "`run-job`",
      "OIDC token",
      "request token and audience",
      "Neither GitHub request carries source code.",
    ]) {
      expect.soft(boundary).toContain(destination);
    }
  });

  // Bug: The trust walkthrough can misidentify the loader, inputs, or autofix caller.
  it.each([
    "src/core/project_listing.rs",
    "src/core/engine_facts/",
    "`AuditHostFacts`",
    "src/wants.rs",
    "metadata only, even for paths outside the listing",
    "`local-engine.cwasm`",
    "against the pin",
    "checks imports on the deserialized module",
    "The Action's publish workflow runs `sitecmd autofix publish-job`",
  ])("documents the host behavior %s", (detail) => {
    expect(prose(ENGINE_BOUNDARY)).toContain(detail);
  });

  it.each(["README.md", "CONTRIBUTING.md"])("links %s to the engine boundary", (file) => {
    expect(read(file)).toContain(`](${ENGINE_BOUNDARY})`);
  });

  // Bug: A shortcut link can duplicate the explanatory README link.
  it("links to the boundary once in the README", () => {
    expect(read("README.md").split(`](${ENGINE_BOUNDARY})`)).toHaveLength(2);
  });

  // Bug: The public license can keep its heading while dropping operative terms.
  const licenseTerms = [
    [
      "What it covers.",
      "The compiled SiteCMD engine module (local-engine.wasm) that ships inside SiteCMD CLI releases and on SiteCMD's releases host",
      "It doesn't cover the SiteCMD CLI's source, which is under the Apache License 2.0",
      "or any engine version SiteCMD published under the Apache License 2.0, which stays under that license",
    ],
    [
      "What you may do.",
      "Use the module free of charge to run SiteCMD's checks through the SiteCMD CLI or a build of the CLI's source",
      "copy it as part of installing, building or testing the CLI",
      "redistribute it unmodified inside the CLI's release packages or inside a fork of the CLI that carries this license with it.",
    ],
    [
      "What you may inspect.",
      "read the module's imports and exports",
      "run it under any WebAssembly tool",
      "observe what it does with what it's given",
      "Nothing in this license limits that.",
    ],
    [
      "What you may not do.",
      "Modify the module; decompile, disassemble or otherwise reverse engineer it to recover its checks, rules or fix text",
      "except where applicable law allows it despite this term",
      "to build or train another check engine, rule set or scanner",
      "or remove this license or SiteCMD's notices",
    ],
    ["Your results.", "The findings, reports and fixes the module produces for you are yours."],
    [
      "Third-party components.",
      "under their own licenses, listed in local-engine.wasm.LICENSES.txt.",
    ],
    [
      "No warranty, limited liability.",
      'SiteCMD provides the module "as is", without warranties or conditions of any kind, express or implied',
      "including any warranty of title, non-infringement, merchantability or fitness for a particular purpose",
      "You're responsible for deciding whether using it suits you.",
      "Unless applicable law requires it or SiteCMD agreed in writing, SiteCMD isn't liable to you for any damages",
      "arising from this license or from using or being unable to use the module, even if SiteCMD was told such damages were possible.",
    ],
    ["Ending.", "Breaking these terms ends your rights under them."],
  ];

  it("includes the source license before the module's eight numbered terms", () => {
    const [source, module] = read("LICENSE").split("SiteCMD Engine Module License\n");
    expect(source).toContain("Version 2.0, January 2004");
    expect(source).toContain("END OF TERMS AND CONDITIONS");
    expect(module.trim().split(/\n(?=\d+\. )/)).toHaveLength(licenseTerms.length);
  });

  it.each(licenseTerms.map((term, index) => [index + 1, ...term]))(
    "pins license item %d, %s",
    (number, heading, ...clauses) => {
      const module = read("LICENSE").split("SiteCMD Engine Module License\n")[1];
      const term = module
        .trim()
        .split(/\n(?=\d+\. )/)
        [number - 1].replace(/\s+/g, " ");
      const label = `${number}. ${heading}`;
      expect(term.startsWith(label)).toBe(true);
      expect(term.slice(label.length).trim()).not.toBe("");
      for (const clause of clauses) expect.soft(term).toContain(clause);
    },
  );

  // Bug: Signed words can keep their pending markers and read as unsigned.
  it.each([
    ["CHANGELOG.md", "Public-site scans require sign-in."],
    ["CHANGELOG.md", "The desktop app and the MCP server are retired."],
    [ENGINE_BOUNDARY, "# Verify the engine boundary"],
    ["README.md", "outside this repository"],
    ["CONTRIBUTING.md", "outside this repository"],
  ])("keeps the signed words in %s around %s without a pending marker", (file, excerpt) => {
    expect.soft(read(file)).toContain(excerpt);
    expect(read(file)).not.toMatch(PENDING_MARKER);
  });

  // Bug: A pending marker left anywhere ships unsigned words in a release.
  it("leaves no pending signature marker outside the tests", () => {
    const marked = spawnSync(
      "git",
      ["grep", "-l", "-i", "pending signature", "--", ".", ":!*.test.mjs"],
      { cwd: ROOT, encoding: "utf8", env: gitEnv() },
    );
    expect(marked.stdout.split("\n").filter(Boolean)).toEqual([]);
    expect(marked.status).toBe(1);
  });

  // Bug: A hosted smoke test can use a site that won't pass verification or omit its text flag.
  it("runs the hosted smoke test against a verified site with text output", () => {
    const smoke = prose("docs/operations/launch-smoke.md");
    expect.soft(smoke).toContain("a verified site in the account");
    expect.soft(smoke).toContain('sitecmd scan --url "$SITECMD_TEST_URL" --output text');
  });

  // Bug: The public guidance can send detector developers to a private file.
  it("keeps the detector walkthrough out of public guidance", () => {
    const guide = prose(`${NATIVE}/AGENTS.md`);
    expect(guide).toContain("The engine module owns check verdicts, coverage, and scoring.");
    expect(guide).not.toContain("detector walkthrough");
    expect(guide).not.toContain("The public walkthrough");
  });

  it("keeps local Code Scan free", () => {
    const readme = prose("README.md");
    expect(readme).toContain("Local Code Scan is free");
    expect(readme).not.toContain("consumes one quota unit");
  });

  it("keeps the standalone CLI package browser-free", () => {
    expect(read(`${NATIVE}/crates/cli/Cargo.toml`)).not.toMatch(/^browser\s*=/m);
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

  for (const file of ["README.md", "CONTRIBUTING.md", "docs/README.md", ENGINE_BOUNDARY]) {
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
