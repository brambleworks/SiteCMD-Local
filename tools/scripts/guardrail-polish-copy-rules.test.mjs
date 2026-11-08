import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { polishCopySafetyFailures } from "./lib/guardrail-polish-copy-rules.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const POLISH_RUST_FILES = [
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/page_leftovers.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/ai_aesthetic.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/copy_content.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/css_architecture.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/framework_defaults.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/html_quality.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/meta_infra.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/titles.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/guidance.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/check_result.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/css_grade.rs",
];
const POLISH_LEAD_FILE = "apps/desktop/src/lib/fix-guides/polish.ts";

function harness(files) {
  return {
    read: (file) => files[file] ?? "",
    exists: (file) => file in files || Object.keys(files).some((key) => key.startsWith(`${file}/`)),
    listFiles: (dir, filter) =>
      Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && (!filter || filter(file))),
  };
}

// Every scenario needs the Rust files to exist and be clean so only the
// lead file under test drives the assertion.
function baseFixture() {
  const files = {};
  for (const file of POLISH_RUST_FILES) {
    files[file] = "pub fn placeholder() {}\n";
  }
  return files;
}

describe("polishCopySafetyFailures", () => {
  it.each(["guidance.rs", "check_result.rs", "css_grade.rs", "page_leftovers.rs"])(
    "flags a banned phrase in %s, whose copy reaches hosted results",
    (name) => {
      // Copy from a new polish source must not escape the wording guardrail.
      const files = baseFixture();
      const file = `apps/desktop/src-tauri/crates/engine/src/checks/polish/${name}`;
      files[file] = 'pub fn reason() -> &str {\n    "A cookie-cutter layout"\n}\n';
      files[POLISH_LEAD_FILE] = "export const POLISH_FIX_GUIDES = {};\n";
      const h = harness(files);
      const failures = polishCopySafetyFailures(h.read, h.exists, h.listFiles);
      expect(failures.some((f) => f.startsWith(`${file}:2`))).toBe(true);
    },
  );

  it("flags a banned phrase in a signal file moved into the engine", () => {
    const files = baseFixture();
    const moved = "apps/desktop/src-tauri/crates/engine/src/checks/polish/copy_content.rs";
    files[moved] = 'pub fn detail() -> String {\n    "A suspicious amount of copy".into()\n}\n';
    files[POLISH_LEAD_FILE] = "export const POLISH_FIX_GUIDES = {};\n";
    const h = harness(files);
    const failures = polishCopySafetyFailures(h.read, h.exists, h.listFiles);
    expect(failures.some((f) => f.startsWith(`${moved}:2`) && /suspicious/i.test(f))).toBe(true);
  });

  it("flags a judgmental word planted in a polish lead sentence (negative control)", () => {
    const files = baseFixture();
    files[POLISH_LEAD_FILE] =
      "export const POLISH_FIX_GUIDES = {\n" +
      '  "floating-blobs": {\n' +
      '    effort: "quick",\n' +
      "    effortMinutes: 3,\n" +
      '    lead: "This page has a suspicious number of decorative floating shapes in the background.",\n' +
      '    default: ["step"],\n' +
      "  },\n" +
      "};\n";

    const h = harness(files);
    const failures = polishCopySafetyFailures(h.read, h.exists, h.listFiles);
    expect(failures.some((f) => f.includes(POLISH_LEAD_FILE) && /suspicious/i.test(f))).toBe(true);
  });

  it("does not flag a lead sentence with no banned phrase", () => {
    const files = baseFixture();
    files[POLISH_LEAD_FILE] =
      "export const POLISH_FIX_GUIDES = {\n" +
      '  "floating-blobs": {\n' +
      '    effort: "quick",\n' +
      "    effortMinutes: 3,\n" +
      '    lead: "This page contains several decorative floating shapes in the background, worth checking they are not distracting.",\n' +
      '    default: ["step"],\n' +
      "  },\n" +
      "};\n";

    const h = harness(files);
    expect(polishCopySafetyFailures(h.read, h.exists, h.listFiles)).toEqual([]);
  });

  it.each([
    [
      "reconstruct claim",
      "This site's production build ships a source map that lets anyone reconstruct your code.",
    ],
    [
      "deployment-fail claim",
      "A loopback URL is hardcoded into this code, which will fail once it runs somewhere else.",
    ],
    [
      "absolute-inability claim",
      "No skip link exists on this page, and a keyboard user has no way to reach the main content.",
    ],
    [
      "confirmed-broken claim",
      "An image on this page shows a broken image icon instead of the picture visitors expect.",
    ],
    [
      "nearly-all-generic claim",
      "This page is built almost entirely from generic containers with no semantic meaning.",
    ],
  ])("flags a planted overclaim lead: %s", (_label, leadText) => {
    const files = baseFixture();
    files[POLISH_LEAD_FILE] =
      "export const POLISH_FIX_GUIDES = {\n" +
      '  "floating-blobs": {\n' +
      '    effort: "quick",\n' +
      "    effortMinutes: 3,\n" +
      `    lead: "${leadText}",\n` +
      '    default: ["step"],\n' +
      "  },\n" +
      "};\n";

    const h = harness(files);
    const failures = polishCopySafetyFailures(h.read, h.exists, h.listFiles);
    expect(failures.some((f) => f.includes(POLISH_LEAD_FILE) && f.includes("overclaim"))).toBe(
      true,
    );
  });

  it("still catches a planted overclaim in a single-quoted lead line", () => {
    const files = baseFixture();
    files[POLISH_LEAD_FILE] =
      "export const POLISH_FIX_GUIDES = {\n" +
      '  "seo.robots_txt": {\n' +
      '    effort: "quick",\n' +
      "    effortMinutes: 3,\n" +
      "    lead: 'Your robots.txt file blocks crawling across the whole site.',\n" +
      '    default: ["step"],\n' +
      "  },\n" +
      "};\n";

    const h = harness(files);
    const failures = polishCopySafetyFailures(h.read, h.exists, h.listFiles);
    expect(
      failures.some(
        (f) =>
          f.includes(POLISH_LEAD_FILE) &&
          f.includes("overclaim") &&
          /blocks crawling across/i.test(f),
      ),
    ).toBe(true);
  });

  it("fails loudly on a lead line whose value uses no recognized quote character", () => {
    const files = baseFixture();
    files[POLISH_LEAD_FILE] =
      "export const POLISH_FIX_GUIDES = {\n" +
      '  "floating-blobs": {\n' +
      '    effort: "quick",\n' +
      "    effortMinutes: 3,\n" +
      "    lead: someImportedConstant,\n" +
      '    default: ["step"],\n' +
      "  },\n" +
      "};\n";

    const h = harness(files);
    const failures = polishCopySafetyFailures(h.read, h.exists, h.listFiles);
    expect(
      failures.some((f) => f.includes(POLISH_LEAD_FILE) && /recognized quote style/i.test(f)),
    ).toBe(true);
  });

  it("keeps every real bundled polish lead sentence passing", () => {
    const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");
    const exists = (relativePath) => fs.existsSync(path.join(ROOT, relativePath));
    const listFiles = (dir, filter) => {
      const out = [];
      const walk = (current) => {
        for (const entry of fs.readdirSync(path.join(ROOT, current), { withFileTypes: true })) {
          const rel = `${current}/${entry.name}`;
          if (entry.isDirectory()) {
            if (entry.name === "node_modules" || entry.name === "target" || entry.name === "dist") {
              continue;
            }
            walk(rel);
          } else if (!filter || filter(rel)) {
            out.push(rel);
          }
        }
      };
      if (fs.existsSync(path.join(ROOT, dir))) walk(dir);
      return out;
    };

    expect(polishCopySafetyFailures(read, exists, listFiles)).toEqual([]);
  });
});
