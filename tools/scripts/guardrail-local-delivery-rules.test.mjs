import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { repoGuardrailIo } from "./check-repo-guardrails.mjs";
import { localDeliveryFailures } from "./lib/guardrail-local-delivery-rules.mjs";

const io = repoGuardrailIo(process.cwd());

/** The local delivery rule's failures with `file` replaced by `source`. It
 *  calls the rule alone: the whole repository suite took over five seconds a
 *  case on CI's two-core runners and timed out. */
function withFile(file, source) {
  const read = (name) => (name === file ? source : io.read(name));
  return localDeliveryFailures(
    read("lefthook.yml"),
    JSON.parse(read("package.json")).scripts ?? {},
    read,
    io.listFiles,
  );
}

it("runs the local delivery rule in the repository guardrails", () => {
  const suite = readFileSync(new URL("./check-repo-guardrails.mjs", import.meta.url), "utf8");
  expect(suite).toContain(
    "failures.push(...localDeliveryFailures(lefthook, packageJson.scripts ?? {}, read, listFiles));",
  );
});

it("rejects a lefthook hook named gate", () => {
  expect(withFile("lefthook.yml", '"gate":\n  commands: {}\n')).toContain(
    "lefthook.yml must not define a hook named gate.",
  );
});

it.each([
  ["commands", (job) => `    ${job}:\n      run: exit 0`],
  ["jobs", (job) => `    - name: ${job}\n      run: exit 0`],
])("rejects the retired receipt job in pre-push %s", (key, entry) => {
  const job = ["gate", "pass"].join("-");
  expect(withFile("lefthook.yml", `pre-push:\n  ${key}:\n${entry(job)}\n`)).toContain(
    "lefthook.yml must not require a local verification receipt before pushing.",
  );
});

it.each(["package.json", "CONTRIBUTING.md", "tools/scripts/verify-push.mjs"])(
  "rejects the retired pnpm command in %s",
  (file) => {
    const command = ["pnpm", "gate"].join(" ");
    const source = io.read(file);
    const changed =
      file === "package.json"
        ? source.replace('"scripts": {', `"scripts": {"old": "${command}",`)
        : source + `\n${command}\n`;
    expect(withFile(file, changed)).toContain(
      `${file} must not invoke or document the retired local verification command.`,
    );
  },
);

it.each([
  ["pnpm", "run", "gate"],
  ["lefthook", "run", "gate"],
])("rejects a retired command in app documentation (%s)", (...words) => {
  const file = "apps/desktop/src-tauri/AGENTS.md";
  const command = words.join(" ");
  expect(withFile(file, io.read(file) + `\n${command}\n`)).toContain(
    `${file} must not invoke or document the retired local verification command.`,
  );
});

it("rejects the retired receipt in the public pre-push script", () => {
  const file = ".lefthook/pre-push/public-tree.sh";
  const receipt = ["gate", "pass"].join("-");
  expect(withFile(file, io.read(file) + `\nnode tools/scripts/${receipt}.mjs check\n`)).toContain(
    "lefthook.yml must not require a local verification receipt before pushing.",
  );
});
