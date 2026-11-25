import fs from "node:fs";
import { isBuiltin } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

import { RUNNER, runnerWiringFailures } from "./lib/runner-wiring.mjs";

const SCRIPTS = path.dirname(fileURLToPath(import.meta.url));
const LIB = path.join(SCRIPTS, "lib");
const RUST_POLICY = "audit/check-rust-dependency-policy.mjs";

function repoSources() {
  const sources = new Map();
  for (const name of fs.readdirSync(LIB)) {
    if (name.endsWith(".mjs")) sources.set(name, fs.readFileSync(path.join(LIB, name), "utf8"));
  }
  sources.set(RUNNER, fs.readFileSync(path.join(SCRIPTS, RUNNER), "utf8"));
  sources.set(RUST_POLICY, fs.readFileSync(path.join(SCRIPTS, RUST_POLICY), "utf8"));
  return sources;
}

it("open guardrails import no packages", () => {
  const pending = [RUNNER];
  const visited = new Set();
  const failures = [];

  for (const file of pending) {
    if (visited.has(file)) continue;
    visited.add(file);
    const source = fs.readFileSync(path.join(SCRIPTS, file), "utf8");
    const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
    function visit(node) {
      const specifier =
        ts.isImportDeclaration(node) || ts.isExportDeclaration(node)
          ? node.moduleSpecifier
          : ts.isCallExpression(node) &&
              (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
                (ts.isIdentifier(node.expression) && node.expression.text === "require"))
            ? node.arguments[0]
            : undefined;
      if (specifier && ts.isStringLiteralLike(specifier)) {
        const reference = specifier.text;
        if (reference.startsWith("./") || reference.startsWith("../")) {
          pending.push(path.posix.join(path.posix.dirname(file), reference));
        } else if (!reference.startsWith("node:") || !isBuiltin(reference)) {
          failures.push(`${file}: ${reference}`);
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(tree);
  }

  expect(failures).toEqual([]);
});

describe("runnerWiringFailures", () => {
  it("finds every guardrail rule reachable from a runner", () => {
    // Bug: A guardrail can become unreachable when moved to the Rust-only policy.
    const { scripts } = JSON.parse(
      fs.readFileSync(path.join(SCRIPTS, "../../package.json"), "utf8"),
    );
    expect(scripts["audit:deps:rust-policy"]).toBe(`node tools/scripts/${RUST_POLICY}`);
    expect(runnerWiringFailures(repoSources(), [RUNNER, RUST_POLICY])).toEqual([]);
  });

  it("covers the whole rule surface, not a sample", () => {
    const sources = repoSources();
    const ruleModules = [...sources.keys()].filter((name) => /^guardrail-.*\.mjs$/.test(name));
    expect(ruleModules).toContain("guardrail-cli-surface-rules.mjs");

    const unchecked = ruleModules.filter(
      (name) => !/^export (?:async )?function \w+Failures/m.test(sources.get(name)),
    );
    expect(unchecked).toEqual([
      "guardrail-rust-function.mjs",
      "guardrail-rust-wire-index.mjs",
      "guardrail-script-budgets.mjs",
      "guardrail-source-regex.mjs",
      "guardrail-source-text.mjs",
      "guardrail-text-utils.mjs",
      "guardrail-workflow-yaml.mjs",
    ]);
  });

  it("reports a rule module the runner never imports", () => {
    const sources = repoSources();
    sources.set(
      "guardrail-orphan-rules.mjs",
      "export function orphanFailures(read) {\n  return [read];\n}\n",
    );

    expect(runnerWiringFailures(sources, [RUNNER, RUST_POLICY]).join("\n")).toContain(
      "guardrail-orphan-rules.mjs exports orphanFailures",
    );
  });

  it("reports a rule the runner imports but never calls", () => {
    const sources = new Map([
      [
        "guardrail-sample-rules.mjs",
        "export function sampleFailures(read) {\n  return [read];\n}\n",
      ],
      [RUNNER, 'import { sampleFailures } from "./lib/guardrail-sample-rules.mjs";\n'],
    ]);

    expect(runnerWiringFailures(sources).join("\n")).toContain(
      "guardrail-sample-rules.mjs exports sampleFailures",
    );
  });

  it("is not satisfied by a comment naming the rule", () => {
    const sources = new Map([
      [
        "guardrail-sample-rules.mjs",
        "export function sampleFailures(read) {\n  return [read];\n}\n",
      ],
      [
        RUNNER,
        'import { sampleFailures } from "./lib/guardrail-sample-rules.mjs";\n// sampleFailures(read) used to run here\n',
      ],
    ]);

    expect(runnerWiringFailures(sources).join("\n")).toContain("exports sampleFailures");
  });

  it("is not satisfied by a rule named inside a string literal", () => {
    const sources = new Map([
      [
        "guardrail-sample-rules.mjs",
        "export function sampleFailures(read) {\n  return [read];\n}\n",
      ],
      [
        RUNNER,
        'import { sampleFailures } from "./lib/guardrail-sample-rules.mjs";\nfailures.push("sampleFailures(read) covers this file");\n',
      ],
    ]);

    expect(runnerWiringFailures(sources).join("\n")).toContain("exports sampleFailures");
  });

  it("accepts rules the runner hands to something else instead of naming a call", () => {
    const sources = new Map([
      [
        "guardrail-sample-rules.mjs",
        "export function aFailures(read) {\n  return [read];\n}\nexport function bFailures(read) {\n  return [read];\n}\n",
      ],
      [
        RUNNER,
        'import { aFailures, bFailures } from "./lib/guardrail-sample-rules.mjs";\nfor (const rule of [aFailures, bFailures]) failures.push(...rule(read));\n',
      ],
    ]);

    expect(runnerWiringFailures(sources)).toEqual([]);
  });

  it("reports a rule declared with export const that nothing wires", () => {
    const sources = new Map([
      ["guardrail-sample-rules.mjs", "export const arrowFailures = (read) => [read];\n"],
      [RUNNER, "const failures = [];\n"],
    ]);

    expect(runnerWiringFailures(sources).join("\n")).toContain(
      "guardrail-sample-rules.mjs exports arrowFailures",
    );
  });

  it("accepts an export-const rule the runner does call", () => {
    const sources = new Map([
      ["guardrail-sample-rules.mjs", "export const arrowFailures = (read) => [read];\n"],
      [
        RUNNER,
        'import { arrowFailures } from "./lib/guardrail-sample-rules.mjs";\nconst failures = arrowFailures(read);\n',
      ],
    ]);

    expect(runnerWiringFailures(sources)).toEqual([]);
  });

  it("reports a re-exported rule nothing wires, at both names", () => {
    const sources = new Map([
      [
        "guardrail-sample-rules.mjs",
        'export { hiddenFailures } from "./guardrail-inner-rules.mjs";\n',
      ],
      [
        "guardrail-inner-rules.mjs",
        "export function hiddenFailures(read) {\n  return [read];\n}\n",
      ],
      [RUNNER, "const failures = [];\n"],
    ]);

    const report = runnerWiringFailures(sources).join("\n");
    expect(report).toContain("guardrail-sample-rules.mjs exports hiddenFailures");
    expect(report).toContain("guardrail-inner-rules.mjs exports hiddenFailures");
  });

  it("accepts a rule the runner reaches through another rule", () => {
    const sources = new Map([
      [
        "guardrail-sample-rules.mjs",
        "export function innerFailures(read) {\n  return [read];\n}\nexport function outerFailures(read) {\n  return innerFailures(read);\n}\n",
      ],
      [
        RUNNER,
        'import { outerFailures } from "./lib/guardrail-sample-rules.mjs";\nconst failures = outerFailures(read);\n',
      ],
    ]);

    expect(runnerWiringFailures(sources)).toEqual([]);
  });

  it("does not reach a rule through a module the runner never reaches", () => {
    const sources = new Map([
      [
        "guardrail-marooned-rules.mjs",
        "export function innerFailures(read) {\n  return [read];\n}\nexport function outerFailures(read) {\n  return innerFailures(read);\n}\n",
      ],
      [RUNNER, "const failures = [];\n"],
    ]);

    expect(runnerWiringFailures(sources)).toHaveLength(2);
  });

  it("reports a missing runner rather than passing vacuously", () => {
    expect(runnerWiringFailures(new Map()).join("\n")).toContain(
      "is missing from the module graph",
    );
  });
});
