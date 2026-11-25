import { stripNonCode } from "./guardrail-source-text.mjs";

// Default runner node in the import graph.
export const RUNNER = "check-repo-guardrails.mjs";

const IMPORT_PATTERN = /import\s*\{([^}]*)\}\s*from\s*"([^"]+)";/g;
// Match imports after string literals have been blanked.
const IMPORT_STATEMENT = /import\s*\{[^}]*\}[^;]*;/g;

function namedExports(source) {
  // Cover function, variable, and re-export forms in formatted source.
  const named = [
    ...[...source.matchAll(/^export (?:async )?function (\w+)/gm)].map((match) => match[1]),
    ...[...source.matchAll(/^export (?:const|let|var) (\w+)/gm)].map((match) => match[1]),
  ];
  for (const [, clause] of source.matchAll(/^export \{([^}]*)\}/gm)) {
    for (const binding of clause.split(",")) {
      // `foo as bar` exports bar, which is the name another module imports.
      const exported = binding
        .trim()
        .split(/\s+as\s+/)
        .pop();
      if (exported) named.push(exported);
    }
  }
  return named;
}

function namedImports(source) {
  const imports = [];
  for (const declaration of source.matchAll(IMPORT_PATTERN)) {
    for (const clause of declaration[1].split(",")) {
      // `foo as bar` binds bar locally but names foo in the target module.
      const [exported, local] = clause.trim().split(/\s+as\s+/);
      if (exported) imports.push({ exported, local: local ?? exported, from: declaration[2] });
    }
  }
  return imports;
}

// Return live identifiers after removing imports, declarations, and non-code.
function usedIdentifiers(source, file) {
  const code = stripNonCode(source, file)
    .replace(IMPORT_STATEMENT, "")
    .replace(/\b(?:function|class)\s+\w+/g, "function");
  return new Set(code.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? []);
}

// Resolve both supported local module spellings.
function resolveModule(specifier) {
  if (!specifier.startsWith(".")) return null;
  const name = specifier.split("/").pop();
  return name.endsWith(".mjs") ? name : null;
}

/**
 * @param {Map<string, string>} sources guardrail modules plus their runners
 * @param {string[]} runners entry points that execute guardrail rules
 * @returns {string[]} unreachable rule exports
 */
export function runnerWiringFailures(sources, runners = [RUNNER]) {
  for (const runner of runners) {
    if (!sources.has(runner)) return [`${runner} is missing from the module graph.`];
  }

  const exportsByModule = new Map();
  const usesByModule = new Map();
  const importsByModule = new Map();
  for (const [name, source] of sources) {
    exportsByModule.set(name, namedExports(source));
    usesByModule.set(name, usedIdentifiers(source, name));
    importsByModule.set(name, namedImports(source));
  }

  // Include imported bindings and locally invoked exports.
  const invocationsFrom = (name) => {
    const uses = usesByModule.get(name) ?? new Set();
    const invocations = new Set();
    for (const { exported, local, from } of importsByModule.get(name) ?? []) {
      const target = resolveModule(from);
      if (target && sources.has(target) && uses.has(local))
        invocations.add(`${target}::${exported}`);
    }
    for (const exported of exportsByModule.get(name) ?? []) {
      if (uses.has(exported)) invocations.add(`${name}::${exported}`);
    }
    return invocations;
  };

  const wired = new Set();
  const reachable = new Set(runners);
  const pending = [...runners];
  while (pending.length > 0) {
    for (const invocation of invocationsFrom(pending.pop())) {
      if (wired.has(invocation)) continue;
      wired.add(invocation);
      const module = invocation.slice(0, invocation.indexOf("::"));
      if (!reachable.has(module)) {
        reachable.add(module);
        pending.push(module);
      }
    }
  }

  const failures = [];
  for (const [name, exported] of exportsByModule) {
    if (runners.includes(name) || !/^guardrail-.*\.mjs$/.test(name)) continue;
    for (const rule of exported) {
      if (!rule.endsWith("Failures") || wired.has(`${name}::${rule}`)) continue;
      failures.push(
        `tools/scripts/lib/${name} exports ${rule}, which nothing reaches from ${runners.join(" or ")}. An unwired rule passes its own tests and guards nothing - call it from a runner, reach it from a rule a runner calls, or delete it.`,
      );
    }
  }
  return failures;
}
