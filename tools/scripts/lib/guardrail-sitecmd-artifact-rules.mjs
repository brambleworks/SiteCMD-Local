import path from "node:path";

import { stripComments, stripNonCode } from "./guardrail-source-text.mjs";

const TEST_MODULE =
  /^[ \t]*#\[cfg\((test|all\([\w, ]+\))\)\]\s*(?:#\[path\s*=\s*"([^"]+)"\]\s*)?mod\s+(\w+)\s*([;{])/gm;
const ARTIFACT_SOURCE =
  /(?:\.sitecmd(?:[/"\\])|\b(?:last-scan\.json|config\.json|issues\.json|issues\.md|rules\.md)\b|\bfind_config_dir\s*\()/;
const FILE_ACCESS =
  /\b(?:(?:fs\s*::\s*)?read_to_string|fs\s*::\s*(?:read|write)|File\s*::\s*(?:open|create))\s*\(/g;

function moduleEnd(code, start) {
  let depth = 1;
  for (let index = start; index < code.length; index += 1) {
    if (code[index] === "{") depth += 1;
    if (code[index] === "}") depth -= 1;
    if (depth === 0) return index + 1;
  }
  return code.length;
}

function productionSource(source, file, testFiles) {
  const code = stripNonCode(source, file);
  const modules = [...stripComments(source, file).matchAll(TEST_MODULE)].reverse();
  for (const match of modules) {
    const [declaration, condition, fileName, name, delimiter] = match;
    if (
      condition !== "test" &&
      !condition
        .slice(4, -1)
        .split(",")
        .map((value) => value.trim())
        .includes("test")
    ) {
      continue;
    }
    const start = match.index + declaration.length;
    if (delimiter === "{") {
      source = source.slice(0, match.index) + source.slice(moduleEnd(code, start));
    } else {
      const directory = path.posix.dirname(file);
      const moduleDirectory = file.endsWith("/mod.rs") ? directory : file.slice(0, -3);
      testFiles.add(
        fileName ? path.posix.join(directory, fileName) : `${moduleDirectory}/${name}.rs`,
      );
    }
  }
  return source;
}

function firstArgumentEnd(code, start) {
  let depth = 0;
  for (let index = start; index < code.length; index += 1) {
    const token = code[index];
    if (depth === 0 && (token === "," || token === ")")) return index;
    if ("([{".includes(token)) depth += 1;
    if (")]}".includes(token)) depth -= 1;
  }
  return code.length;
}

function usesDirectArtifactAccess(source, file) {
  const paths = stripComments(source, file);
  const code = stripNonCode(source, file);
  const artifactVariables = new Set(["sitecmd_dir"]);
  const referencesArtifact = (expression) =>
    ARTIFACT_SOURCE.test(expression) ||
    (expression.match(/\b\w+\b/g) ?? []).some((word) => artifactVariables.has(word));

  for (const binding of code.matchAll(/\blet\s+(?:mut\s+)?(\w+)\s*=\s*[^;]+;/g)) {
    if (referencesArtifact(paths.slice(binding.index, binding.index + binding[0].length))) {
      artifactVariables.add(binding[1]);
    }
  }
  return [...code.matchAll(FILE_ACCESS)].some((call) => {
    const start = call.index + call[0].length;
    return referencesArtifact(paths.slice(start, firstArgumentEnd(code, start)));
  });
}

export function sitecmdArtifactFailures(read, listFiles) {
  const files = listFiles(
    "apps/desktop/src-tauri/src/cli",
    (file) => file.endsWith(".rs") && !/(?:\/tests(?:\/|\.rs$)|_tests\.rs$)/.test(file),
  );
  const testFiles = new Set();
  const sources = files.map((file) => [file, productionSource(read(file), file, testFiles)]);
  return sources
    .filter(([file, source]) => !testFiles.has(file) && usesDirectArtifactAccess(source, file))
    .map(
      ([file]) =>
        `${file} must use the shared bounded readers and atomic writer for .sitecmd artifacts.`,
    );
}
