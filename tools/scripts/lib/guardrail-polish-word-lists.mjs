import { stripComments, stripNonCode } from "./guardrail-source-text.mjs";

const ROOT = "apps/desktop/src-tauri/crates/engine/src/checks/polish";
const LITERAL = /(?:br|r)(#*)"[\s\S]*?"\1|b?"(?:\\[\s\S]|[^"\\])*"/y;

function endOf(code, open, left, right) {
  let depth = 1;
  for (let i = open + 1; i < code.length; i += 1) {
    if (code[i] === left) depth += 1;
    if (code[i] === right && --depth === 0) return i;
  }
  return -1;
}

/** The `{` that opens the test module or function an attribute starts, or -1 for any other item. */
function testItemBody(code, cursor) {
  const skipSpace = () => {
    while (/\s/.test(code[cursor] ?? "")) cursor += 1;
  };
  skipSpace();
  // Further attributes, as in `#[cfg(test)] #[allow(dead_code)] mod tests {`.
  while (code.startsWith("#[", cursor)) {
    const close = code.indexOf("]", cursor);
    if (close < 0) return -1;
    cursor = close + 1;
    skipSpace();
  }
  if (code.startsWith("pub", cursor)) {
    let after = cursor + 3;
    if (code[after] === "(") after = code.indexOf(")", after) + 1;
    if (after > 0 && /\s/.test(code[after] ?? "")) {
      cursor = after;
      skipSpace();
    }
  }
  const item = /(?:mod|fn)\s+\w+/y;
  item.lastIndex = cursor;
  if (item.exec(code) === null) return -1;
  for (let i = item.lastIndex; i < code.length; i += 1) {
    if (code[i] === "{") return i;
    if (code[i] === ";") return -1;
  }
  return -1;
}

function productionCode(source, file) {
  let code = stripNonCode(source, file);
  for (const match of code.matchAll(/#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]/g)) {
    // An attribute inside a test item blanked earlier is already gone.
    if (code[match.index] !== "#") continue;
    const open = testItemBody(code, match.index + match[0].length);
    if (open < 0) continue;
    const end = endOf(code, open, "{", "}");
    if (end >= 0)
      code =
        code.slice(0, match.index) +
        code.slice(match.index, end + 1).replace(/[^\n]/g, " ") +
        code.slice(end + 1);
  }
  return code;
}

function stringCount(body, separator = ",") {
  let cursor = 0;
  let count = 0;
  while (cursor < body.length) {
    while (/\s/.test(body[cursor] ?? "") && cursor < body.length) cursor += 1;
    if (cursor === body.length) break;
    LITERAL.lastIndex = cursor;
    const literal = LITERAL.exec(body);
    if (literal === null) return 0;
    count += 1;
    cursor = LITERAL.lastIndex;
    while (/\s/.test(body[cursor] ?? "") && cursor < body.length) cursor += 1;
    if (cursor === body.length) break;
    if (body[cursor++] !== separator) return 0;
  }
  return count;
}

function annotated(lines, line) {
  let index = line - 2;
  while (/^\s*#\[.*\]\s*$/.test(lines[index] ?? "")) index -= 1;
  return /^\s*\/\/ technical vocabulary: https:\/\/\S+\s*$/.test(lines[index] ?? "");
}

function sourceLine(source, code, index) {
  const line = source.slice(0, index).split("\n").length;
  const declarations = [...code.slice(0, index).matchAll(/\b(?:const|static|let|fn)\s+\w+/g)];
  const declaration = declarations.at(-1)?.index;
  return [line, declaration === undefined ? line : source.slice(0, declaration).split("\n").length];
}

/** Reject unsourced literal vocabularies, including wrapped arrays and matches. */
export function polishWordListFailures(read, exists, listFiles) {
  const failures = [];
  for (const file of listFiles(
    ROOT,
    (name) => name.endsWith(".rs") && !/(?:^|\/)tests\.rs$/.test(name),
  )) {
    if (!exists(file)) {
      failures.push(`${file}: listed polish source is missing`);
      continue;
    }
    const source = read(file);
    const code = productionCode(source, file);
    const strings = stripComments(source, file);
    const lines = source.split("\n");
    const candidates = [];
    for (const open of code.matchAll(/\[/g)) {
      const end = endOf(code, open.index, "[", "]");
      if (end >= 0 && stringCount(strings.slice(open.index + 1, end)) >= 2)
        candidates.push(open.index);
    }
    for (const match of code.matchAll(/\bmatches!\s*\(/g)) {
      const open = match.index + match[0].length - 1;
      const end = endOf(code, open, "(", ")");
      let cursor = open + 1;
      while (cursor < end && code[cursor] !== ",") {
        if (code[cursor] === "(") cursor = endOf(code, cursor, "(", ")");
        cursor += 1;
      }
      if (end >= 0 && stringCount(strings.slice(cursor + 1, end).replace(/,\s*$/, ""), "|") >= 2)
        candidates.push(match.index);
    }
    for (const index of candidates) {
      const positions = sourceLine(source, code, index);
      if (positions.some((line) => annotated(lines, line))) continue;
      failures.push(
        `${file}:${positions[1]}: move this word list into word_lists.json or cite its technical vocabulary`,
      );
    }
  }
  return failures;
}
