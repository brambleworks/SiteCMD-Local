import { readFileSync, readdirSync } from "node:fs";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { expect, it } from "vitest";

const directory = "tools/scripts/";
const connected = "guardrail-connected-request-rules.mjs";
const redaction = "guardrail-redaction-order-rules.mjs";
const wire = "guardrail-rust-wire-index.mjs";

function parse(file) {
  return ts.createSourceFile(
    file,
    readFileSync(directory + file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
}

function nodes(source, predicate) {
  const found = [];
  function visit(node) {
    if (predicate(node)) found.push(node);
    ts.forEachChild(node, visit);
  }
  visit(source);
  return found;
}

const fixtureFiles = readdirSync(directory).filter(
  (file) => /^guardrail-(?:connected|redaction|rust-wire)/.test(file) && file.endsWith(".test.mjs"),
);
const inputs = fixtureFiles.flatMap((file) => {
  const source = parse(file);
  return [
    source.text,
    ...nodes(source, (node) => ts.isStringLiteralLike(node) || ts.isTemplateLiteralToken(node)).map(
      (node) => node.text,
    ),
  ];
});

function productionRegex(file, prefix) {
  const source = parse("lib/" + file);
  const matches = nodes(source, (node) => ts.isRegularExpressionLiteral(node)).filter((node) =>
    node.text.startsWith("/" + prefix),
  );
  expect(matches).toHaveLength(1);
  const literal = matches[0].text;
  return new RegExp(literal.slice(1, literal.lastIndexOf("/")), "g");
}

function productionFunction(name) {
  const source = parse("lib/" + connected);
  const matches = nodes(
    source,
    (node) => ts.isFunctionDeclaration(node) && node.name?.text === name,
  );
  expect(matches).toHaveLength(1);
  return runInNewContext(`(${matches[0].getText(source)})`);
}

function captures(pattern, input) {
  return [...input.matchAll(pattern)].map((match) => ({
    values: [...match],
    index: match.index,
    groups: match.groups,
  }));
}

function equivalent(file, prefix, oldPattern, nearMisses) {
  const previous = new RegExp(oldPattern, "g");
  const current = productionRegex(file, prefix);
  for (const input of [...inputs, ...nearMisses]) {
    expect(captures(current, input), input).toEqual(captures(previous, input));
  }
}

it("preserves cfg test module match ranges and captures", () => {
  equivalent(
    connected,
    String.raw`#\[cfg`,
    String.raw`#\[cfg\(test\)\]\s*(?:#\[path[^\n]+\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*([;{])`,
    [
      ...["", '#[path = "tests.rs"]\n'].flatMap((path) =>
        ["", "pub ", "pub(crate) ", "pub()\n"].flatMap((visibility) =>
          [";", "{"].map((end) => `#[cfg(test)]\n${path}${visibility}mod tests ${end}`),
        ),
      ),
      "#[cfg(test)] #[path] mod tests;",
      "#[cfg(test)] #[path =\n] pub mod tests;",
      "#[cfg(test)] pub(crate mod tests;",
      "#[cfg(test)] pubmod tests;",
      "#[cfg(test)] mod tests",
    ],
  );
});

it("preserves qualified wire root validation", () => {
  const previous = new RegExp(String.raw`^(?:\w+::)*\w+$`);
  const current = productionFunction("isWirePath");
  for (const input of [
    ...inputs,
    "Root",
    "crate::module::Root",
    "0::_::9",
    "",
    "::Root",
    "crate::",
    "crate:::Root",
    "crate::Root\n",
    "Vec<Root>",
    "x".repeat(1024) + "::!",
  ]) {
    expect(current(input), input).toBe(previous.test(input));
  }
});

it("preserves opaque field detection through nested numeric vectors", () => {
  const previous = new RegExp(
    String.raw`\b(?:String|str|Value|HashMap|Map)\b|\bVec\s*<\s*(?:(?:Option|Vec)\s*<\s*)*(?:[uif]\d+|bool)\b|\[[^\]]*\]`,
  );
  const current = productionFunction("hasOpaqueField");
  for (const input of [
    ...inputs,
    "Vec < Option < Vec < u8>>>",
    "Vec<Option<bool>>",
    "Vec<Option<Option<u123>>>",
    "Vec<core::option::Option<u8>>",
    "Vec< OptionVec<u8>>",
    "Vec<Option<NotNumeric>> Vec<i64>",
    "Vec<Option<u8suffix>>",
    "Stringish",
    "[unfinished",
    "[x]\n[]",
    "Vec<".repeat(128) + "Other",
    "Vec<".repeat(128) + "bool",
  ]) {
    expect(current(input), input).toBe(previous.test(input));
  }
});

it("preserves qualified type path matches on malformed paths", () => {
  const previous = new RegExp(String.raw`(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*`, "g");
  const current = productionFunction("typePaths");
  for (const input of [
    ...inputs,
    "crate::module::Root",
    "Option<crate::Foo> Vec<u8>",
    "a:::b a:: b a::0b a::b::",
    "9a::b ::_x::Y",
    "a::".repeat(128) + "!",
  ]) {
    expect([...current(input)], input).toEqual(input.match(previous) ?? []);
  }
});

it("preserves binding names expressions mutations and match ranges", () => {
  equivalent(
    redaction,
    String.raw`\blet\s+(?:mut`,
    String.raw`\blet\s+(?:mut\s+)?(?<name>\w+)(?:\s*:[^=;]+)?\s*=\s*(?<expression>[\s\S]*?);|\b(?<mutated>\w+)\.truncate\s*\([^;]*;`,
    [
      "let mut preview: &str = &value[..70]; preview.truncate(3);",
      "let mut = value; let mutx = x;",
      "let x: = value;",
      "let x: ; let y = z;",
      "let x == y;",
      "let x =\n value;",
      "let x = unfinished",
      "x.truncate(unfinished;",
      "let x" + " ".repeat(128) + "!",
    ],
  );
});

it("preserves redacted binding matches with optional module paths", () => {
  equivalent(
    redaction,
    String.raw`\blet\s+(\w+)`,
    String.raw`\blet\s+(\w+)\s*=\s*(?:[\w:]+::)?redact_\w+\s*\(`,
    [
      "let safe = redact_secrets(x);",
      "let safe = crate::module::redact_secrets (x);",
      "let safe = :::redact_secrets(x);",
      "let safe = 0::redact_secrets(x);",
      "let safe = crate:redact_secrets(x);",
      "let safe = redact_(x);",
      "let safe = crate::redact_secrets! (x);",
    ],
  );
});

it("preserves trailing public visibility removal", () => {
  equivalent(wire, String.raw`pub(?:`, String.raw`pub(?:\([^)]*\))?\s*$`, [
    "#[derive(Serialize)] pub(crate) ",
    "pub()\n",
    "pub(crate",
    "pub(crate) trailing",
    "notpub ",
    "pub(crate))",
  ]);
});

it("preserves named field captures with public visibility", () => {
  equivalent(
    wire,
    String.raw`^\s*(?:pub`,
    String.raw`^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:(?!:)\s*([\s\S]*)$`,
    [
      "pub(crate) field: Option<u8>",
      "pub field: \n String",
      "pubfield: Type",
      "pub(crate)field: Type",
      "field::Type",
      "pub: Type",
      "pub(crate field: Type",
      "pub() 9: ",
      "field: trailing\n",
    ],
  );
});

it("preserves public visibility removal from tuple fields", () => {
  equivalent(wire, String.raw`\bpub(?:`, String.raw`\bpub(?:\([^)]*\))?\s*`, [
    "pub(crate) Option<u8>, pub String",
    "publicity pub()Type",
    "notpub pub(crate",
    "pub(crate)) Type",
    "pub \n Type",
  ]);
});
