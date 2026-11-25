import { expect, it } from "vitest";

import { tomlFields } from "./lib/toml-fields.mjs";

it.each([
  ['"', '"'],
  ['"', '""'],
  ["'", "'"],
  ["'", "''"],
])("reads a multiline string ending with delimiter quotes (%s%s)", (quote, suffix) => {
  // Extra closing quotes consumed the field after a multiline string.
  const delimiter = quote.repeat(3);
  const source = `[package]\ndescription = ${delimiter}x${suffix}${delimiter}\nname = "fixture"\n`;
  expect(tomlFields(source)).toEqual([
    { path: ["package", "description"], value: `x${suffix}` },
    { path: ["package", "name"], value: "fixture" },
  ]);
});

it.each(["\n", "\r\n"])("joins multiline basic strings across a line ending (%j)", (newline) => {
  // A line-ending backslash left the newline and indentation in the decoded field.
  const source = ['name = """', "public-\\ \t", " ", '  fixture"""'].join(newline);
  expect(tomlFields(source)).toEqual([{ path: ["name"], value: "public-fixture" }]);
});

it("decodes TOML byte escapes in basic string keys and values", () => {
  // TOML 1.1 byte escapes were left encoded in keys and values.
  const source = String.raw`"fixtur\x65" = """\x4f\x4B"""`;
  expect(tomlFields(source)).toEqual([{ path: ["fixture"], value: "OK" }]);
});

it("decodes the TOML escape character in basic strings", () => {
  // TOML 1.1's escape character decoded as the letter e.
  const source = String.raw`value = "\e[0m"`;
  expect(tomlFields(source)).toEqual([{ path: ["value"], value: "\u001b[0m" }]);
});
