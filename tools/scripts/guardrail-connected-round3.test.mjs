import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const base = "apps/desktop/src-tauri/";
const read = (file) => readFileSync(file, "utf8");

describe("connected review round 3", () => {
  it("P1 documents canonicalizer version 3 path escapes", () => {
    // Q1: quoted JSON version pins stayed obsolete while the unquoted check passed.
    const spec = read("docs/engineering/connected-service/connected-protocol-spec.md");
    expect(spec).not.toContain("Bytes outside unreserved ASCII are preserved as sent");
    expect(spec).not.toMatch(/["'`]?canonicalizer["'`]?\s*:\s*1\b/);
    expect(spec).toContain("canonicalizer: 3");
    expect(spec).toContain("Authored non-ASCII");
    expect(spec).toContain("uppercase UTF-8 percent escapes under version 3");
    expect(spec).toContain("`canonicalizer`: integer, currently 3");
    expect(spec).toContain("### Canonicalization, version 3");
  });

  it("names the exact encoded characters including caret", () => {
    // Canonical route spellings must agree across native and hosted producers.
    const spec = read("docs/engineering/connected-service/connected-protocol-spec.md");
    expect(spec).toContain("these ten characters");
    expect(spec).toContain("The engine encodes `^` as `%5E` to match the hosted canonicalizer.");
  });

  it("removes the unused site-origin wire contract", () => {
    // Site origins: an unused type implied a request contract without any producer.
    const fixture = JSON.parse(read(`${base}tests/fixtures/parity/wire_identifiers.json`));
    expect(fixture.types).not.toHaveProperty("site_origin");
    expect(fixture.rules).not.toHaveProperty("site_origin");
    expect(read(`${base}crates/protocol/src/sync/wire.rs`)).not.toContain("SiteOrigin");
    expect(read(`${base}crates/protocol/src/sync/wire_grammar.rs`)).not.toContain("fn site_origin");
    expect(read(`${base}crates/protocol/src/sync/wire_tests.rs`)).not.toContain(
      '.remove("site_origin")',
    );
  });

  it("P4 removes obsolete non-ASCII grammar and encoding documentation", () => {
    // P4: the grammar retained an unreachable non-ASCII branch and its encoder comment was false.
    const grammar = read(`${base}crates/protocol/src/sync/wire_grammar.rs`);
    const route = read(`${base}crates/protocol/src/route.rs`);
    expect(grammar).not.toContain("!c.is_ascii()");
    expect(route).not.toContain("any non-ASCII byte alone");
    expect(route).toContain("Encode raw non-ASCII and ten printable ASCII characters");
    expect(route).not.toContain("and path percent-encode characters");
    expect(read("docs/engineering/connected-service/connected-protocol-spec.md")).toContain(
      "which URL parsing removes; raw backslashes become slashes.",
    );
  });

  it("P7 describes route compatibility without internal review ids", () => {
    // P7: the vendored corpus described compatibility using a private review item id.
    const fixture = JSON.parse(read(`${base}tests/fixtures/parity/wire_identifiers.json`));
    expect(fixture.types.route_path._comment).not.toContain("N6");
    expect(fixture.types.route_path._comment).toContain("after canonicalizer version 3");
  });
});
