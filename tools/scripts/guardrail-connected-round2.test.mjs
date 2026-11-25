import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { connectedRequestFailures } from "./lib/guardrail-connected-request-rules.mjs";
const base = "apps/desktop/src-tauri/";
const wire = `${base}crates/protocol/src/sync/wire.rs`;
const read = (file) => readFileSync(file, "utf8");
const check = (source, extra = {}) => {
  const sources = { [wire]: read(wire), [`${base}src/future.rs`]: source, ...extra };
  return connectedRequestFailures(Object.keys(sources), (file) => sources[file]);
};
describe("connected review round 2", () => {
  it.each(["Hidden", "Vec<Hidden>"])("N1a audits tuple request fields: %s", (type) => {
    // N1a: tuple request bodies hid nested free text from the transitive audit.
    expect(
      check(
        `#[derive(Serialize)] struct FutureRequest(${type}); impl WireRequest for FutureRequest {} #[derive(Serialize)] struct Hidden { note: String }`,
      ),
    ).not.toEqual([]);
  });
  it.each(["Vec<String>", "Option<Hidden>", "&'static str", "(String,)"])(
    "N1b refuses non-declaration roots: %s",
    (type) => {
      // N1b: generic, reference, and tuple roots bypassed the sealed request audit.
      expect(
        check(
          `impl WireRequest for ${type} {} #[derive(Serialize)] struct Hidden { note: String }`,
        ),
      ).not.toEqual([]);
    },
  );
  it("N1b fingerprints the sealed transport boundary", () => {
    // N1b: editing Sealed could admit an unaudited root without a review failure.
    const file = `${base}src/connected_service/request_body.rs`;
    expect(
      check("", {
        [file]: read(file).replace(
          "pub trait Sealed {}",
          "pub trait Sealed {} impl Sealed for Vec<String> {}",
        ),
      }).join("\n"),
    ).toContain("serializer changed");
  });
  it.each(["Digest", "Identifier"])(
    "M6 N1c resolves imported and qualified manual serializers: %s",
    (name) => {
      // M6/N1c: an audited leaf name concealed a hand-written serializer in another module.
      const extra = {
        [`${base}src/x.rs`]: `pub struct ${name}(pub String); impl serde::Serialize for ${name} {}`,
      };
      for (const type of [name, `crate::x::${name}`]) {
        expect(
          check(
            `use crate::x::${name}; #[derive(Serialize)] struct FutureRequest { value: ${type} } impl WireRequest for FutureRequest {}`,
            extra,
          ),
        ).not.toEqual([]);
      }
    },
  );
  it("M6 resolves trusted aliases without confusing unrelated definitions", () => {
    // M6: the privacy gate must resolve a definition rather than trusting or banning its short name.
    expect(
      check(
        "use sitecmd_protocol::sync::wire::Digest as SafeDigest; #[derive(Serialize)] struct FutureRequest { value: SafeDigest } impl WireRequest for FutureRequest {}",
        {
          [`${base}src/x.rs`]: "#[derive(Serialize)] pub struct Digest { note: String }",
        },
      ),
    ).toEqual([]);
  });
  it("M6 resolves a module alias before trusting an external crate path", () => {
    // M6: a namespace import could redirect an apparently trusted qualified leaf.
    expect(
      check(
        "use crate::x as sitecmd_protocol; #[derive(Serialize)] struct FutureRequest { value: sitecmd_protocol::sync::wire::Digest } impl WireRequest for FutureRequest {}",
        {
          [`${base}src/x/sync/wire.rs`]: "#[derive(Serialize)] pub struct Digest { note: String }",
        },
      ),
    ).not.toEqual([]);
  });
  it("M6 resolves local modules before external crate names", () => {
    // M6: a local module can shadow a trusted crate namespace without sharing its definition.
    expect(
      check(
        "mod sitecmd_protocol { pub mod sync { pub mod wire { #[derive(Serialize)] pub struct Digest { note: String } } } } #[derive(Serialize)] struct FutureRequest { value: sitecmd_protocol::sync::wire::Digest } impl WireRequest for FutureRequest {} ",
      ),
    ).not.toEqual([]);
  });
  it("N1b rejects generic implementations as unaudited roots", () => {
    // N1b: a generic impl header must not hide a container request root from discovery.
    expect(check("impl<T> WireRequest for Vec<T> {} ")).not.toEqual([]);
  });
  it("M6 rejects opaque numeric collections through qualified container paths", () => {
    // M6: preserving module paths must not admit numeric collections rejected by the original gate.
    expect(
      check(
        "#[derive(Serialize)] struct FutureRequest { bytes: std::vec::Vec<std::option::Option<u8>> } impl WireRequest for FutureRequest {} ",
      ),
    ).not.toEqual([]);
  });
  it("N2 isolates the macro serializer rule with an audited field", () => {
    // N2: an undeclared Secret field made the macro regression pass with the macro rule deleted.
    const source =
      "use sitecmd_protocol::sync::wire::CheckId; #[derive(Serialize)] struct FutureRequest { value: CheckId } impl WireRequest for FutureRequest {}";
    expect(check(source)).toEqual([]);
    expect(
      check(`${source} macro_rules! secret { () => { impl Serialize for $name {} } }`).join("\n"),
    ).toContain("custom request serializer");
  });
  it("Corpus records canonical values and excludes dashboard operation fields", () => {
    // Corpus: dashboard-only field policies and silent canonical rewrites must not redefine CLI wire values.
    const fixture = JSON.parse(read(`${base}tests/fixtures/parity/wire_identifiers.json`));
    expect(fixture._comment).toContain("21 dashboard-only");
    expect(fixture.types.route_path._comment).toContain("canonical wire value /caf%C3%A9");
    expect(fixture.types).not.toHaveProperty("site_origin");
    expect(fixture.types.route_path.valid).toContain("/caf%C3%A9");
    expect(fixture.types.route_path.invalid).toContain("/café");
    for (const name of ["PutScopeBody", "MintCiTokenBody", "CreateSiteBody"])
      expect(fixture.types).not.toHaveProperty(name);
  });
  it("P5 removes unused connected reads and their models and tests", () => {
    // P5: six reads with no caller kept dead public methods, response models, and tests.
    const source = read(`${base}src/connected_service.rs`);
    for (const file of ["read_views.rs", "read_models.rs", "read_views_tests.rs"])
      expect(existsSync(`${base}src/connected_service/${file}`)).toBe(false);
    expect(source).not.toContain("read_views");
    expect(source).not.toContain("read_models");
    for (const name of [
      "verified_good_profile",
      "list_site_credentials",
      "list_reports",
      "list_alert_webhooks",
      "list_destinations",
      "notification_settings",
    ])
      expect(source).not.toContain(`pub async fn ${name}(`);
  });
  it("N8 directs setup and token pins to the SiteCMD dashboard", () => {
    // N8: CLI remediation still pointed to deleted desktop setup and token flows.
    const source = read(`${base}src/cli/connected_submit.rs`);
    for (const stale of [
      "select or seed the governing CI workflow in the desktop app",
      "pins chosen in the desktop app",
      "Connect this site in the desktop app",
      "connected dashboard",
    ])
      expect(source).not.toContain(stale);
    expect(read("README.md")).not.toContain("manage those from Settings in the desktop app");
  });
  it("N9 documents current bootstrap and group reads", () => {
    // N9: deleted scope writes left misleading bootstrap and groups documentation.
    const source = read(`${base}src/connected_service.rs`);
    expect(source).not.toContain("which the bootstrap path reads as its cue");
    expect(source).not.toContain("Replace scope under an optimistic revision guard");
  });
  it("N10 removes impossible length checks and blank field gaps", () => {
    // N10: typed constructors made duplicate validation dead and removals left literal gaps.
    const source = read(`${base}src/connected_ci.rs`);
    expect(source).not.toContain("ordering.authority_id.is_empty()");
    expect(source).not.toContain("predecessor.is_empty()");
    for (const file of [
      "src/connected_ci.rs",
      "src/connected_ci_tests.rs",
      "src/db/connected_payload.rs",
    ])
      expect(read(`${base}${file}`)).not.toMatch(/(?:manifest_digest|deployment):[^\n]*,\n\s*\n/);
  });
});
