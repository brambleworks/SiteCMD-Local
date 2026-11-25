import { ENGINE_CRATES } from "./lib/publication-history-rules.mjs";
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { connectedRequestFailures } from "./lib/guardrail-connected-request-rules.mjs";
const rust = "apps/desktop/src-tauri/";
const read = (p) => readFileSync(p, "utf8");
it("names connected request checks by behavior", () => {
  // Numbered labels and missing explanations hid what the connected request checks cover.
  const source = read(new URL(import.meta.url));
  expect(source).not.toMatch(
    /^\s*(?:describe\("(?:[t]ask|[r]eview)\b|it\("[IM]\d+\b|\/\/ [IM]\d+\b)/m,
  );
  for (const [, name, firstLine] of source.matchAll(/^\s*it\("([^"]+)", \(\) => \{\n([^\n]*)/gm)) {
    expect(firstLine, name).toMatch(/^\s*\/\/ \S/);
  }
});

describe("Connected request boundaries", () => {
  it("finds free text in a new top-level service client", () => {
    // Top-level clients can send request bodies from outside the service directory.
    const file = `${rust}src/connected_future.rs`;
    const source =
      "#[derive(Serialize)] struct FutureRequest { note: String } impl WireRequest for FutureRequest {} impl ConnectedServiceClient { fn post() { self.request(Method::POST, url, None, Some(&FutureRequest { note })); } }";
    expect(connectedRequestFailures([file], () => source).join("\n")).toContain("FutureRequest");
  });
  it("requires typed bodies and idempotency at the send boundary", () => {
    // A raw serialized body bypasses request type checks.
    const source = read(`${rust}src/connected_service.rs`);
    const boundary = source.slice(
      source.indexOf("pub(crate) async fn request"),
      source.indexOf("/// One wire exchange"),
    );
    expect(boundary).toContain("WireRequest");
    expect(boundary).not.toContain("Option<String>");
    expect(boundary).toContain("Option<&Digest>");
  });
  it("keeps dashboard setup operations out of the desktop client", () => {
    // The desktop client sent dashboard setup requests the service no longer accepts.
    const source = read(`${rust}src/connected_service.rs`);
    for (const name of [
      "CreateSiteRequest",
      "MintCiTokenRequest",
      "VerifyRequest",
      "ScopePutRequest",
      "pub async fn mutate_group",
      "pub async fn create_site",
    ])
      expect(source).not.toContain(name);
  });
  it("omits unused runtime facts from wire snapshots", () => {
    // Unused runtime facts caused valid gate and sync requests to fail encoding.
    const source = read(`${rust}crates/protocol/src/sync/snapshot.rs`);
    for (const name of [
      "pub execution_profile:",
      "pub stack_facts:",
      "pub engine_release:",
      "pub evaluation_time:",
    ])
      expect(source).not.toContain(name);
  });
  it("uses the measurement enum on the wire", () => {
    // Arbitrary runtime labels were accepted as measurement units.
    expect(read(`${rust}crates/protocol/src/sync/snapshot.rs`)).toContain(
      "pub unit: MeasurementUnit",
    );
  });
  it("omits the retired failure field and retry text", () => {
    // Retired failure data left retry text with no way to render.
    expect(read(`${rust}src/connected_service/autofix_jobs.rs`)).not.toContain("previous_failure");
    expect(read(`${rust}src/cli/autofix/brief_publish.rs`)).not.toContain(
      "The previous attempt did not resolve this finding.",
    );
  });
  it("checks transitive leaves, numeric arrays, and macro serializers", () => {
    // Nested types, numeric arrays, and macro serializers escaped the privacy check.
    const file = `${rust}src/connected_future.rs`;
    const outside = `${rust}crates/protocol/src/vocab.rs`;
    for (const [body, extra] of [
      [
        "#[derive(Serialize)] struct FutureRequest { data: Hidden }",
        "#[derive(Serialize)] struct Hidden { note: String }",
      ],
      [
        "#[derive(Serialize)] struct FutureRequest { reason: CoverageExceptionReason }",
        "#[derive(Serialize)] enum CoverageExceptionReason { Other(String) }",
      ],
      ["#[derive(Serialize)] struct FutureRequest { bytes: Vec<u8> }", ""],
      ["#[derive(Serialize)] struct FutureRequest { bytes: Vec<Option<u8>> }", ""],
      ["#[derive(Serialize)] struct FutureRequest { bits: [bool; 128] }", ""],
      ["#[derive(Serialize)] struct FutureRequest<'a> { bytes: &'a [u8] }", ""],
      ["#[derive(Serialize)] struct FutureRequest { bytes: Vec<(u8, u8)> }", ""],
      [
        "#[derive(Serialize)] struct FutureRequest { value: CheckId } macro_rules! secret { () => { impl Serialize for $name {} } }",
        "",
      ],
    ]) {
      const sources = {
        [file]: `use ${ENGINE_CRATES[0].replaceAll("-", "_")}::sync::wire::CheckId; ${body} impl WireRequest for FutureRequest {} impl ConnectedServiceClient { fn post() { self.request(); } }`,
        [outside]: extra,
      };
      expect(
        connectedRequestFailures(Object.keys(sources), (p) => sources[p]).length,
        body,
      ).toBeGreaterThan(0);
    }
  });
  it("has no standalone connected request check script", () => {
    // Repository gates invoke the connected request check through the shared entry point.
    expect(existsSync("tools/scripts/check-connected-requests.mjs")).toBe(false);
  });
});

it("rejects shadowed audited leaf names", () => {
  // A familiar leaf name can resolve to a different string-bearing Rust type.
  const wire = `${rust}crates/protocol/src/sync/wire.rs`;
  const file = `${rust}src/future_wire.rs`;
  for (const declaration of [
    "#[derive(Serialize)] struct Digest { note: String }",
    "type Digest = String;",
    "use customer::Secret as Digest;",
  ]) {
    const sources = {
      [wire]: read(wire),
      [file]: `${declaration} #[derive(Serialize)] struct FutureRequest { digest: Digest } impl WireRequest for FutureRequest {}`,
    };
    expect(
      connectedRequestFailures(Object.keys(sources), (p) => sources[p]).length,
    ).toBeGreaterThan(0);
  }
});
