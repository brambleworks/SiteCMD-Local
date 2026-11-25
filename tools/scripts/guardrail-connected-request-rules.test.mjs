// Fix-job result summaries leaked arbitrary CI tool output to SiteCMD.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { repoGuardrailIo } from "./check-repo-guardrails.mjs";
import { connectedServicePayloadFailures } from "./lib/guardrail-sync-payload-rules.mjs";
import { connectedRequestFailures } from "./lib/guardrail-connected-request-rules.mjs";
import { publicRustSources } from "./lib/guardrail-protocol-contents-rules.mjs";
const read = (file) => readFileSync(file, "utf8");
describe("connected request privacy", () => {
  it("rejects every unconstrained string on all discovered request types", () => {
    expect(
      connectedRequestFailures(publicRustSources(repoGuardrailIo(process.cwd()).listFiles), read),
    ).toEqual([]);
  });
  it("runs in the repository gate and catches a reintroduced result summary", () => {
    const io = repoGuardrailIo(process.cwd());
    const originalRead = io.read;
    io.read = (file) => {
      const source = originalRead(file);
      return file.endsWith("connected_service/autofix_jobs.rs")
        ? source.replace(
            "pub struct ResultReport {",
            "pub struct ResultReport {\n    pub summary: String,",
          )
        : source;
    };
    // The gate's own entry point, not the whole repository gate: that ran
    // every guardrail and took most of CI's five seconds.
    expect(connectedServicePayloadFailures(io.read, io.exists, io.listFiles).join("\n")).toContain(
      "ResultReport.summary",
    );
    expect(read("tools/scripts/check-repo-guardrails.mjs")).toContain(
      "connectedServicePayloadFailures(read, exists, listFiles)",
    );
  });

  it("discovers new requests and nested enum fields without a type allowlist", () => {
    const file = "apps/desktop/src-tauri/src/connected_future.rs";
    for (const source of [
      "#[derive(Serialize)] struct NewRequest { summary: String }",
      "#[derive(Serialize)] struct NewRequest { summary: OutcomeCode }",
      "#[derive(Serialize)] enum NewRequest { Blocked { reason: Option<String> } }",
      "#[derive(Serialize)] struct NewRequest<'a> { text: &'a str }",
      "#[derive(Serialize)] struct NewRequest { text: serde_json::Value }",
      "#[derive(Serialize)] struct NewRequest { text: UnknownWrapper }",
      "#[derive(Serialize)] enum NewRequest { Message(String) }",
      "#[derive(Serialize)] enum NewRequest { Message(UnknownWrapper) }",
      "#[derive(Serialize)] struct NewRequest(String);",
    ])
      expect(
        connectedRequestFailures([file], () => `${source} impl WireRequest for NewRequest {}`)
          .length,
      ).toBeGreaterThan(0);
  });
});
