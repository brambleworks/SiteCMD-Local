import { describe, expect, it } from "vitest";
import { connectedSetupFailures } from "./lib/guardrail-connected-setup-rules.mjs";
describe("desktop setup retirement", () => {
  it("permits only the live state reader", () => {
    // I1/M1: dashboard setup is unavailable to a desktop credential.
    expect(connectedSetupFailures(() => "pub async fn state() {}").length).toBe(0);
  });
  it("rejects each retired setup or write method", () => {
    // I1/M1: removed request doors must not reappear under another body type.
    for (const name of [
      "create_connected_site",
      "create_site",
      "delete_site",
      "erase_site",
      "verify_site",
      "mint_ci_token",
      "put_scope",
      "mutate_group",
    ]) {
      expect(connectedSetupFailures(() => `pub async fn ${name}() {}`).join("\n")).toContain(name);
    }
  });
});
