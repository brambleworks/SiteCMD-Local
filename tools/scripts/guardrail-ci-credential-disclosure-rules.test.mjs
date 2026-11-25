import { describe, expect, it } from "vitest";

import { ciCredentialDisclosureFailures } from "./lib/guardrail-ci-credential-disclosure-rules.mjs";

const ACTION = ".github/actions/sitecmd-gate/action.yml";

const ACTION_BASE = [
  "inputs:",
  "  connection-export:",
  "    description: The encrypted connection export.",
  "  ci-token:",
  "    description: >-",
  "      The CI token minted for this site in SiteCMD. Bound to one site,",
  "      it can read only the deployment-ordering cursor, run this gate, notify",
  "      deployments, and submit code evidence. It cannot read findings,",
  "      lifecycle state, or account data. This action uses it for the gate alone.",
  "    required: true",
  "  threshold:",
  "    description: The least severe NEW finding that fails the build.",
].join("\n");

function run(overrides = {}) {
  const fixture = { [ACTION]: ACTION_BASE, ...overrides };
  return ciCredentialDisclosureFailures((file) => fixture[file] ?? "");
}

describe("ciCredentialDisclosureFailures", () => {
  it("accepts surfaces that name all four operations and the read boundary", () => {
    // A complete CI token description can be rejected.
    expect(run()).toEqual([]);
  });

  it("rejects an action description that drops deployment notification", () => {
    // The CI token description can omit deployment notification.
    const failures = run({
      [ACTION]: ACTION_BASE.replace("notify", "mention"),
    });
    expect(failures.some((failure) => failure.includes("deployment notification"))).toBe(true);
  });

  it("rejects an action description that drops the evidence door", () => {
    // The CI token description can omit code evidence submission.
    const failures = run({
      [ACTION]: ACTION_BASE.replace("and submit code evidence.", ""),
    });
    expect(failures.some((failure) => failure.includes("code evidence submission"))).toBe(true);
  });

  it("rejects an action that no longer declares the ci-token input", () => {
    // An action can lose the ci-token input and go unreported.
    const failures = run({
      [ACTION]: ACTION_BASE.replace("  ci-token:", "  runner-token:"),
    });
    expect(failures.some((failure) => failure.includes("no longer declares"))).toBe(true);
  });

  it("rejects an action that drops the deployment cursor read", () => {
    // The CI token description can omit the deployment-ordering cursor read.
    const failures = run({
      [ACTION]: ACTION_BASE.replace("read only the deployment-ordering cursor, ", ""),
    });
    expect(failures.some((failure) => failure.includes("deployment-ordering cursor"))).toBe(true);
  });

  it("rejects an action description that drops the gate operation", () => {
    // A CI token description can omit that the token runs the gate.
    const failures = run({
      [ACTION]: ACTION_BASE.replace("run this gate, ", "").replace(" for the gate alone", ""),
    });
    expect(failures.some((failure) => failure.includes("the gate"))).toBe(true);
  });

  it("rejects an action description that drops the findings read boundary", () => {
    // A CI token description can omit that the token cannot read findings.
    const failures = run({
      [ACTION]: ACTION_BASE.replace("cannot read findings,", "cannot read"),
    });
    expect(failures.some((failure) => failure.includes("the findings read boundary"))).toBe(true);
  });
});
