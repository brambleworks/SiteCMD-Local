import { expect, it } from "vitest";
import { entry, failures } from "./lib/capability-manifest-test-fixtures.mjs";

it.each(["impl crate::checks::Check for Http2Check", "impl<'a> Check for Http2Check<'a>"])(
  "reads scope from %s",
  (header) => {
    // A qualified or generic implementation must not silently escape scope comparison.
    const engine = {
      "performance/protocol.rs": `${header} {
    fn id(&self) -> &str { "performance.http2" }
    fn origin_scoped(&self) -> bool { true }
  }`,
    };
    expect(
      failures({ entries: [entry("performance.http2", { scope: "origin" })], engine }),
    ).toEqual([]);
    expect(
      failures({ entries: [entry("performance.http2", { scope: "page" })], engine }).join("\n"),
    ).toContain("origin_scoped=true");
  },
);
