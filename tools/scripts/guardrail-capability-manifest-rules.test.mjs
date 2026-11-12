import { describe, expect, it } from "vitest";
import { capabilityManifestFailures } from "./lib/guardrail-capability-manifest-rules.mjs";

import {
  MANIFEST,
  entry,
  emits,
  repo,
  failures,
} from "./lib/capability-manifest-test-fixtures.mjs";

describe("completeness", () => {
  it("passes when every emitted id has a row", () => {
    expect(
      failures({
        entries: [entry("seo.title")],
        engine: { "seo/meta.rs": emits("seo.title") },
      }),
    ).toEqual([]);
  });

  it("fails when a check ships without a manifest entry", () => {
    const found = failures({
      entries: [entry("seo.title")],
      engine: { "seo/meta.rs": emits("seo.title"), "seo/new.rs": emits("seo.invented") },
    });
    expect(found.join("\n")).toContain("seo.invented");
    expect(found.join("\n")).toContain("no capability-manifest entry");
  });

  it("sees a check declared below a test module whose body is another file", () => {
    const hidden = {
      "seo/meta.rs": emits("seo.title"),
      "seo/structured_data/mod.rs": `#[cfg(test)]\nmod tests;\nmod validate;\n\n${emits("seo.structured_data")}`,
    };
    const found = failures({ entries: [entry("seo.title")], engine: hidden });
    expect(found.join("\n")).toContain("seo.structured_data");
    expect(found.join("\n")).toContain("no capability-manifest entry");
    expect(
      failures({ entries: [entry("seo.title"), entry("seo.structured_data")], engine: hidden }),
    ).toEqual([]);
  });

  it("accepts a declared runner id without a row", () => {
    expect(
      failures({
        entries: [entry("security.headers.csp")],
        runners: [["security.headers", "emits security.headers.{csp}"]],
        engine: {
          "security/headers.rs": `fn id(&self) -> &str {\n        "security.headers"\n    }\n${emits("security.headers.csp")}`,
        },
      }),
    ).toEqual([]);
  });

  it("counts the cross-page analyzer's ids as emitted", () => {
    expect(
      failures({
        entries: [
          entry("seo.title"),
          entry("seo.orphan_pages", { scope: "session", hosted: "artifact" }),
        ],
        engine: { "seo/meta.rs": emits("seo.title") },
        session: ["seo.orphan_pages"],
      }),
    ).toEqual([]);
  });

  it("fails when a cross-page id has no row", () => {
    const found = failures({
      entries: [entry("seo.title")],
      engine: { "seo/meta.rs": emits("seo.title") },
      session: ["seo.orphan_pages"],
    });
    expect(found.join("\n")).toContain("seo.orphan_pages");
    expect(found.join("\n")).toContain("no capability-manifest entry");
  });

  it("fails when a row names an id nothing emits any more", () => {
    const found = failures({
      entries: [entry("seo.title"), entry("seo.retired")],
      engine: { "seo/meta.rs": emits("seo.title") },
    });
    expect(found.join("\n")).toContain("seo.retired");
  });

  it("fails when a family is keyed by a prefix no constant declares", () => {
    const found = failures({
      entries: [entry("accessibility.axe.", { family: true, hosted: "browser" })],
      engine: { "accessibility/axe.rs": 'pub const OTHER_PREFIX: &str = "accessibility.other.";' },
    });
    expect(found.join("\n")).toContain("does not match any CHECK_ID_PREFIX");
  });

  it("accepts a family whose prefix constant exists", () => {
    expect(
      failures({
        entries: [entry("accessibility.axe.", { family: true, hosted: "browser" })],
        engine: {
          "accessibility/axe.rs": 'pub const CHECK_ID_PREFIX: &str = "accessibility.axe.";',
        },
      }),
    ).toEqual([]);
  });
});

describe("lane truth", () => {
  it("rejects unsupported HTTP/2 now that the engine grades an observed protocol", () => {
    // An obsolete exception would silently discard an emitted hosted check.
    const id = "performance.http2";
    expect(
      failures({
        entries: [
          entry(id, { hosted: "unsupported", requires: [], compare_on: ["transport_profile"] }),
        ],
        engine: { "performance/protocol.rs": emits(id) },
      }).join("\n"),
    ).toContain("marked unsupported");
  });

  it("still rejects another emitted performance check marked unsupported", () => {
    const id = "performance.cache";
    const found = failures({
      entries: [entry(id, { hosted: "unsupported", requires: [] })],
      engine: { "performance/cache.rs": emits(id) },
    });
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("marked unsupported");
    expect(found[0]).toContain(id);
  });

  it("exempts an unsupported id only when every source is under predeploy", () => {
    const id = "config.localhost_refs";
    const entries = [entry(id, { hosted: "unsupported", requires: [] })];
    const predeploy = { "predeploy/mod.rs": emits(id) };
    expect(failures({ entries, engine: predeploy })).toEqual([]);
    for (const engine of [
      { "config/refs.rs": emits(id) },
      { ...predeploy, "config/refs.rs": emits(id) },
      { "predeploy_extra/mod.rs": emits(id) },
    ]) {
      expect(failures({ entries, engine }).join("\n")).toContain("marked unsupported");
    }
    expect(
      failures({ entries, engine: predeploy, desktop: { "predeploy/mod.rs": emits(id) } }).join(
        "\n",
      ),
    ).toContain("marked unsupported");
  });

  it("backs a session check's hosted lane only while the engine declares it", () => {
    const fixture = {
      entries: [entry("seo.orphan_pages", { scope: "session" })],
      desktop: { "seo/session.rs": emits("seo.orphan_pages") },
      session: ["seo.orphan_pages"],
    };
    expect(failures(fixture)).toEqual([]);
    expect(failures({ ...fixture, session: [] }).join("\n")).toContain("claims artifact");
  });

  it("fails when a desktop-only check claims a hosted lane", () => {
    const found = failures({
      entries: [entry("seo.title", { hosted: "artifact" })],
      desktop: { "seo/meta.rs": emits("seo.title") },
    });
    expect(found.join("\n")).toContain("claims artifact");
  });

  it("accepts unsupported for a check the engine does not own", () => {
    expect(
      failures({
        entries: [entry("seo.title", { hosted: "unsupported", requires: [] })],
        desktop: { "seo/meta.rs": emits("seo.title") },
      }),
    ).toEqual([]);
  });

  it("fails when an engine check is marked unsupported", () => {
    const found = failures({
      entries: [entry("seo.title", { hosted: "unsupported" })],
      engine: { "seo/meta.rs": emits("seo.title") },
    });
    expect(found.join("\n")).toContain("marked unsupported");
  });
});

describe("scope agreement", () => {
  it("reports an unreadable constant-returning check id", () => {
    // A non-literal id must not silently remove a check from scope comparison.
    const engine = {
      "performance/protocol.rs": `const CHECK_ID: &str = "performance.http2";
      impl Check for Http2Check {
        fn origin_scoped(&self) -> bool { true }
        fn id(&self) -> &str { CHECK_ID }
      }`,
    };
    const entries = [entry("performance.http2", { scope: "page" })];
    expect(failures({ entries, engine }).join("\n")).toContain("cannot read check id");
  });

  it("reports a check implementation without a closing brace", () => {
    // A block whose end cannot be found must not be treated as fully inspected.
    const engine = {
      "performance/protocol.rs": `impl Check for Http2Check {
      fn id(&self) -> &str { "performance.http2" }
      fn origin_scoped(&self) -> bool { true }
    `,
    };
    const entries = [entry("performance.http2", { scope: "origin" })];
    expect(failures({ entries, engine }).join("\n")).toContain("cannot bound Check implementation");
  });

  it("reads scope past impl words and braces in documentation", () => {
    // An impl word or brace inside a comment must not cut the implementation short.
    const engine = {
      "performance/protocol.rs": `impl Check for Http2Check {
      /// This impl grades a protocol, even when this comment contains }.
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
  });

  it("rejects an origin row when Http2Check inherits page scope", () => {
    // Removing the override must not leave an origin row backed by a page check.
    const engine = {
      "performance/protocol.rs": `impl Check for Http2Check {
      fn id(&self) -> &str { "performance.http2" }
      fn run(&self, ctx: &PageContext) -> Vec<CheckResult> { vec![] }
    }`,
    };
    const entries = [entry("performance.http2", { scope: "origin" })];
    expect(failures({ entries, engine }).join("\n")).toContain("origin_scoped=false");
  });

  it.each([true, false])(
    "compares the engine's HTTP/2 origin declaration %s with its row",
    (origin) => {
      // Reading only desktop adapters misses the synchronous engine check's scope.
      const engine = {
        "performance/protocol.rs": `impl Check for Http2Check {
      fn origin_scoped(&self) -> bool { ${origin} }
      fn id(&self) -> &str { "performance.http2" }
    }`,
      };
      const matching = entry("performance.http2", { scope: origin ? "origin" : "page" });
      expect(failures({ entries: [matching], engine })).toEqual([]);
      const mismatch = { ...matching, scope: origin ? "page" : "origin" };
      expect(failures({ entries: [mismatch], engine }).join("\n")).toContain(
        `origin_scoped=${origin}`,
      );
    },
  );

  const originCheck = (id) =>
    `fn origin_scoped(&self) -> bool {\n        true\n    }\n    fn id(&self) -> &str {\n        "${id}"\n    }\n`;

  it("fails when the desktop runs a check once per origin and the manifest calls it page-scoped", () => {
    const found = failures({
      entries: [entry("seo.robots_txt", { hosted: "unsupported" })],
      desktop: { "seo/robots.rs": originCheck("seo.robots_txt") },
    });
    expect(found.join("\n")).toContain("origin_scoped=true");
  });

  it("passes when both say origin", () => {
    expect(
      failures({
        entries: [entry("seo.robots_txt", { hosted: "unsupported", scope: "origin" })],
        desktop: { "seo/robots.rs": originCheck("seo.robots_txt") },
      }),
    ).toEqual([]);
  });
});

describe("clock honesty", () => {
  const expiryCheck = (id) =>
    `pub fn evaluate(now: DateTime<Utc>) -> CheckResult {\n    let _ = evaluation_time;\n    CheckResult { check_id: "${id}".into() }\n}`;

  it("fails when a verdict reads evaluation_time and nothing it emits is clock-dependent", () => {
    const found = failures({
      entries: [entry("security.ssl.expiry")],
      engine: { "security/tls.rs": expiryCheck("security.ssl.expiry") },
    });
    expect(found.join("\n")).toContain("clock_dependent");
  });

  it("passes once one of the file's checks is classed clock-dependent", () => {
    expect(
      failures({
        entries: [
          entry("security.ssl.expiry", { class: "clock_dependent" }),
          entry("security.ssl.hostname"),
        ],
        engine: {
          "security/tls.rs": `${expiryCheck("security.ssl.expiry")}\n${emits("security.ssl.hostname")}`,
        },
      }),
    ).toEqual([]);
  });

  it("ignores an evaluation_time that only appears in test fixtures", () => {
    expect(
      failures({
        entries: [entry("seo.title")],
        engine: {
          "seo/meta.rs": `${emits("seo.title")}\n#[cfg(test)]\nmod tests {\n    let evaluation_time = now();\n}`,
        },
      }),
    ).toEqual([]);
  });
});

describe("the published document", () => {
  it("fails when the manifest is missing", () => {
    const found = capabilityManifestFailures(
      () => {
        throw new Error("ENOENT");
      },
      () => [],
    );
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("regenerate");
  });

  it("fails when the manifest carries no digest", () => {
    const [read, listFiles] = repo({ entries: [entry("seo.title")] });
    const stripped = (file) =>
      file === MANIFEST
        ? JSON.stringify({ schema_version: 1, entries: [entry("seo.title")] })
        : read(file);
    expect(capabilityManifestFailures(stripped, listFiles).join("\n")).toContain("manifest_digest");
  });
});

describe("polish signals", () => {
  const table = [
    "pub const POLISH_SIGNALS: &[PolishSignal] = &[",
    "    PolishSignal {",
    '        id: "missing-lang",',
    "        reads_stylesheets: false,",
    "        run: html_quality::missing_lang,",
    "    },",
    "];",
  ].join("\n");
  const row = entry("polish.missing-lang");

  it("reads the engine table's signals as emitted engine ids", () => {
    expect(failures({ entries: [row], engine: { "polish/mod.rs": table } })).toEqual([]);
  });

  it("flags a polish row whose signal the table no longer lists", () => {
    const found = failures({ entries: [row], engine: { "polish/mod.rs": "" } }).join("\n");
    expect(found).toContain("no check tree emits");
    expect(found).toContain("polish.missing-lang");
  });

  it("flags a hosted polish row whose signal table sits outside the engine", () => {
    const found = failures({ entries: [row], desktop: { "polish/mod.rs": table } }).join("\n");
    expect(found).toContain("outside the engine crate");
    expect(found).toContain("polish.missing-lang");
  });

  it("flags a signal with no row", () => {
    const found = failures({
      entries: [entry("seo.title")],
      engine: { "seo/meta.rs": emits("seo.title"), "polish/mod.rs": table },
    }).join("\n");
    expect(found).toContain("no capability-manifest entry");
    expect(found).toContain("polish.missing-lang");
  });
});
