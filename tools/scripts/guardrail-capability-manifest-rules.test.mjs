import { describe, expect, it } from "vitest";
import { capabilityManifestFailures } from "./lib/guardrail-capability-manifest-rules.mjs";

const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const REGISTRY = "apps/desktop/src-tauri/crates/engine/src/manifest/registry/mod.rs";
const DESKTOP = "apps/desktop/src-tauri/src/checks";
const ENGINE = "apps/desktop/src-tauri/crates/engine/src/checks";
const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";

function entry(check, overrides = {}) {
  return {
    check,
    contract: "0000000000000000",
    hosted: "artifact",
    class: "deterministic",
    scope: "page",
    requires: ["page_artifact"],
    compare_on: [],
    ...overrides,
  };
}

function emits(id, extra = "") {
  return `pub fn run() -> CheckResult {\n    CheckResult { check_id: "${id}".into() }\n}\n${extra}`;
}

function repo({ entries = [], runners = [], desktop = {}, engine = {}, session = [] }) {
  const files = {
    [MANIFEST]: JSON.stringify({
      schema_version: 1,
      manifest_digest: "b5fef8de083e1976",
      entries,
    }),
    [REGISTRY]: [
      "pub const RUNNER_IDS: &[(&str, &str)] = &[",
      ...runners.map(([id, why]) => `    (\n        "${id}",\n        "${why}",\n    ),`),
      "];",
    ].join("\n"),
    [SESSION]: [
      "pub const SESSION_CHECK_IDS: &[&str] = &[",
      ...session.map((id) => `    "${id}",`),
      "];",
    ].join("\n"),
  };
  for (const [name, source] of Object.entries(desktop)) files[`${DESKTOP}/${name}`] = source;
  for (const [name, source] of Object.entries(engine)) files[`${ENGINE}/${name}`] = source;

  const read = (file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  };
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
  return [read, listFiles];
}

function failures(fixture) {
  return capabilityManifestFailures(...repo(fixture));
}

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
