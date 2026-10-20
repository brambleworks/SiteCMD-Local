import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { publicFaceFailures } from "./lib/guardrail-public-face-rules.mjs";
import { ROOT, realRead } from "./guardrail-test-support.mjs";

const DOCS_INDEX = "docs/README.md";
const CONTRIBUTING = "CONTRIBUTING.md";
const CONNECTED_SPECS = "docs/engineering/connected-service";
const PRODUCT_DOCS = "docs/product";
const LOCALHOST_FIXTURES = "apps/desktop/src-tauri/src/core/localhost.rs";
const PROTOCOL_SPEC = `${CONNECTED_SPECS}/connected-protocol-spec.md`;
const README = "README.md";
const PRODUCT_FACTS = "product-facts.json";

function realFiles() {
  const files = {
    [DOCS_INDEX]: realRead(DOCS_INDEX),
    [CONTRIBUTING]: realRead(CONTRIBUTING),
    [LOCALHOST_FIXTURES]: realRead(LOCALHOST_FIXTURES),
    [README]: realRead(README),
    [PRODUCT_FACTS]: realRead(PRODUCT_FACTS),
  };
  for (const name of fs.readdirSync(path.join(ROOT, CONNECTED_SPECS))) {
    if (name.endsWith(".md"))
      files[`${CONNECTED_SPECS}/${name}`] = realRead(`${CONNECTED_SPECS}/${name}`);
  }
  for (const name of fs.readdirSync(path.join(ROOT, PRODUCT_DOCS))) {
    if (name.endsWith(".md"))
      files[`${PRODUCT_DOCS}/${name}`] = realRead(`${PRODUCT_DOCS}/${name}`);
  }
  return files;
}

function run(mutate = () => {}) {
  const files = realFiles();
  mutate(files);
  const read = (file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  };
  const exists = (file) => file in files;
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
  return publicFaceFailures(read, exists, listFiles).join("\n");
}

describe("publicFaceFailures", () => {
  it("passes the real repository", () => {
    expect(run()).toBe("");
  });

  it("catches a spec that returns to the nonce allocator envelope", () => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] +=
          "\nStored as `{envelope_version, algorithm, kid, nonce, ciphertext}` under MAX_ENCRYPTIONS_PER_KID.\n";
      }),
    ).toContain("specifies a retired Connect crypto contract");
  });

  it("catches a delivery spec that adopts the desktop's body-only signature again", () => {
    expect(
      run((files) => {
        files["docs/engineering/connected-service/alert-delivery-spec.md"] +=
          "\nSignatures are the desktop's exact format (`sha256=` lowercase hex over the raw body).\n";
      }),
    ).toContain("specifies a retired Connect crypto contract");
  });

  it("catches a spec that signs outgoing webhooks with the body-only HMAC again", () => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] +=
          "\nThe signature is the desktop's existing `sha256=` lowercase-hex HMAC contract.\n";
      }),
    ).toContain("specifies a retired Connect crypto contract");
  });

  it.each([
    "/v1/provider-connections",
    "/v1/hooks/vercel",
    "/v1/hooks/netlify",
    "/callbacks/{provider}",
    "/callbacks/vercel",
    "/callbacks/netlify",
    "project_already_claimed",
    "provider_connection",
    "provider connection",
    "provider-connection",
    "provider\nconnections",
    "provider-attested",
    "provider attestation",
    "provider door",
    "provider hooks",
    "provider webhook",
    "provider projects",
    "provider credential",
    "provider authority",
    "provider ordering",
    "provider authorization",
    "provider's authorization code",
    "provider OAuth",
    "the provider's OAuth flow",
    "OAuth authorization for the provider",
    "OAuth authorization\nfor the provider",
    "provider and generic deploy hooks",
    "promotion event",
    "promotion sequence",
    "provider_connection_id",
    "the provider's connection_id",
    "connection_id for the provider",
    "external_project_id",
    "webhook reprovisioning",
    "reprovision the provider webhook",
    "`promotion`",
    '"kind": "provider"',
    "Vercel deploy door",
    "Vercel's webhook",
    "callback for Netlify",
  ])("rejects a spec line containing %s", (contract) => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] += `\nThe protocol uses ${contract}.\n`;
      }),
    ).toContain("specifies a retired Connect provider contract");
  });

  it.each(
    ["Vercel", "Netlify"].flatMap((host) =>
      [
        "door",
        "hook",
        "webhook",
        "connection",
        "credential",
        "OAuth",
        "callback",
        "promotion",
        "publish event",
        "authority",
        "ordering",
      ].flatMap((term) => [`${host} ${term}`, `${term} ${host}`]),
    ),
  )("rejects a deployment host in the retired context %s", (contract) => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] += `\nThe protocol uses ${contract}.\n`;
      }),
    ).toContain("specifies a retired Connect provider contract");
  });

  it.each([
    "Reprovision CI after fingerprint-key rotation.",
    "Vercel and Netlify identify hosts.",
    "An OAuth delegation flow validates a single-use state at /callbacks/google.",
    "An OAuth callback validates its single-use state before exchanging the authorization code.",
    "A database connection_id identifies a local database session.",
    "A provider record uses a revision. A database connection_id identifies its session.",
    "A provider record uses a revision. An OAuth callback at /callbacks/google validates state.",
    "The OAuth provider redirects to /callbacks/google with a single-use state.",
    "An identity provider runs the OAuth flow, and its connection_id names the grant.",
  ])("allows the kept description %s", (description) => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] += `\n${description}\n`;
      }),
    ).toBe("");
  });

  it("allows the host-project routes and their deployment host identifiers", () => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] +=
          "\nGET and PUT `/v1/sites/{site}/host-project` read and write host-project bindings: " +
          '`host: "vercel"` names `project_id` and `project_name`, ' +
          'and `host: "netlify"` names `netlify_site_id`.\n';
      }),
    ).toBe("");
  });

  it("rejects a restored provider connection sentence", () => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] +=
          "\nVercel and Netlify are connected through a first-class\n`provider_connection` resource.\n";
      }),
    ).toContain("specifies a retired Connect provider contract");
  });

  it("allows verified-good baseline promotion", () => {
    expect(
      run((files) => {
        files[`${CONNECTED_SPECS}/hosted-scanner-spec.md`] +=
          "\nVerified-good promotion requires a complete, clean observation.\n";
      }),
    ).toBe("");
  });

  it("restricts the provider contract rule to implementation specifications", () => {
    expect(
      run((files) => {
        files[`${CONNECTED_SPECS}/maintained-surfaces.md`] += "\nprovider_connection\n";
      }),
    ).toBe("");
  });

  // docs/product/get-value-in-5-minutes.md still reads as product intent ("SiteCMD
  // should ...") today; the rule module excludes it until the desktop-repo-public-face
  // plan's Task 8 rewrites the walkthrough. Prove the exclusion is narrow: the intent
  // check still fires for every other product doc.
  it("still catches product intent in a doc other than the pending walkthrough", () => {
    expect(
      run((files) => {
        files["docs/product/fix-your-first-issue.md"] += "\nSiteCMD should do this.\n";
      }),
    ).toContain("reads as product intent");
  });

  it("rejects a docs index that still lists the executed cutover as an entry point", () => {
    expect(
      run((files) => {
        files[DOCS_INDEX] = files[DOCS_INDEX].replace(/ \(historical:[^)]*\)/, "");
      }),
    ).toContain("historical");
  });

  it("rejects public docs that call the committed connected specs private", () => {
    expect(
      run((files) => {
        files[CONTRIBUTING] = "Connected-service internals live in SiteCMD-Web.\n";
      }),
    ).toContain("docs/engineering/connected-service/");
  });

  it("rejects a spec that defers to the private commercial record", () => {
    expect(
      run((files) => {
        files[PROTOCOL_SPEC] +=
          "\nThe billable unit (commercial terms spec) is the connected production site.\n";
      }),
    ).toContain("defers to a private record");
  });

  it("rejects a real third-party domain in the environment fixtures", () => {
    expect(
      run((files) => {
        files[LOCALHOST_FIXTURES] += '("https://upstage.ai", "production"),\n';
      }),
    ).toContain("real third-party domain");
  });

  it("rejects a README check count that drifted from the generated facts", () => {
    expect(
      run((files) => {
        files[README] = files[README].replace(
          /^\| Web Scan(\s+)\|(\s+)157 \|/m,
          "| Web Scan$1|$2 99 |",
        );
      }),
    ).toContain("Run pnpm facts:generate");
  });

  it("rejects a README that dropped a check-count row entirely", () => {
    expect(
      run((files) => {
        files[README] = files[README].replace(/^\| Code Scan .*\n/m, "");
      }),
    ).toContain('must keep a "Code Scan" row');
  });

  it("rejects a dependency-ecosystem count the generated facts do not support", () => {
    expect(
      run((files) => {
        files[README] = files[README].replace(
          "across 8 package ecosystems",
          "across 40 package ecosystems",
        );
      }),
    ).toContain("package ecosystems");
  });

  it("rejects a real tunnelling host the message already claimed to cover", () => {
    expect(
      run((files) => {
        files[LOCALHOST_FIXTURES] += '("https://localhost.run", "production"),\n';
      }),
    ).toContain("real third-party domain");
  });
});
