import { describe, expect, it } from "vitest";
import { publicationRecordFailures } from "./lib/guardrail-publication-record-rules.mjs";

const MATRIX = "docs/engineering/connected-service/maintained-surfaces.md";
const PUBLICATION_CHECKLIST = "docs/operations/publication-checklist.md";
const HOSTED_SPEC = "docs/engineering/connected-service/hosted-scanner-spec.md";
const PRODUCT = "apps/desktop/PRODUCT.md";
const DEV_SH = "tools/scripts/dev.sh";
const LIB = "tools/scripts/lib/guardrail-example-rules.mjs";

function sources() {
  return {
    [MATRIX]: `# The maintained-surface matrix

## This repository

| Surface | Claims | Must agree with | Disposition | Sign-off |
| ------- | ------ | --------------- | ----------- | -------- |
| \`README.md\` | Privacy posture | \`product-facts.json\` | Sweep | Pending |
| \`CONTRIBUTING.md\` | What is open | Publication decision | Done | Pending |
| \`SECURITY.md\` | The privacy boundary | Trust pages | Done | Pending |
| \`AGENTS.md\` | Shipped entitlement behavior | \`license_constants.json\` | Migration train | Pending |
| \`apps/desktop/PRODUCT.md\` | The paid axis | \`product-facts.json\` | Migration train | Pending |
| \`docs/engineering/connected-service/\` | The connected contract | Each other | Keep | Pending |

## SiteCMD-Web

| Surface | Claims | Must agree with | Disposition | Sign-off |
| ------- | ------ | --------------- | ----------- | -------- |
| \`docs/engineering/publication-decision.md\` | License and scope | Commercial terms | Relocated there 2026-08-09 | Pending |
| \`pricing.astro\` | Prices | \`product-facts.json\` | Rewrite | Pending |
`,
    [HOSTED_SPEC]: `# Hosted scanner

## Scope

Normative contract.
`,
    [PUBLICATION_CHECKLIST]: `# Public repository cutover

Rewrite the existing repository in place.
`,
    "README.md": `# SiteCMD

\`\`\`txt
apps/
  desktop/            Tauri v2 desktop app
  mcp-server/         MCP server package
\`\`\`

Source code stays on the user's machine.

\`\`\`bash
pnpm --filter @sitecmd/desktop run tauri:dev
\`\`\`
`,
    "CONTRIBUTING.md": `# Contributing

- \`apps/desktop/\` - the desktop app.
- \`apps/mcp-server/\` - the MCP server.

Run \`pnpm --filter sitecmd-mcp run test\`.

The source-publication decision record, maintained privately, owns the boundary.
`,
    "SECURITY.md": `# Security Policy

Use [private vulnerability reporting](https://github.com/brambleworks/SiteCMD-Local/security/advisories/new), or email security@sitecmd.com with the key at [.github/security-contact-key.asc](.github/security-contact-key.asc).

The connected service is in scope: its API, hosted scanner, and delivery paths.

Boundaries live at [trust](https://sitecmd.com/trust) and [privacy](https://sitecmd.com/privacy).
`,
    ".github/security-contact-key.asc":
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEbase64\n-----END PGP PUBLIC KEY BLOCK-----\n",
    "AGENTS.md": `# Agent guidance

Free/Core redaction is applied in Rust before payloads reach the frontend.
`,
    [PRODUCT]: `# Product truth

Source code and scan history never leave the machine.
`,
    "apps/desktop/package.json": `{ "name": "@sitecmd/desktop" }`,
    "apps/mcp-server/package.json": `{ "name": "sitecmd-mcp" }`,
    [DEV_SH]: `#!/usr/bin/env bash
APP_PROCESS_PATTERNS=("@tauri-apps/cli/.*/tauri\\\\.js dev")
TARGET_DIR="$REPO_ROOT/apps/desktop/src-tauri/target"
pnpm --filter @sitecmd/desktop run dev
`,
    [LIB]: `// \`pnpm --filter a --filter b run test\` covers each named workspace.
export function exampleFailures() {
  return [];
}
`,
    "docs/README.md": `# Documentation

Business strategy records are maintained privately in the SiteCMD-Web repository.
`,
  };
}

function failures(mutate = () => {}) {
  const files = sources();
  mutate(files);
  const read = (file) => {
    if (!(file in files)) throw new Error(`no fixture for ${file}`);
    return files[file];
  };
  const exists = (file) => file in files;
  const listFiles = (dir, predicate) =>
    Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file));
  return publicationRecordFailures(read, exists, listFiles).join("\n");
}

describe("links into the private strategy records", () => {
  it("passes when every rule holds", () => {
    expect(failures()).toBe("");
  });

  it("fails when a public document links the relocated decision record", () => {
    expect(
      failures((files) => {
        files["docs/README.md"] +=
          "\n- [Source-publication decision](engineering/publication-decision.md)\n";
      }),
    ).toContain("private repository");
  });

  it("fails when a spec links the relocated RFC with an anchor", () => {
    expect(
      failures((files) => {
        files[HOSTED_SPEC] +=
          "\nSee [the architecture](connected-service-rfc.md#sequencing) for order.\n";
      }),
    ).toContain("private repository");
  });

  it("still allows backticked mentions that name a record without linking it", () => {
    expect(
      failures((files) => {
        files["docs/README.md"] +=
          "\nThe record lives at `docs/engineering/publication-decision.md` in SiteCMD-Web.\n";
      }),
    ).toBe("");
  });
});

describe("connected-service specifications", () => {
  it("rejects retained review diaries before the normative contract", () => {
    expect(
      failures((files) => {
        files[HOSTED_SPEC] = files[HOSTED_SPEC].replace(
          "## Scope",
          `${"Amended a forty-ninth time after cross-spec review round.\n".repeat(70)}\n## Scope`,
        );
      }),
    ).toContain("keep revision transcripts in Git");
  });

  it("rejects revision commentary inside an accepted specification", () => {
    expect(
      failures((files) => {
        files[HOSTED_SPEC] += "\nAn earlier revision used a different contract.\n";
      }),
    ).toContain("contains a retained review transcript");
  });
});

describe("the maintained-surface matrix", () => {
  it("fails when the matrix does not exist", () => {
    expect(
      failures((files) => {
        delete files[MATRIX];
      }),
    ).toContain("maintained-surface matrix must exist");
  });

  it("fails when the in-place publication checklist does not exist", () => {
    expect(
      failures((files) => {
        delete files[PUBLICATION_CHECKLIST];
      }),
    ).toContain("public cutover checklist must exist");
  });

  it("fails when a row points at a file that is not there", () => {
    expect(
      failures((files) => {
        files[MATRIX] = files[MATRIX].replace("`README.md`", "`docs/engineering/gone.md`");
      }),
    ).toContain("nothing is there");
  });

  it("does not validate paths in the SiteCMD-Web section against this tree", () => {
    expect(failures()).toBe("");
  });

  it("rejects a live founder-acceptance status in the public matrix", () => {
    expect(
      failures((files) => {
        files[MATRIX] += "\n**Founder acceptance:** Pending explicit review.\n";
      }),
    ).toContain("private release record");
  });

  it("fails when a product document makes a promise without a row", () => {
    expect(
      failures((files) => {
        files[MATRIX] = files[MATRIX].replace(/\| `apps\/desktop\/PRODUCT\.md`.*\n/, "");
      }),
    ).toContain("no row in");
  });

  it("does not flag a product document that only describes mechanism", () => {
    expect(
      failures((files) => {
        files[PRODUCT] = "# Product truth\n\nRedaction is applied in the licensing layer.\n";
        files[MATRIX] = files[MATRIX].replace(/\| `apps\/desktop\/PRODUCT\.md`.*\n/, "");
      }),
    ).toBe("");
  });
});

describe("public network-boundary wording", () => {
  it("rejects claims that every dynamic destination is named", () => {
    expect(
      failures((files) => {
        files["README.md"] += "\nThe Trust page enumerates every outbound call by name.\n";
      }),
    ).toContain("dynamic destinations by class");
  });

  it("accepts a sentence that denies complete enumeration", () => {
    expect(
      failures((files) => {
        files["README.md"] += "\nThe Trust page does not enumerate every outbound call by name.\n";
      }),
    ).not.toContain("dynamic destinations by class");
  });
});

describe("layout maps against the tree", () => {
  it("fails when a map names a workspace that moved out", () => {
    expect(
      failures((files) => {
        files["CONTRIBUTING.md"] += "\n- `apps/sitecmd.com/` - the marketing site.\n";
      }),
    ).toContain("not a workspace in this repository");
  });

  it("fails when a map omits a workspace that is here", () => {
    expect(
      failures((files) => {
        files["README.md"] = files["README.md"].replace(
          "  mcp-server/         MCP server package\n",
          "",
        );
      }),
    ).toContain("must name the `mcp-server` workspace");
  });

  it("fails when a shell entry point starts a workspace that moved out", () => {
    expect(
      failures((files) => {
        files[DEV_SH] += 'LANDING_DIR="$REPO_ROOT/apps/sitecmd.com"\n';
      }),
    ).toContain("not a workspace in this repository");
  });

  it("does not read a scoped dependency path as an app directory", () => {
    expect(failures()).toBe("");
  });
});

describe("workspace filters", () => {
  it("fails when a script filters a package that is not in the workspace", () => {
    expect(
      failures((files) => {
        files[DEV_SH] += "pnpm --filter sitecmd-website run dev\n";
      }),
    ).toContain("fails silently");
  });

  it("fails when documentation tells a reader to filter a missing package", () => {
    expect(
      failures((files) => {
        files["README.md"] += "\n```bash\npnpm --filter sitecmd-website run build\n```\n";
      }),
    ).toContain("fails silently");
  });

  it("ignores a filter that only illustrates the syntax in a comment", () => {
    expect(failures()).toBe("");
  });

  it("ignores a filter whose name comes from a variable", () => {
    expect(
      failures((files) => {
        files[DEV_SH] += 'pnpm --filter "$PACKAGE" run dev\n';
      }),
    ).toBe("");
  });
});

describe("the security policy", () => {
  it("fails when the connected service is not in scope", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] = files["SECURITY.md"].replace(
          "The connected service is in scope: its API, hosted scanner, and delivery paths.",
          "The desktop app is in scope.",
        );
      }),
    ).toContain("connected service is in scope");
  });

  it("fails when it does not point at the trust pages", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] = files["SECURITY.md"].replace("https://sitecmd.com/trust", "#");
      }),
    ).toContain("sitecmd.com/trust");
  });
});

describe("the security intake", () => {
  it("fails when SECURITY.md hedges about private vulnerability reporting", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] +=
          "\nUse GitHub reporting when it is available for this repository.\n";
      }),
    ).toContain("must not hedge");
  });

  it("fails when the contact key is not committed", () => {
    expect(
      failures((files) => {
        delete files[".github/security-contact-key.asc"];
      }),
    ).toContain("security@sitecmd.com and the committed OpenPGP key");
  });

  it("fails when the advisories link is gone", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] = files["SECURITY.md"].replace("/security/advisories/new", "/issues");
      }),
    ).toContain("first channel");
  });
});

describe("the security intake relationships", () => {
  it("fails when the email channel is listed before GitHub reporting", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] = files["SECURITY.md"].replace(
          "Use [private vulnerability reporting](https://github.com/brambleworks/SiteCMD-Local/security/advisories/new), or email security@sitecmd.com",
          "Email security@sitecmd.com, or use [private vulnerability reporting](https://github.com/brambleworks/SiteCMD-Local/security/advisories/new)",
        );
      }),
    ).toContain("before the email channel");
  });

  it("fails when SECURITY.md stops linking the key path", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] = files["SECURITY.md"].replace(
          "[.github/security-contact-key.asc](.github/security-contact-key.asc)",
          "our key",
        );
      }),
    ).toContain("committed OpenPGP key");
  });

  it("fails when the committed key is truncated", () => {
    expect(
      failures((files) => {
        files[".github/security-contact-key.asc"] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
      }),
    ).toContain("armored OpenPGP public key block");
  });

  it("fails on hedge variants, not only the exact sentence", () => {
    expect(
      failures((files) => {
        files["SECURITY.md"] += "\nUse GitHub reporting When Available.\n";
      }),
    ).toContain("must not hedge");
  });
});
