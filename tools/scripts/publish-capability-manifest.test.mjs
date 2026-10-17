import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  classifyPublishResponse,
  manifestDigestOf,
  publishCapabilityManifest,
} from "./publish-capability-manifest.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MANIFEST_FILE = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";

const DIGEST = "ad51493a86e8be14";
const DOCUMENT = JSON.stringify({
  entries: [{ check: "security.dns.spf", contract: "0123456789abcdef" }],
  manifest_digest: DIGEST,
  schema_version: 1,
});

const OIDC_ENDPOINT = "https://token.actions.githubusercontent.com/?api-version=2.0";
const REQUEST_TOKEN = "actions-request-token-secret";
const MINTED_TOKEN = "minted-oidc-token-secret";
const ENV = {
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
  ACTIONS_ID_TOKEN_REQUEST_URL: OIDC_ENDPOINT,
};

const REQUEST_ID = "req_0123456789abcdef";
const TITLES = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  409: "Conflict",
};

// A refusal the way Connect answers one: RFC 9457 problem details.
function problem(status, code, detail = "The registry refused this request.") {
  return {
    code,
    detail,
    request_id: REQUEST_ID,
    status,
    title: TITLES[status],
    type: "about:blank",
  };
}

// Stub OIDC and registry responses while recording requests.
function stubPort(answers, mint = { status: 200, value: MINTED_TOKEN }) {
  const puts = [];
  const port = async (url, init = {}) => {
    if (url.startsWith(OIDC_ENDPOINT)) {
      return {
        json: async () => ({ value: mint.value }),
        ok: mint.status < 400,
        status: mint.status,
      };
    }
    puts.push({ init, url });
    const answer = answers.shift();
    if (!answer) throw new Error("stub port ran out of registry answers");
    if (answer.networkError) throw new Error(answer.networkError);
    return {
      json: async () => {
        if (answer.unparseable) throw new Error("not json");
        return answer.body ?? null;
      },
      ok: answer.status < 400,
      status: answer.status,
    };
  };
  return { port, puts };
}

function publish(answers, overrides = {}) {
  const { port, puts } = stubPort(answers, overrides.mint);
  return publishCapabilityManifest({
    body: Buffer.from(overrides.document ?? DOCUMENT, "utf8"),
    engineRelease: overrides.engineRelease ?? "1.5.4",
    env: overrides.env ?? ENV,
    fetch: port,
    sleep: async () => {},
  }).then((result) => ({ ...result, puts }));
}

describe("the capability manifest reaches the registry before anything ships under it", () => {
  it("registers a manifest the registry has never seen", async () => {
    const result = await publish([
      { body: { entries: 153, manifest_digest: DIGEST, status: "registered" }, status: 201 },
    ]);
    expect(result.ok).toBe(true);
    expect(result.message).toContain("registered");
    expect(result.message).toContain("153 entries");
  });

  it("succeeds when the digest is already registered with the same bytes", async () => {
    const result = await publish([
      {
        body: { entries: 153, manifest_digest: DIGEST, status: "already_registered" },
        status: 200,
      },
    ]);
    expect(result.ok).toBe(true);
    expect(result.message).toContain("already_registered");
  });

  it("sends the document bytes to the digest the document declares", async () => {
    const result = await publish([
      { body: { entries: 1, manifest_digest: DIGEST, status: "registered" }, status: 201 },
    ]);
    expect(result.puts[0].url).toBe(`https://connect.sitecmd.com/v1/engine-manifests/${DIGEST}`);
    expect(result.puts[0].init.method).toBe("PUT");
    expect(result.puts[0].init.headers["x-sitecmd-engine-release"]).toBe("1.5.4");
  });

  it("refuses to publish a document with no usable digest", async () => {
    const result = await publish([], { document: JSON.stringify({ schema_version: 1 }) });
    expect(result.ok).toBe(false);
    expect(result.message).toContain("manifest_digest");
    expect(result.puts).toHaveLength(0);
  });

  it("fails without ever retrying when the digest is registered with different bytes", async () => {
    const result = await publish([
      { body: problem(409, "already_registered_with_different_content"), status: 409 },
    ]);
    expect(result.ok).toBe(false);
    expect(result.puts).toHaveLength(1);
    expect(result.message).toContain("immutable by design");
    expect(result.message).not.toMatch(/overwrit(e|ing) (it|the entry) (and|to)/i);
  });

  it("fails rather than passing when the registry door is unconfigured", async () => {
    const result = await publish([{ body: problem(404, "not_found"), status: 404 }]);
    expect(result.ok).toBe(false);
    expect(result.message).toContain("not a no-op");
  });

  it("names the 400 the registry actually returned", async () => {
    const result = await publish([{ body: problem(400, "engine_release_required"), status: 400 }]);
    expect(result.ok).toBe(false);
    expect(result.message).toContain("x-sitecmd-engine-release");
  });

  it("retries a 5xx and succeeds on a later attempt", async () => {
    const result = await publish([
      { status: 503 },
      { body: { entries: 153, manifest_digest: DIGEST, status: "registered" }, status: 201 },
    ]);
    expect(result.ok).toBe(true);
    expect(result.puts).toHaveLength(2);
  });

  it("retries a network error and gives up after three attempts", async () => {
    const result = await publish([
      { networkError: "ECONNRESET" },
      { networkError: "ECONNRESET" },
      { networkError: "ECONNRESET" },
    ]);
    expect(result.ok).toBe(false);
    expect(result.puts).toHaveLength(3);
    expect(result.message).toContain("3 attempts");
  });

  it("never repeats a request the registry has already judged", async () => {
    const result = await publish([{ body: problem(400, "malformed_manifest"), status: 400 }]);
    expect(result.puts).toHaveLength(1);
  });

  it("stops when the job cannot mint an identity", async () => {
    const result = await publish([], { env: {} });
    expect(result.ok).toBe(false);
    expect(result.message).toContain("id-token: write");
  });

  it("keeps every credential out of the reported message", async () => {
    const refused = await publish([{ body: problem(401, "unauthorized"), status: 401 }]);
    const mintFailed = await publish([], { mint: { status: 403, value: MINTED_TOKEN } });
    for (const message of [refused.message, mintFailed.message]) {
      expect(message).not.toContain(MINTED_TOKEN);
      expect(message).not.toContain(REQUEST_TOKEN);
    }
  });

  it("keeps the status when the body will not parse", async () => {
    const result = await publish([
      { status: 500, unparseable: true },
      { body: { entries: 153, manifest_digest: DIGEST, status: "registered" }, status: 201 },
    ]);
    expect(result.ok).toBe(true);
  });

  it("refuses a 2xx that is not the registry's own answer", async () => {
    const notTheRegistry = await publish([{ body: "<html>hello</html>", status: 200 }]);
    expect(notTheRegistry.ok).toBe(false);
    expect(notTheRegistry.message).toContain("did not come from the manifest registry");
  });

  it("refuses a 2xx that echoes a digest other than the one published", async () => {
    const result = await publish([
      {
        body: { entries: 153, manifest_digest: "0123456789abcdef", status: "registered" },
        status: 201,
      },
    ]);
    expect(result.ok).toBe(false);
    expect(result.message).toContain("did not come from the manifest registry");
  });

  it("reads the digest of the artifact this repository actually ships", async () => {
    const document = manifestDigestOf(fs.readFileSync(path.join(ROOT, MANIFEST_FILE), "utf8"));
    expect(document.ok).toBe(true);
  });

  it("names a problem refusal's code, detail and request id", () => {
    const verdict = classifyPublishResponse({
      body: problem(
        409,
        "already_registered_with_different_content",
        "This digest already names other bytes.",
      ),
      digest: DIGEST,
      status: 409,
    });
    expect(verdict.outcome).toBe("refused");
    expect(verdict.message).toContain("409 already_registered_with_different_content");
    expect(verdict.message).toContain("This digest already names other bytes.");
    expect(verdict.message).toContain(`[${REQUEST_ID}]`);
  });

  it("names the provenance reason a rejected identity carries", () => {
    for (const reason of ["ref_mismatch", "workflow_ref_mismatch", "repository_mismatch"]) {
      const verdict = classifyPublishResponse({
        body: { ...problem(403, "provenance_rejected"), reason },
        digest: DIGEST,
        status: 403,
      });
      expect(verdict.outcome).toBe("refused");
      expect(verdict.message).toContain("403 provenance_rejected");
      expect(verdict.message).toContain(`reason: ${reason}`);
    }
  });

  it("treats an unexpected 4xx as a refusal and a 5xx as retryable", async () => {
    expect(classifyPublishResponse({ body: null, digest: DIGEST, status: 429 }).outcome).toBe(
      "refused",
    );
    expect(classifyPublishResponse({ body: null, digest: DIGEST, status: 502 }).outcome).toBe(
      "retry",
    );
  });
});
