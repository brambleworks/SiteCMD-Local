#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const CONNECT_ORIGIN = "https://connect.sitecmd.com";
const MANIFEST_ROUTE = "/v1/engine-manifests/";
const OIDC_AUDIENCE = CONNECT_ORIGIN;

const MANIFEST_FILE = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const APP_CARGO_TOML = "apps/desktop/src-tauri/Cargo.toml";
const MAX_ENGINE_RELEASE_CHARS = 64;

const DIGEST_PATTERN = /^[0-9a-f]{16,64}$/;

const MAX_ATTEMPTS = 3;
const RETRY_BACKOFF_MS = [1000, 3000];

/** Read and validate the document's own content-addressed digest. */
export function manifestDigestOf(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { message: `${MANIFEST_FILE} is not valid JSON.`, ok: false };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { message: `${MANIFEST_FILE} is not a capability manifest document.`, ok: false };
  }
  const digest = parsed.manifest_digest;
  if (typeof digest !== "string" || !DIGEST_PATTERN.test(digest)) {
    return {
      message:
        `${MANIFEST_FILE} declares no usable manifest_digest (found ${JSON.stringify(digest)}). ` +
        "The registry keys the document by this value, so publishing without one would store a manifest at an identity it does not claim. " +
        "Regenerate the artifact with `cargo test -p sitecmd-engine --test capability_manifest -- --ignored regenerate`, " +
        "which is the deliberately ignored test that rewrites the file; the unignored one only asserts it is current and would simply fail again.",
      ok: false,
    };
  }
  return { digest, ok: true };
}

/** Classify a registry response as published, retryable, or refused. */
export function classifyPublishResponse({ status, body, digest }) {
  const detail = body && typeof body === "object" && body.error ? body.error : null;
  const code = detail && typeof detail.code === "string" ? detail.code : "unknown";
  const said = detail && typeof detail.message === "string" ? ` ${detail.message}` : "";
  const requestId =
    detail && typeof detail.request_id === "string" ? ` [${detail.request_id}]` : "";
  const entries =
    body && typeof body === "object" && typeof body.entries === "number" ? body.entries : "unknown";

  if (status === 201 || status === 200) {
    const declared = body && typeof body === "object" ? body.status : null;
    const echoed = body && typeof body === "object" ? body.manifest_digest : null;
    const expected = status === 201 ? "registered" : "already_registered";
    if (declared !== expected || echoed !== digest) {
      return {
        message:
          `refused (${status}): the answer did not come from the manifest registry.\n` +
          `  Expected the registry's own ${expected} for digest ${digest}, and got status ${JSON.stringify(declared)} with digest ${JSON.stringify(echoed)}.\n` +
          "  A 2xx alone is not proof of publication, and passing on one would let a build ship under a digest the registry never learned.",
        outcome: "refused",
      };
    }
    return status === 201
      ? {
          message: `registered: the connect registry now resolves digest ${digest} (${entries} entries).`,
          outcome: "published",
        }
      : {
          message: `already_registered: the connect registry already holds these exact bytes for digest ${digest} (${entries} entries).`,
          outcome: "published",
        };
  }
  if (status === 409) {
    return {
      message:
        `refused (409 ${code}): digest ${digest} is already registered with DIFFERENT bytes.${said}${requestId}\n` +
        "  The registry is immutable by design: a registered manifest is the meaning of every observation recorded under its digest, so rewriting one would silently retro-define findings the service has already accepted.\n" +
        "  This means one of two things, and you must find out which before anything ships:\n" +
        "    * the artifact moved without its digest moving (a generation bug: the committed JSON is not what sitecmd_engine::manifest produces), or\n" +
        "    * two builds computed one identity for two meanings (a digest collision in the manifest hash).\n" +
        "  Do not attempt to overwrite the entry. Rollback is re-pointing a build at an already-registered digest, never unregistering one.",
      outcome: "refused",
    };
  }
  if (status === 404) {
    return {
      message:
        `refused (404 ${code}): the connect manifest registry door is not there.${said}${requestId}\n` +
        "  Either the Worker is deployed without its manifest bucket or its publisher allowlist, or brambleworks/SiteCMD-Local is not the allowed publisher.\n" +
        "  This is a failure and not a no-op: passing here would let a build ship under a digest the registry never learned, and every observation it produces would be quarantined as incomparable.",
      outcome: "refused",
    };
  }
  if (status === 413) {
    return {
      message:
        `refused (413 ${code}): the manifest is larger than the registry accepts.${said}${requestId}\n` +
        "  The real artifact is about 38 KB against a 512 KB ceiling, so this is a generation bug rather than growth.",
      outcome: "refused",
    };
  }
  if (status === 400) {
    const guidance = {
      digest_key_mismatch:
        "The document's own manifest_digest is not the key it was published under, which can only happen if this script sent a key it did not read from the document.",
      engine_release_required:
        "The x-sitecmd-engine-release header was missing or over 64 characters. A publication names the build it is publishing for.",
      malformed_manifest:
        "The registry could not index the document: the schema version is not the one it understands, or an entry is missing its check or contract. Regenerate the artifact.",
    }[code];
    return {
      message: `refused (400 ${code}): ${guidance ?? "the registry rejected the request."}${said}${requestId}`,
      outcome: "refused",
    };
  }
  if (status === 401 || status === 403) {
    return {
      message:
        `refused (${status} ${code}): the connect registry did not accept this job's identity.${said}${requestId}\n` +
        `  The token must be a GitHub Actions OIDC token for audience ${OIDC_AUDIENCE}, minted in a job with permissions: id-token: write, whose repository claim is the registry's allowed publisher.`,
      outcome: "refused",
    };
  }
  if (status >= 500) {
    return {
      message: `connect answered ${status} ${code}.${said}${requestId}`,
      outcome: "retry",
    };
  }
  return {
    message: `refused (${status} ${code}): unexpected answer from the manifest registry.${said}${requestId}`,
    outcome: "refused",
  };
}

async function oidcToken(fetchPort, env) {
  const endpoint = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!endpoint || !requestToken) {
    return {
      message:
        "no Actions OIDC endpoint in the environment. The publishing job must declare permissions: id-token: write; without it there is no credential this registry accepts.",
      ok: false,
    };
  }
  let response;
  try {
    response = await fetchPort(`${endpoint}&audience=${encodeURIComponent(OIDC_AUDIENCE)}`, {
      headers: { authorization: `Bearer ${requestToken}` },
    });
  } catch (error) {
    return { message: `could not reach the Actions OIDC endpoint: ${error.message}`, ok: false };
  }
  if (!response.ok) {
    // Never include a failed token-mint body in errors.
    return { message: `the Actions OIDC endpoint answered ${response.status}.`, ok: false };
  }
  const minted = await response.json();
  if (!minted || typeof minted.value !== "string" || minted.value.length === 0) {
    return { message: "the Actions OIDC endpoint returned no token value.", ok: false };
  }
  return { ok: true, token: minted.value };
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Publish one manifest through injected network and timing ports. */
export async function publishCapabilityManifest(options) {
  const { body, engineRelease } = options;
  const fetchPort = options.fetch;
  const sleep = options.sleep ?? defaultSleep;
  const env = options.env ?? process.env;

  const document = manifestDigestOf(Buffer.from(body).toString("utf8"));
  if (!document.ok) return { message: document.message, ok: false };

  if (!engineRelease || engineRelease.length > MAX_ENGINE_RELEASE_CHARS) {
    return {
      message: `engine release ${JSON.stringify(engineRelease)} is empty or over ${MAX_ENGINE_RELEASE_CHARS} characters; the registry bounds the header it is sent in.`,
      ok: false,
    };
  }

  const credential = await oidcToken(fetchPort, env);
  if (!credential.ok) return { message: credential.message, ok: false };

  const url = `${CONNECT_ORIGIN}${MANIFEST_ROUTE}${document.digest}`;
  let last = "";
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    let response;
    try {
      response = await fetchPort(url, {
        body,
        headers: {
          authorization: `Bearer ${credential.token}`,
          "content-type": "application/json",
          "x-sitecmd-engine-release": engineRelease,
        },
        method: "PUT",
      });
    } catch (error) {
      last = `could not reach ${url}: ${error.message}`;
      if (attempt < MAX_ATTEMPTS) {
        await sleep(RETRY_BACKOFF_MS[attempt - 1]);
        continue;
      }
      return { message: `${last} (${MAX_ATTEMPTS} attempts)`, ok: false };
    }

    // Classification uses status even when the optional body is malformed.
    const parsed = await response.json().catch(() => null);

    const verdict = classifyPublishResponse({
      body: parsed,
      digest: document.digest,
      status: response.status,
    });
    if (verdict.outcome === "published") return { message: verdict.message, ok: true };
    if (verdict.outcome === "refused") return { message: verdict.message, ok: false };
    last = verdict.message;
    if (attempt < MAX_ATTEMPTS) await sleep(RETRY_BACKOFF_MS[attempt - 1]);
  }
  return { message: `${last} (${MAX_ATTEMPTS} attempts)`, ok: false };
}

function engineReleaseFrom(cargoToml) {
  const packageSection = cargoToml.split(/^\[/m).find((section) => section.startsWith("package]"));
  return packageSection?.match(/^version\s*=\s*"([^"]+)"/m)?.[1] ?? "";
}

async function main() {
  let body;
  try {
    body = fs.readFileSync(path.join(ROOT, MANIFEST_FILE));
  } catch (error) {
    console.error(`publish-capability-manifest: cannot read ${MANIFEST_FILE}: ${error.message}`);
    process.exit(1);
  }
  const release = engineReleaseFrom(fs.readFileSync(path.join(ROOT, APP_CARGO_TOML), "utf8"));

  const result = await publishCapabilityManifest({
    body,
    engineRelease: release,
    fetch: globalThis.fetch,
  });
  if (result.ok) {
    console.log(`publish-capability-manifest: ${result.message}`);
    process.exit(0);
  }
  console.error(`publish-capability-manifest: ${result.message}`);
  process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
