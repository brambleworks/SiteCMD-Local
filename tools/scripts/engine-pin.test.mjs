import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";
import { afterEach, expect, it, vi } from "vitest";

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal();
  return { ...original, writeFile: vi.fn(original.writeFile) };
});

const scripts = fileURLToPath(new URL("./", import.meta.url));
const repository = path.resolve(scripts, "../..");
const modulePath = "engine/local-engine.wasm";
const moduleName = path.basename(modulePath);
const licensesName = `${moduleName}.LICENSES.txt`;
const moduleBytes = "fixture module";
const licenseText = "Fixture engine dependency license\n";
const digest = createHash("sha256").update(moduleBytes).digest("hex");
const lock = {
  version: "1.2.3",
  sha256: digest,
  abi_version: 2,
  url: "https://releases.sitecmd.com/engine/v1.2.3/local-engine.wasm",
  github_release: { repository: "brambleworks/SiteCMD-Engine-Releases", tag: "engine-v1.2.3" },
};
const canSign = spawnSync("minisign", ["-v"], { stdio: "ignore" }).status === 0;
const skipSigning = !canSign && process.env.CI === undefined;
const directories = [];

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-pin-"));
  directories.push(root);
  mkdirSync(path.dirname(path.join(root, modulePath)));
  writeFileSync(path.join(root, "engine.lock"), JSON.stringify(lock));
  vi.stubEnv("SITECMD_ENGINE_TOKEN", undefined);
  return root;
}

function run(script, args, root) {
  return spawnSync(process.execPath, [path.join(scripts, script), ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

function fakeCommand(root, command, source) {
  const filename = path.join(root, command);
  writeFileSync(filename, `#!${process.execPath}\n${source}\n`, { mode: 0o755 });
  return filename;
}

function minisign(args) {
  const result = spawnSync("minisign", args, { encoding: "utf8" });
  expect(
    result.status,
    result.error?.code === "ENOENT"
      ? "minisign is required for engine bump tests in CI"
      : result.stderr,
  ).toBe(0);
}

function signedAssets(root) {
  const publicFile = path.join(root, "test.pub");
  const secretFile = path.join(root, "test.key");
  minisign(["-G", "-W", "-p", publicFile, "-s", secretFile]);
  const assets = new Map([
    [moduleName, moduleBytes],
    [licensesName, licenseText],
  ]);
  for (const [name, content] of [...assets]) {
    const file = path.join(root, name);
    writeFileSync(file, content);
    minisign(["-S", "-s", secretFile, "-m", file, "-t", "sitecmd local engine v2.0.0"]);
    assets.set(`${name}.minisig`, readFileSync(`${file}.minisig`));
  }
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      const bytes = assets.get(new URL(url).pathname.split("/").at(-1));
      return bytes === undefined ? new Response(null, { status: 404 }) : new Response(bytes);
    }),
  );
  return { assets, publicKey: readFileSync(publicFile, "utf8").trimEnd().split("\n").at(-1) };
}

it("fetch_and_lock_fixture_match_the_protocol_abi_version", async () => {
  // Bug: The fetcher and its fixture can agree on an ABI the Rust host rejects.
  const protocol = readFileSync(
    path.join(repository, "apps/desktop/src-tauri/crates/protocol/src/engine_abi/mod.rs"),
    "utf8",
  );
  const version = protocol.match(/^pub const ENGINE_ABI_VERSION: u32 = (\d+);$/m);
  expect(version).not.toBeNull();
  expect(lock.abi_version).toBe(Number(version[1]));
  const root = fixture();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(moduleBytes)),
  );
  const { fetchEngine } = await import("./fetch-engine.mjs");
  await expect(fetchEngine(root)).resolves.toEqual(lock);
});

it("fetch_refuses_a_digest_mismatch_and_leaves_no_file", async () => {
  // A digest mismatch leaves an old or corrupt module available to build.
  const root = fixture();
  writeFileSync(path.join(root, modulePath), "stale module");
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("different module")),
  );
  const { fetchEngine } = await import("./fetch-engine.mjs");
  await expect(fetchEngine(root)).rejects.toThrow(/SHA-256.*engine\.lock/);
  expect(readdirSync(path.dirname(path.join(root, modulePath)))).toEqual([]);
});

it("fetch_writes_no_bytes_whose_digest_is_wrong", async () => {
  // Downloaded bytes reach the disk before their digest is checked.
  const root = fixture();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("different module")),
  );
  writeFile.mockClear();
  const { fetchEngine } = await import("./fetch-engine.mjs");
  await expect(fetchEngine(root)).rejects.toThrow(/SHA-256.*engine\.lock/);
  expect(
    writeFile.mock.calls.map(([file]) => String(file)).filter((file) => file.endsWith(moduleName)),
  ).toEqual([]);
});

it("fetch_refuses_a_lock_url_it_did_not_derive", async () => {
  // A lock whose url names another host is requested instead of the release origin.
  const root = fixture();
  writeFileSync(
    path.join(root, "engine.lock"),
    JSON.stringify({ ...lock, url: "https://example.invalid/local-engine.wasm" }),
  );
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { fetchEngine } = await import("./fetch-engine.mjs");
  await expect(fetchEngine(root)).rejects.toThrow(/Invalid engine\.lock/);
  expect(fetch).not.toHaveBeenCalled();
});

it("fetch_requests_the_url_derived_from_the_version", async () => {
  // The request URL is copied from the lock file's text instead of derived from the version.
  const root = fixture();
  const requested = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      requested.push(url);
      return new Response(moduleBytes);
    }),
  );
  const { fetchEngine } = await import("./fetch-engine.mjs");
  await fetchEngine(root);
  expect(requested).toEqual(["https://releases.sitecmd.com/engine/v1.2.3/local-engine.wasm"]);
});

it("fetch_falls_back_to_the_github_release", async () => {
  // Bug: A failed public download can skip the GitHub fallback or fetch from the source repository.
  const { fetchEngine } = await import("./fetch-engine.mjs");
  const root = fixture();
  vi.stubEnv("PATH", `${root}${path.delimiter}${process.env.PATH}`);
  const fetch = vi.fn(async () => {
    throw new Error("fixture network failure");
  });
  vi.stubGlobal("fetch", fetch);
  fakeCommand(
    root,
    "gh",
    `
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    const args = process.argv.slice(2);
    const directory = args[8];
    assert.deepEqual(args, ["release", "download", "engine-v1.2.3", "--repo",
      "brambleworks/SiteCMD-Engine-Releases", "--pattern", "local-engine.wasm", "--dir", directory]);
    assert.equal(process.env.GH_TOKEN, fs.readFileSync(path.join(import.meta.dirname, "expected-token"), "utf8"));
    fs.writeFileSync(path.join(directory, "local-engine.wasm"), ${JSON.stringify(moduleBytes)});
  `,
  );
  const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
  writeFileSync(path.join(root, "expected-token"), "");
  await fetchEngine(root);
  expect(warning).toHaveBeenCalledWith(expect.stringContaining("fixture network failure"));
  expect(fetch).toHaveBeenCalledWith(lock.url, expect.any(Object));
  expect(readFileSync(path.join(root, modulePath), "utf8")).toBe(moduleBytes);

  writeFileSync(path.join(root, "expected-token"), "fixture-token");
  vi.stubEnv("SITECMD_ENGINE_TOKEN", "fixture-token");
  fetch.mockClear();
  await fetchEngine(root);
  expect(fetch).not.toHaveBeenCalled();
  expect(readFileSync(path.join(root, modulePath), "utf8")).toBe(moduleBytes);
});

it("reports why the GitHub fallback failed without exposing credentials", async () => {
  // A fallback error drops the GitHub diagnostic or logs the engine token.
  const { fetchEngine } = await import("./fetch-engine.mjs");
  const root = fixture();
  vi.stubEnv("PATH", `${root}${path.delimiter}${process.env.PATH}`);
  vi.stubEnv("SITECMD_ENGINE_TOKEN", "fixture-engine-secret");
  vi.stubEnv("GITHUB_TOKEN", "fixture-github-secret");
  vi.stubGlobal("fetch", vi.fn());
  fakeCommand(
    root,
    "gh",
    'console.error("release asset unavailable", process.env.GH_TOKEN, process.env.GITHUB_TOKEN); process.exit(1);',
  );
  const failure = await fetchEngine(root).catch((error) => error);
  expect(failure).toBeInstanceOf(Error);
  expect(failure.message).toContain("release asset unavailable [redacted] [redacted]");
  expect(failure.message).not.toMatch(/fixture-(?:engine|github)-secret/);
  expect(fetch).not.toHaveBeenCalled();
  expect(readdirSync(path.dirname(path.join(root, modulePath)))).toEqual([]);
});

it.skipIf(skipSigning)("bump_refuses_a_bad_signature", async () => {
  // A module or license file can replace a pin with an invalid signature.
  const { bumpEngine } = await import("./fetch-engine.mjs");
  const root = fixture();
  const { assets, publicKey } = signedAssets(root);
  const lockFile = path.join(root, "engine.lock");
  const licenseFile = path.join(root, `${modulePath}.LICENSES.txt`);
  writeFileSync(licenseFile, "old licenses");
  for (const name of [moduleName, licensesName]) {
    const signature = assets.get(`${name}.minisig`);
    assets.set(`${name}.minisig`, "invalid");
    await expect(bumpEngine(root, "2.0.0", publicKey)).rejects.toThrow(/signature/i);
    expect(JSON.parse(readFileSync(lockFile, "utf8"))).toEqual(lock);
    expect(readFileSync(licenseFile, "utf8")).toBe("old licenses");
    expect(existsSync(path.join(root, modulePath))).toBe(false);
    assets.set(`${name}.minisig`, signature);
  }
  await expect(bumpEngine(root, "2.0.1", publicKey)).rejects.toThrow(/signature.*engine version/);
  expect(JSON.parse(readFileSync(lockFile, "utf8"))).toEqual(lock);
  expect(readFileSync(licenseFile, "utf8")).toBe("old licenses");
});

it.skipIf(skipSigning)("bump_rewrites_the_lock_and_licenses", async () => {
  // Bug: A verified bump can leave the old module's licenses or write the wrong release repository.
  const { bumpEngine } = await import("./fetch-engine.mjs");
  const root = fixture();
  const { publicKey } = signedAssets(root);
  await bumpEngine(root, "2.0.0", publicKey);
  expect(JSON.parse(readFileSync(path.join(root, "engine.lock"), "utf8"))).toEqual({
    ...lock,
    version: "2.0.0",
    url: "https://releases.sitecmd.com/engine/v2.0.0/local-engine.wasm",
    github_release: { ...lock.github_release, tag: "engine-v2.0.0" },
  });
  expect(readFileSync(path.join(root, `${modulePath}.LICENSES.txt`), "utf8")).toBe(licenseText);
  expect(readFileSync(path.join(root, modulePath), "utf8")).toBe(moduleBytes);
});

it("bump_refuses_without_a_configured_public_key", async () => {
  // An unconfigured signer allows a caller to substitute a trust root.
  const root = fixture();
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { bumpEngine } = await import("./fetch-engine.mjs");
  await expect(bumpEngine(root, "2.0.0", "")).rejects.toThrow(/ENGINE_MINISIGN_PUBLIC_KEY.*empty/);
  expect(fetch).not.toHaveBeenCalled();
});

function fakeBinary(root, version, sha256) {
  return fakeCommand(
    root,
    "sitecmd",
    `
    const args = process.argv.slice(2).join(" ");
    if (args === "--version") console.log(${JSON.stringify(version)});
    else if (args === "engine info --json") console.log(JSON.stringify({ sha256: ${JSON.stringify(sha256)} }));
    else process.exitCode = 2;
  `,
  );
}

it("verify_pin_refuses_unpinned", () => {
  // An unpinned version passes even when its digest happens to match.
  const root = fixture();
  const result = run(
    "verify-engine-pin.mjs",
    [fakeBinary(root, "sitecmd 2.0.0+unpinned", digest)],
    root,
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("+unpinned");
});

it("verify_pin_refuses_a_different_digest", () => {
  // A binary embedding a different module passes release verification.
  const root = fixture();
  const binary = fakeBinary(root, "sitecmd 2.0.0", digest.toUpperCase());
  const result = run("verify-engine-pin.mjs", [binary], root);
  expect(result.status).toBe(1);
  expect(result.stderr).toMatch(/SHA-256.*engine\.lock/);
  expect(
    run("verify-engine-pin.mjs", [fakeBinary(root, "sitecmd 2.0.0", digest)], root).status,
  ).toBe(0);
});

function runLegalGenerator(root) {
  const generator = "generate-third-party-artifacts.mjs";
  mkdirSync(path.join(root, "tools", "scripts"), { recursive: true });
  mkdirSync(path.join(root, "apps", "desktop", "src-tauri"), { recursive: true });
  copyFileSync(path.join(scripts, generator), path.join(root, "tools", "scripts", generator));
  vi.stubEnv("PATH", `${root}${path.delimiter}${process.env.PATH}`);
  fakeCommand(
    root,
    "cargo",
    'if (process.argv[2] === "metadata") console.log(JSON.stringify({ packages: [] }));',
  );
  return spawnSync(process.execPath, [path.join(root, "tools", "scripts", generator)], {
    cwd: root,
    encoding: "utf8",
  });
}

it("third_party_notices_include_the_module_licenses", () => {
  // The CLI's consolidated license texts omit the embedded module's dependencies.
  const root = fixture();
  writeFileSync(path.join(root, `${modulePath}.LICENSES.txt`), licenseText);
  const result = runLegalGenerator(root);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(path.join(root, "THIRD_PARTY_LICENSES.txt"), "utf8")).toContain(licenseText);
});

it("reports the missing engine license sidecar when a lock exists", () => {
  // A locked module without its license sidecar produces an opaque file error.
  const root = fixture();
  const result = runLegalGenerator(root);
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("engine.lock requires engine/local-engine.wasm.LICENSES.txt");
  expect(existsSync(path.join(root, "THIRD_PARTY_LICENSES.txt"))).toBe(false);
});
