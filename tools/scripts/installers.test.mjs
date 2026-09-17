import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const PUBLIC_INSTALLER = path.join(ROOT, "install.sh");
const SETUP_INSTALLER = path.join(ROOT, ".github", "actions", "setup-sitecmd", "install.sh");
const VERSION = "1.5.4";
const SHA256 = "a".repeat(64);
const temporaryRoots = [];

function writeExecutable(file, source) {
  fs.writeFileSync(file, source, { mode: 0o755 });
}

function createInstallerFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-installer-test-"));
  temporaryRoots.push(root);
  const bin = path.join(root, "bin");
  const installDir = path.join(root, "install");
  const fixtures = path.join(root, "fixtures");
  fs.mkdirSync(bin);
  fs.mkdirSync(installDir);
  fs.mkdirSync(fixtures);

  const archive = path.join(fixtures, "archive.tar.gz");
  const checksum = path.join(fixtures, "archive.tar.gz.sha256");
  const signature = path.join(fixtures, "archive.tar.gz.sig");
  const binary = path.join(fixtures, "sitecmd");
  fs.writeFileSync(archive, "signed archive fixture\n");
  fs.writeFileSync(checksum, `${SHA256}  archive.tar.gz\n`);
  fs.writeFileSync(signature, "c2lnbmF0dXJl\n");
  writeExecutable(binary, `#!/bin/sh\nprintf 'sitecmd ${VERSION}\\n'\n`);

  writeExecutable(
    path.join(bin, "curl"),
    `#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output=$2
    shift 2
    continue
  fi
  url=$1
  shift
done
if [ -n "$FAKE_CURL_LOG" ]; then
  printf '%s\\n' "$url" >> "$FAKE_CURL_LOG"
fi
if [ -z "$output" ]; then
  printf '%s\\n' "$FAKE_LATEST_RESPONSE"
  exit 0
fi
case "$url" in
  *.sha256) cp "$FAKE_CHECKSUM" "$output" ;;
  *.sig) cp "$FAKE_SIGNATURE" "$output" ;;
  *) cp "$FAKE_ARCHIVE" "$output" ;;
esac
`,
  );
  writeExecutable(path.join(bin, "base64"), "#!/bin/sh\ncat\n");
  writeExecutable(path.join(bin, "minisign"), '#!/bin/sh\nexit "${FAKE_MINISIGN_STATUS:-0}"\n');
  writeExecutable(
    path.join(bin, "sha256sum"),
    '#!/bin/sh\nprintf \'%s  %s\\n\' "$FAKE_ACTUAL_SHA256" "$1"\n',
  );
  writeExecutable(
    path.join(bin, "uname"),
    `#!/bin/sh
case "$1" in
  -s) printf '%s\\n' "${"$"}{FAKE_UNAME_SYSTEM:-Linux}" ;;
  -m) printf '%s\\n' "${"$"}{FAKE_UNAME_ARCH:-x86_64}" ;;
esac
`,
  );
  writeExecutable(
    path.join(bin, "tar"),
    `#!/bin/sh
destination=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-C" ]; then
    destination=$2
    shift 2
    continue
  fi
  shift
done
mkdir -p "$destination"
cp "$FAKE_BINARY" "$destination/sitecmd"
chmod 0755 "$destination/sitecmd"
`,
  );
  writeExecutable(
    path.join(bin, "mv"),
    `#!/bin/sh
source_path=$1
destination_path=$2
case "$source_path" in
  "$FAKE_INSTALL_DIR"/*)
    if [ "${"$"}{FAKE_LOCAL_MV_STATUS:-0}" -ne 0 ]; then
      exit "$FAKE_LOCAL_MV_STATUS"
    fi
    PATH=/usr/bin:/bin exec mv "$source_path" "$destination_path"
    ;;
esac
printf 'partial-install\\n' > "$destination_path"
exit 91
`,
  );
  writeExecutable(
    path.join(bin, "install"),
    `#!/bin/sh
source_path=$3
destination_path=$4
case "$destination_path" in
  "$FAKE_INSTALL_DIR"/.sitecmd.*)
    cp "$source_path" "$destination_path"
    chmod 0755 "$destination_path"
    exit 0
    ;;
esac
printf 'partial-install\\n' > "$destination_path"
exit 92
`,
  );

  const environment = (overrides) => ({
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    HOME: root,
    RUNNER_TEMP: root,
    SITECMD_INSTALL_DIR: installDir,
    SITECMD_VERSION: VERSION,
    FAKE_ACTUAL_SHA256: SHA256,
    FAKE_ARCHIVE: archive,
    FAKE_BINARY: binary,
    FAKE_CHECKSUM: checksum,
    FAKE_INSTALL_DIR: installDir,
    FAKE_LATEST_RESPONSE: `{"latest_version":"${VERSION}"}`,
    FAKE_MINISIGN_STATUS: "0",
    FAKE_SIGNATURE: signature,
    ...overrides,
  });

  return {
    bin,
    binary,
    environment,
    installDir,
    root,
    runPublic(overrides = {}) {
      return spawnSync("sh", [PUBLIC_INSTALLER], {
        cwd: ROOT,
        encoding: "utf8",
        env: environment(overrides),
      });
    },
    runSetup(overrides = {}) {
      return spawnSync("bash", [SETUP_INSTALLER], {
        cwd: ROOT,
        encoding: "utf8",
        env: environment(overrides),
      });
    },
  };
}

function seedInstalledCli(fixture) {
  const installed = path.join(fixture.installDir, "sitecmd");
  const source = "#!/bin/sh\nprintf 'sitecmd old\\n'\n";
  writeExecutable(installed, source);
  return { installed, source };
}

function expectPreserved(result, installed) {
  expect(result.status).not.toBe(0);
  expect(fs.readFileSync(installed.installed, "utf8")).toBe(installed.source);
}

function runInstaller(fixture, installer, overrides = {}) {
  return installer === "public" ? fixture.runPublic(overrides) : fixture.runSetup(overrides);
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("CLI installers", { timeout: 15_000 }, () => {
  it("replaces an existing public CLI through a destination-local rename", () => {
    const fixture = createInstallerFixture();
    const { installed } = seedInstalledCli(fixture);

    const result = fixture.runPublic();

    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(fs.readFileSync(installed, "utf8")).toBe(fs.readFileSync(fixture.binary, "utf8"));
    expect(fs.statSync(installed).mode & 0o777).toBe(0o755);
  });

  it("replaces an existing setup-action CLI through a destination-local rename", () => {
    const fixture = createInstallerFixture();
    const { installed } = seedInstalledCli(fixture);

    const result = fixture.runSetup();

    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(fs.readFileSync(installed, "utf8")).toBe(fs.readFileSync(fixture.binary, "utf8"));
    expect(fs.statSync(installed).mode & 0o777).toBe(0o755);
  });

  it.each(["public", "setup"])("rejects an invalid signature in the %s installer", (kind) => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = runInstaller(fixture, kind, { FAKE_MINISIGN_STATUS: "9" });

    expectPreserved(result, installed);
  });

  it("rejects a public archive whose checksum does not match", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = fixture.runPublic({ FAKE_ACTUAL_SHA256: "b".repeat(64) });

    expect(result.stderr).toContain("checksum verification failed");
    expectPreserved(result, installed);
  });

  it.each(["public", "setup"])("rejects a version mismatch in the %s installer", (kind) => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);
    writeExecutable(fixture.binary, "#!/bin/sh\nprintf 'sitecmd 9.9.9\\n'\n");

    const result = runInstaller(fixture, kind);

    expect(result.stderr).toContain("expected 'sitecmd 1.5.4'");
    expectPreserved(result, installed);
  });

  it("installs the public release selected by the latest-version endpoint", () => {
    const fixture = createInstallerFixture();

    const result = fixture.runPublic({ SITECMD_VERSION: "" });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Installed sitecmd 1.5.4");
  });

  it("rejects a malformed latest-version response", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = fixture.runPublic({
      SITECMD_VERSION: "",
      FAKE_LATEST_RESPONSE: '{"latest":"1.5.4"}',
    });

    expect(result.stderr).toContain("could not determine the latest version");
    expectPreserved(result, installed);
  });

  it.each([
    ["public", { FAKE_UNAME_SYSTEM: "FreeBSD" }, "unsupported platform: FreeBSD"],
    ["public", { FAKE_UNAME_ARCH: "riscv64" }, "no prebuilt CLI for Linux/riscv64"],
    ["setup", { FAKE_UNAME_SYSTEM: "Darwin" }, "supports Linux x86_64 and arm64 runners only"],
    ["setup", { FAKE_UNAME_ARCH: "riscv64" }, "supports Linux x86_64 and arm64 runners only"],
  ])("rejects an unsupported platform in the %s installer", (kind, overrides, message) => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = runInstaller(fixture, kind, overrides);

    expect(result.stderr).toContain(message);
    expectPreserved(result, installed);
  });

  it.each([
    ["public", "aarch64"],
    ["public", "arm64"],
    ["setup", "aarch64"],
    ["setup", "arm64"],
  ])("downloads the Linux arm64 archive from the %s installer on %s", (kind, arch) => {
    const fixture = createInstallerFixture();
    const log = path.join(fixture.root, "curl.log");

    const result = runInstaller(fixture, kind, { FAKE_UNAME_ARCH: arch, FAKE_CURL_LOG: log });

    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(fs.readFileSync(log, "utf8")).toContain(
      `/v${VERSION}/sitecmd-cli_${VERSION}_linux-aarch64.tar.gz`,
    );
  });

  it.each(["public", "setup"])(
    "preserves an existing CLI when the %s install rename fails",
    (kind) => {
      const fixture = createInstallerFixture();
      const installed = seedInstalledCli(fixture);

      const result = runInstaller(fixture, kind, { FAKE_LOCAL_MV_STATUS: "93" });

      expectPreserved(result, installed);
      expect(fs.readdirSync(fixture.installDir)).toEqual(["sitecmd"]);
    },
  );

  it("executes nothing when the public installer is truncated mid-stream", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);
    const source = fs.readFileSync(PUBLIC_INSTALLER, "utf8");

    const result = spawnSync("sh", [], {
      cwd: ROOT,
      encoding: "utf8",
      env: fixture.environment({}),
      input: source.slice(0, source.length - 120),
    });

    expect(result.stdout).not.toContain("Downloading");
    expectPreserved(result, installed);
  });

  it("refuses a latest-version answer older than the installed CLI", () => {
    const fixture = createInstallerFixture();
    const installed = path.join(fixture.installDir, "sitecmd");
    writeExecutable(installed, "#!/bin/sh\nprintf 'sitecmd 1.6.0\\n'\n");

    const result = fixture.runPublic({ SITECMD_VERSION: "" });

    expect(result.stderr).toContain("refusing to downgrade");
    expect(result.status).not.toBe(0);
    expect(fs.readFileSync(installed, "utf8")).toContain("1.6.0");
  });

  it("installs an explicitly pinned version that is older than the installed CLI", () => {
    const fixture = createInstallerFixture();
    writeExecutable(
      path.join(fixture.installDir, "sitecmd"),
      "#!/bin/sh\nprintf 'sitecmd 1.6.0\\n'\n",
    );

    const result = fixture.runPublic();

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Installed sitecmd 1.5.4");
  });

  it("names the package-manager command when minisign is missing", () => {
    const fixture = createInstallerFixture();
    fs.unlinkSync(path.join(fixture.bin, "minisign"));

    const result = fixture.runPublic({
      FAKE_UNAME_SYSTEM: "Darwin",
      PATH: `${fixture.bin}:/usr/bin:/bin`,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("minisign is required");
    expect(result.stderr).toContain("brew install minisign");
  });

  it("names the apt-get install command on Linux when apt-get is available", () => {
    const fixture = createInstallerFixture();
    writeExecutable(path.join(fixture.bin, "apt-get"), "#!/bin/sh\nexit 0\n");
    fs.unlinkSync(path.join(fixture.bin, "minisign"));

    const result = fixture.runPublic({
      FAKE_UNAME_SYSTEM: "Linux",
      PATH: `${fixture.bin}:/usr/bin:/bin`,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("minisign is required");
    expect(result.stderr).toContain("sudo apt-get install minisign");
  });

  it("falls back to the minisign docs URL on Linux without a known package manager", () => {
    const fixture = createInstallerFixture();
    fs.unlinkSync(path.join(fixture.bin, "minisign"));
    // The stub-only PATH keeps the real OS out of the probe: on an Ubuntu
    // runner /usr/bin holds apt-get (and /bin is a symlink to it), so any
    // real directory on PATH turns this into the package-manager branch.
    // grep and expr stubs satisfy the earlier prerequisite probes.
    writeExecutable(path.join(fixture.bin, "grep"), "#!/bin/sh\nexit 0\n");
    writeExecutable(path.join(fixture.bin, "expr"), "#!/bin/sh\nexit 0\n");

    const result = spawnSync("/bin/sh", [PUBLIC_INSTALLER], {
      cwd: ROOT,
      encoding: "utf8",
      env: fixture.environment({
        FAKE_UNAME_SYSTEM: "Linux",
        PATH: fixture.bin,
      }),
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("minisign is required");
    expect(result.stderr).toContain("https://jedisct1.github.io/minisign/#installation");
  });

  it("rejects a latest-version answer with a fourth version component", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = fixture.runPublic({
      SITECMD_VERSION: "",
      FAKE_LATEST_RESPONSE: '{"latest_version":"1.0.0.0"}',
    });

    expect(result.stderr).toContain("invalid release version");
    expectPreserved(result, installed);
  });

  it("refuses a pre-release latest-version answer older than the installed release", () => {
    const fixture = createInstallerFixture();
    const installed = path.join(fixture.installDir, "sitecmd");
    writeExecutable(installed, "#!/bin/sh\nprintf 'sitecmd 1.6.0\\n'\n");

    const result = fixture.runPublic({
      SITECMD_VERSION: "",
      FAKE_LATEST_RESPONSE: '{"latest_version":"1.6.0-rc.1"}',
    });

    expect(result.stderr).toContain("refusing to downgrade");
    expect(result.status).not.toBe(0);
    expect(fs.readFileSync(installed, "utf8")).toContain("1.6.0");
  });

  it("installs a release that supersedes an installed pre-release of the same version", () => {
    const fixture = createInstallerFixture();
    writeExecutable(
      path.join(fixture.installDir, "sitecmd"),
      "#!/bin/sh\nprintf 'sitecmd 1.5.4-rc.1\\n'\n",
    );

    const result = fixture.runPublic({ SITECMD_VERSION: "" });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Installed sitecmd 1.5.4");
  });

  it("rejects a latest-version answer with a trailing dot", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = fixture.runPublic({
      SITECMD_VERSION: "",
      FAKE_LATEST_RESPONSE: '{"latest_version":"1.2.3."}',
    });

    expect(result.stderr).toContain("invalid release version");
    expectPreserved(result, installed);
  });

  it("rejects a latest-version answer with a leading zero on a component", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = fixture.runPublic({
      SITECMD_VERSION: "",
      FAKE_LATEST_RESPONSE: '{"latest_version":"01.2.3"}',
    });

    expect(result.stderr).toContain("invalid release version");
    expectPreserved(result, installed);
  });

  it("rejects an oversized version component without leaking a raw integer-comparison error", () => {
    const fixture = createInstallerFixture();
    const installed = seedInstalledCli(fixture);

    const result = fixture.runPublic({
      SITECMD_VERSION: "",
      FAKE_LATEST_RESPONSE: '{"latest_version":"12345678901234567890.0.0"}',
    });

    expect(result.stderr).toContain("invalid release version");
    expect(result.stderr).not.toContain("integer expression");
    expectPreserved(result, installed);
  });

  it("requires expr as a prerequisite so a missing tool fails closed", () => {
    const fixture = createInstallerFixture();
    const installed = path.join(fixture.installDir, "sitecmd");
    writeExecutable(installed, "#!/bin/sh\nprintf 'sitecmd 1.5.4-rc.1\\n'\n");

    // Invoke the /bin/sh binary directly (a bare "sh" resolves through the
    // overridden PATH and would fail to launch). The PATH is the stub bin
    // ALONE: expr lives in /bin on macOS but /usr/bin on Linux, so excluding
    // one real directory is not portable; the stub bin carries every probed
    // prerequisite except expr itself.
    writeExecutable(path.join(fixture.bin, "grep"), "#!/bin/sh\nexit 0\n");
    const result = spawnSync("/bin/sh", [PUBLIC_INSTALLER], {
      cwd: ROOT,
      encoding: "utf8",
      env: fixture.environment({
        SITECMD_VERSION: "",
        FAKE_LATEST_RESPONSE: '{"latest_version":"1.5.4-rc.2"}',
        PATH: fixture.bin,
      }),
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("expr is required");
    expect(fs.readFileSync(installed, "utf8")).toContain("1.5.4-rc.1");
  });
});
