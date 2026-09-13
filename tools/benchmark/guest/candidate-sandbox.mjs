import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyLinkdingRuntime } from "./linkding-runtime.mjs";
import { verifyWhoogleRuntime } from "./whoogle-runtime.mjs";
import { verifyFlaskReuploadedRuntime } from "./flask-reuploaded-runtime.mjs";
import { verifyBrowserRuntime } from "./browser-runtime.mjs";
import { leaseBrowserInputs } from "./browser-inputs.mjs";
import { verifyOnekeyRuntime } from "./replacement-onekey-runtime.mjs";
import { executeFmdCandidate } from "./replacement-fmd-executor.mjs";

const directory = path.dirname(fileURLToPath(import.meta.url));

const replacementSupportFiles = Object.freeze([
  "replacement-cases.mjs",
  "replacement-dom.mjs",
  "replacement-redirect-python.py",
  "replacement-redirect.mjs",
  "replacement-tls-python.py",
  "replacement-tls.mjs",
  "replacement-unsafe-html.mjs",
]);
const onekeySupportFiles = Object.freeze([
  "replacement-onekey-candidate.py",
  "replacement-onekey-fixtures.py",
]);

export function candidateAdapterProfile(item) {
  const fmd = item.fmdAdapter === true;
  const control = item.controlAdapter === true;
  const replacement = item.replacementAdapter === true;
  const onekey = item.onekeyAdapter === true;
  const node = control || fmd || replacement || item.runtime === "node";
  const linkding = item.id === "linkding-asset-sandbox";
  const whoogle = item.id === "whoogle-named-config-path";
  const flaskReuploaded = item.repository === "flask-reuploaded";
  const confirmatory = item.confirmatory === true;
  const adapter = fmd
    ? "replacement-fmd-controller.mjs"
    : control
      ? "replacement-control-candidate.mjs"
      : onekey
        ? "replacement-onekey-probe.py"
        : replacement
          ? "replacement-node-candidate.mjs"
          : linkding
            ? "linkding-candidate.py"
            : whoogle
              ? "whoogle-candidate.py"
              : flaskReuploaded
                ? "flask-reuploaded-candidate.py"
                : confirmatory
                  ? node
                    ? "confirmatory-node-candidate.mjs"
                    : "confirmatory-python-candidate.py"
                  : item.id === "tornado-static-redirect"
                    ? "tornado-candidate.py"
                    : node
                      ? "node-candidate.mjs"
                      : "python-candidate.py";
  return {
    adapter,
    confirmatory,
    control,
    fmd,
    flaskReuploaded,
    linkding,
    node,
    onekey,
    replacement,
    supportFiles: control
      ? ["replacement-control-hash.mjs"]
      : replacement
        ? [...replacementSupportFiles]
        : onekey
          ? [...onekeySupportFiles]
          : [],
    whoogle,
  };
}

export function executeCandidate(item, candidate, input) {
  if (process.platform !== "linux" || process.getuid() !== 0)
    throw new Error("Candidate execution requires the isolated guest controller");
  if (item.fmdAdapter === true) return executeFmdCandidate(item, candidate, input);
  const {
    adapter,
    confirmatory,
    flaskReuploaded,
    linkding,
    node,
    onekey,
    replacement,
    supportFiles,
    whoogle,
  } = candidateAdapterProfile(item);
  const browser = linkding && input.operation === "browser";
  const runtime = onekey
    ? verifyOnekeyRuntime(item.repositoryRuntime)
    : linkding
      ? verifyLinkdingRuntime(item.repositoryRuntime)
      : whoogle
        ? verifyWhoogleRuntime(item.repositoryRuntime)
        : flaskReuploaded
          ? verifyFlaskReuploadedRuntime(item.repositoryRuntime)
          : null;
  if (browser) verifyBrowserRuntime(item.browserRuntime);
  const lease = browser ? leaseBrowserInputs(candidate) : null;
  const onekeyDirectory = onekey ? mkdtempSync("/tmp/sitecmd-onekey-") : null;
  if (onekeyDirectory) {
    writeFileSync(path.join(onekeyDirectory, "hosts"), "127.0.0.1 localhost\n", { mode: 0o644 });
    writeFileSync(path.join(onekeyDirectory, "nsswitch.conf"), "hosts: files\n", {
      mode: 0o644,
    });
  }
  const unit = browser ? `sitecmd-browser-${randomBytes(12).toString("hex")}` : null;
  const args = [
    "--quiet",
    "--wait",
    "--pipe",
    "--collect",
    ...(browser ? ["--property=User=grader", `--unit=${unit}`] : []),
    `--property=MemoryMax=${browser ? "1G" : "512M"}`,
    `--property=TasksMax=${browser ? 256 : onekey ? 64 : 32}`,
    `--property=RuntimeMaxSec=${browser ? 90 : onekey ? 45 : linkding ? 40 : whoogle || flaskReuploaded ? 30 : confirmatory || replacement ? 20 : 8}`,
    "bwrap",
    ...(onekey ? [] : ["--unshare-user"]),
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup",
    "--die-with-parent",
    "--new-session",
    "--cap-drop",
    "ALL",
    ...(onekey
      ? ["--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_KILL"]
      : []),
    "--ro-bind",
    "/usr",
    "/usr",
    "--symlink",
    "usr/lib",
    "/lib",
    ...(onekey ? ["--symlink", "usr/bin", "/bin"] : []),
    "--ro-bind",
    lease?.source ?? candidate,
    "/work",
    "--ro-bind",
    path.join(lease?.directory ?? directory, adapter),
    "/adapter",
    ...(node ? ["--ro-bind", realpathSync("/usr/local/bin/node"), "/node"] : []),
    ...((confirmatory && node) || replacement
      ? [
          "--dir",
          "/compiler",
          "--ro-bind",
          path.join(directory, "../vendor/typescript.cjs"),
          "/compiler/typescript.cjs",
        ]
      : []),
    ...(confirmatory && node
      ? ["--ro-bind", path.join(directory, "confirmatory-dom.mjs"), "/confirmatory-dom.mjs"]
      : []),
    ...supportFiles.flatMap((file) => {
      const target = onekey
        ? file === "replacement-onekey-candidate.py"
          ? "/candidate.py"
          : "/onekey_fixtures.py"
        : `/${file}`;
      return ["--ro-bind", path.join(directory, file), target];
    }),
    ...(onekey
      ? [
          "--dir",
          "/etc",
          "--ro-bind",
          path.join(onekeyDirectory, "hosts"),
          "/etc/hosts",
          "--ro-bind",
          path.join(onekeyDirectory, "nsswitch.conf"),
          "/etc/nsswitch.conf",
          "--ro-bind",
          `${runtime.directory}/venv`,
          "/runtime",
        ]
      : runtime
        ? ["python", "environment/venv"].flatMap((part) => [
            "--ro-bind",
            `${runtime.directory}/${part}`,
            `${runtime.directory}/${part}`,
          ])
        : []),
    ...(browser
      ? [
          "--symlink",
          "usr/bin",
          "/bin",
          ...["block", "bus", "class", "dev", "devices"].flatMap((name) => [
            "--dir",
            `/sys/${name}`,
          ]),
          ...["/etc/fonts", "/etc/passwd", "/etc/group"].flatMap((file) => [
            "--ro-bind",
            file,
            file,
          ]),
          ...["linkding-browser", "webdriver-session"].flatMap((name) => [
            "--ro-bind",
            path.join(lease.directory, `${name}.py`),
            `/probes/${name.replaceAll("-", "_")}.py`,
          ]),
          ...["pids.events", "memory.events", "memory.peak"].flatMap((name) => [
            "--ro-bind",
            `/sys/fs/cgroup/system.slice/${unit}.service/${name}`,
            `/probes/${name}`,
          ]),
        ]
      : []),
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--chdir",
    "/work",
    "--clearenv",
    "--setenv",
    "PATH",
    "/usr/bin:/usr/local/bin",
    ...(replacement
      ? ["--setenv", "SITECMD_BENCHMARK_TYPESCRIPT", "/compiler/typescript.cjs"]
      : []),
    ...(onekey ? ["--setenv", "PYTHONDONTWRITEBYTECODE", "1"] : []),
    "--uid",
    onekey ? "0" : "65534",
    "--gid",
    onekey ? "0" : "65534",
    "--",
    ...(node
      ? ["/node", "--max-old-space-size=256", "/adapter"]
      : [
          onekey
            ? "/runtime/bin/python"
            : runtime
              ? `${runtime.directory}/environment/venv/bin/python`
              : "/usr/bin/python3",
          "-B",
          "/adapter",
        ]),
  ];
  let result;
  try {
    result = spawnSync("systemd-run", args, {
      input: JSON.stringify({ ...input, entry: item.entry }),
      encoding: "utf8",
      timeout: browser
        ? 95000
        : onekey
          ? 50000
          : linkding
            ? 45000
            : whoogle || flaskReuploaded
              ? 35000
              : confirmatory || replacement
                ? 25000
                : 12000,
      maxBuffer: 1024 * 1024,
      env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    });
  } finally {
    lease?.close();
    if (onekeyDirectory) rmSync(onekeyDirectory, { recursive: true, force: true });
  }
  if (browser) verifyBrowserRuntime(item.browserRuntime);
  if (result.status !== 0)
    return {
      error: "CandidateProcessError",
      message: `${result.error?.message ?? result.status}: ${result.stderr}`,
    };
  try {
    return JSON.parse(result.stdout);
  } catch {
    return { error: "InvalidCandidateOutput", message: result.stdout };
  }
}
