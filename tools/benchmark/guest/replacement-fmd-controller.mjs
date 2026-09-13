import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { digest } from "../lib/workflow-plan.mjs";
import { createFmdFixture } from "./replacement-fmd-fixture.mjs";
import { isApprovedFmdCandidatePath } from "./replacement-fmd-path.mjs";
import { isValidFmdReferenceRun, stabilizeFmdReferenceRuns } from "./replacement-fmd-reference.mjs";
import { verifyFmdBrowserRuntime } from "./replacement-fmd-runtime.mjs";

if (process.platform !== "linux" || process.getuid() !== 0) {
  throw new Error("FMD browser grading requires the isolated guest controller");
}
const execFileAsync = promisify(execFile);
const supportDirectory = path.dirname(fileURLToPath(import.meta.url));
const request = JSON.parse(readFileSync(0, "utf8"));
const runtime = verifyFmdBrowserRuntime(request.browserRuntime);
const candidate = realpathSync(request.candidate);
if (!isApprovedFmdCandidatePath(candidate) || !lstatSync(candidate).isDirectory()) {
  throw new Error("FMD candidate path is outside the isolated benchmark workspace");
}

const temporary = mkdtempSync("/tmp/sitecmd-fmd-browser-");
const fixture = createFmdFixture(path.join(runtime.reference.directory, "baseline"));
const detailsRenderIndexes = Array.from({ length: 10 }, (_value, index) => index);
const mapRenderIndexes = [...detailsRenderIndexes];
const detailsReferencePositions = [
  [0],
  [1, 7],
  [2, 6],
  [3, 5],
  [4],
  [3, 5],
  [2, 6],
  [1, 7],
  [8],
  [9],
];

function compactRun(run) {
  const result = run.result;
  return {
    exitCode: run.exitCode,
    error: run.error,
    stderr: run.stderr.slice(-2_000),
    result: result
      ? {
          passed: result.passed,
          setupError: result.setupError,
          checks: Array.isArray(result.checks)
            ? result.checks.map((check) => ({ name: check.name, passed: check.passed }))
            : null,
          observations: Array.isArray(result.observations)
            ? result.observations.map((observation) => ({
                pageOverrideInstalled: observation.pageOverrideInstalled,
              }))
            : null,
          pendingActionSamples: Array.isArray(result.pendingActionSamples)
            ? result.pendingActionSamples.map((record) => ({
                completed: record.completed,
                samples: Array.isArray(record.samples) ? record.samples.length : null,
              }))
            : null,
          earlyRenderSamples: Array.isArray(result.earlyRenderSamples)
            ? result.earlyRenderSamples.map((record) => ({
                samples: Array.isArray(record.samples) ? record.samples.length : null,
                settleSamples: Array.isArray(record.settleSamples)
                  ? record.settleSamples.length
                  : null,
              }))
            : null,
        }
      : null,
  };
}

async function runBrowser(source, count, runFixture) {
  writeFileSync(path.join(temporary, "fixture.json"), JSON.stringify(runFixture), {
    mode: 0o644,
  });
  return Promise.all(
    Array.from({ length: count }, async () => {
      const args = [
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--property=MemoryMax=1G",
        "--property=TasksMax=128",
        "--property=RuntimeMaxSec=60",
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/bin",
        "/bin",
        "--dir",
        "/etc",
        "--ro-bind",
        path.join(temporary, "hosts"),
        "/etc/hosts",
        "--ro-bind",
        path.join(temporary, "nsswitch.conf"),
        "/etc/nsswitch.conf",
        "--ro-bind",
        "/etc/alternatives",
        "/etc/alternatives",
        "--ro-bind",
        "/etc/fonts",
        "/etc/fonts",
        "--ro-bind",
        "/etc/passwd",
        "/etc/passwd",
        "--ro-bind",
        "/etc/group",
        "/etc/group",
        "--ro-bind",
        source,
        "/work",
        "--ro-bind",
        path.join(temporary, "probe.py"),
        "/probe.py",
        "--ro-bind",
        path.join(temporary, "actions.js"),
        "/actions.js",
        "--ro-bind",
        path.join(temporary, "fixture.json"),
        "/fixture.json",
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
        "/usr/bin:/bin",
        "--setenv",
        "PYTHONDONTWRITEBYTECODE",
        "1",
        "--setenv",
        "TZ",
        "UTC",
        "--setenv",
        "LIBGL_ALWAYS_SOFTWARE",
        "1",
        "--setenv",
        "WEBKIT_DISABLE_DMABUF_RENDERER",
        "1",
        "--setenv",
        "XDG_CACHE_HOME",
        "/tmp/cache",
        "--setenv",
        "XDG_DATA_HOME",
        "/tmp/data",
        "--uid",
        "65534",
        "--gid",
        "65534",
        "--",
        "xvfb-run",
        "-a",
        "-s",
        "-screen 0 1280x1800x24",
        "dbus-run-session",
        "--",
        "/usr/bin/python3",
        "-B",
        "/probe.py",
      ];
      let exitCode;
      let stdout;
      let stderr;
      let errorMessage;
      try {
        const result = await execFileAsync("systemd-run", args, {
          encoding: "utf8",
          timeout: 65_000,
          maxBuffer: 4 * 1024 * 1024,
          env: { PATH: "/usr/sbin:/usr/bin:/bin" },
        });
        exitCode = 0;
        stdout = result.stdout;
        stderr = result.stderr;
        errorMessage = null;
      } catch (error) {
        exitCode = Number.isInteger(error.code) ? error.code : null;
        stdout = typeof error.stdout === "string" ? error.stdout : "";
        stderr = typeof error.stderr === "string" ? error.stderr : "";
        errorMessage = error.message;
      }
      let parsed;
      try {
        const prefix = "SITECMD_FMD_OBSERVATIONS ";
        const lines = stdout.split("\n").filter((line) => line.startsWith(prefix));
        if (lines.length !== 1) throw new Error("Expected one FMD controller result");
        parsed = JSON.parse(lines[0].slice(prefix.length));
      } catch {
        parsed = null;
      }
      return { exitCode, stderr, error: errorMessage, result: parsed };
    }),
  );
}

function validMarkerFrame(frame, pixels, { requireHeadHashes = false } = {}) {
  const hash = (value) => /^[a-f0-9]{64}$/.test(value ?? "");
  return (
    Array.isArray(frame.markerBoxObservations) &&
    Array.isArray(frame.markerBodyCrops) &&
    frame.markerBodyCrops.every((crop) => hash(crop.sha256) && pixels[crop.sha256]) &&
    Array.isArray(frame.markerBodyMaskGeometry) &&
    frame.markerBodyMaskGeometry.length === frame.markerBodyCrops.length &&
    Array.isArray(frame.markerBodyWithoutSiblingPaintCrops) &&
    frame.markerBodyWithoutSiblingPaintCrops.length === frame.markerBodyCrops.length &&
    frame.markerBodyWithoutSiblingPaintCrops.every(
      (crop) => crop === null || (hash(crop.sha256) && pixels[crop.sha256]),
    ) &&
    typeof frame.markerGeometryStable === "boolean" &&
    Boolean(frame.markerSiblingPaintComparison) &&
    Array.isArray(frame.markerHeadCrops) &&
    (!requireHeadHashes || frame.markerHeadCrops.every((crop) => hash(crop.sha256)))
  );
}

function buildOracle(referenceRuns, detailsRuns) {
  if (!referenceRuns.every(isValidFmdReferenceRun) || !detailsRuns.every(isValidFmdReferenceRun)) {
    const failures = [
      ...referenceRuns.map((run, index) => ({ run, source: "reference", index })),
      ...detailsRuns.map((run, index) => ({ run, source: "details-reference", index })),
    ]
      .filter(({ run }) => !isValidFmdReferenceRun(run))
      .map(({ run, source, index }) => ({
        source,
        index,
        exitCode: run.exitCode,
        error: run.error,
        stderr: run.stderr.slice(-1_000),
        passed: run.result?.passed,
        setupError: run.result?.setupError,
        checks: run.result?.checks?.length,
        failedChecks: run.result?.checks
          ?.filter((check) => !check.passed)
          .map((check) => check.name),
        observations: run.result?.observations?.map((observation) => ({
          provider: observation.provider,
          battery: observation.battery,
          deviceId: observation.deviceId,
          date: observation.date,
          time: observation.time,
          center: observation.center,
          zoom: observation.zoom,
          markers: observation.markerPoints?.length,
          polylines: observation.polylines,
        })),
        locationRequests: run.result?.requests
          ?.filter((request) => request.path === "/api/v1/location")
          .map((request) => request.data?.Data),
      }));
    throw new Error(`FMD render references failed: ${JSON.stringify(failures)}`);
  }
  const expectedRenderFrames = Array.from({ length: 10 }, (_value, index) => [
    ...new Map(
      referenceRuns
        .map((run) => run.result.observations[index].renderFrame)
        .map((frame) => [JSON.stringify(frame), frame]),
    ).values(),
  ]);
  const detailsPool = [...referenceRuns, ...detailsRuns];
  const expectedDetailsFrames = detailsReferencePositions.map((positions) => [
    ...new Map(
      positions
        .flatMap((position) =>
          detailsPool.map((run) => run.result.observations[position].renderFrame),
        )
        .map((frame) => [frame.detailsPixelsSha256, frame]),
    ).values(),
  ]);
  const expectedTransitionFrames = Array.from({ length: 10 }, (_value, index) =>
    referenceRuns.flatMap((run) => [
      ...run.result.pendingActionSamples[index].samples,
      ...run.result.earlyRenderSamples[index].samples,
      ...run.result.earlyRenderSamples[index].settleSamples,
    ]),
  );
  const expectedMarkerBodyPixels = Object.create(null);
  for (const run of referenceRuns) {
    for (const [sha256, pixels] of Object.entries(run.result.markerBodyPixels ?? {})) {
      if (
        expectedMarkerBodyPixels[sha256] !== undefined &&
        expectedMarkerBodyPixels[sha256] !== pixels
      ) {
        throw new Error("FMD marker reference pixels conflict");
      }
      expectedMarkerBodyPixels[sha256] = pixels;
    }
  }
  if (
    Object.keys(expectedMarkerBodyPixels).length === 0 ||
    !expectedTransitionFrames.every(
      (frames) =>
        frames.length >= 21 &&
        frames.every(
          (frame) => !frame.mapVisual || validMarkerFrame(frame, expectedMarkerBodyPixels),
        ),
    ) ||
    !expectedTransitionFrames.every((frames) =>
      frames.every(
        (frame) =>
          Array.isArray(frame.markerBodyUnobscured) &&
          frame.markerBodyUnobscured.length === frame.markerBodyCrops.length &&
          frame.markerBodyUnobscured.every((value) => typeof value === "boolean"),
      ),
    ) ||
    !detailsRenderIndexes.every((index) =>
      expectedRenderFrames[index].every(
        (frame) => frame.width === 1280 && frame.height === 1600 && frame.channels === 3,
      ),
    ) ||
    !expectedRenderFrames.every((frames) =>
      frames.every(
        (frame) =>
          JSON.stringify(frame.detailsBox) === JSON.stringify(frames[0].detailsBox) &&
          JSON.stringify(frame.mapBox) === JSON.stringify(frames[0].mapBox),
      ),
    ) ||
    !expectedDetailsFrames.every((frames) =>
      frames.every((frame) => /^[a-f0-9]{64}$/.test(frame.detailsPixelsSha256)),
    ) ||
    !expectedRenderFrames
      .slice(1, 8)
      .every((frames) =>
        frames.every(
          (frame) =>
            /^[a-f0-9]{64}$/.test(frame.activeMarkerCrop?.sha256 ?? "") &&
            Array.isArray(frame.visibleMarkerCrops) &&
            frame.visibleMarkerCrops.length >= 1 &&
            frame.visibleMarkerCrops.every((crop) => /^[a-f0-9]{64}$/.test(crop.sha256)),
        ),
      ) ||
    !expectedRenderFrames.every((frames) =>
      frames.every(
        (frame) =>
          validMarkerFrame(frame, expectedMarkerBodyPixels, { requireHeadHashes: true }) &&
          Array.isArray(frame.markerBodyUnobscured) &&
          frame.markerBodyUnobscured.length === frame.markerBodyCrops.length &&
          frame.markerBodyUnobscured.every((value) => typeof value === "boolean"),
      ),
    )
  ) {
    throw new Error("FMD visual reference oracle is incomplete");
  }
  return {
    expectedRenderFrames,
    expectedDetailsFrames,
    expectedTransitionFrames,
    expectedMarkerBodyPixels,
  };
}

async function captureReferences(source, runFixture) {
  const initial = await runBrowser(source, 3, runFixture);
  return stabilizeFmdReferenceRuns(initial, async () => {
    const [retry] = await runBrowser(source, 1, runFixture);
    return retry;
  });
}

async function main() {
  writeFileSync(
    path.join(temporary, "probe.py"),
    readFileSync(path.join(supportDirectory, "replacement-fmd-probe.py")),
    { mode: 0o644 },
  );
  writeFileSync(
    path.join(temporary, "actions.js"),
    readFileSync(path.join(supportDirectory, "replacement-fmd-actions.js")),
    { mode: 0o644 },
  );
  writeFileSync(path.join(temporary, "hosts"), "127.0.0.1 localhost\n", { mode: 0o644 });
  writeFileSync(path.join(temporary, "nsswitch.conf"), "hosts: files\n", { mode: 0o644 });
  const referenceCapture = await captureReferences(
    path.join(runtime.reference.directory, "reference"),
    { ...fixture, renderMode: "capture" },
  );
  const detailsCapture = await captureReferences(
    path.join(runtime.reference.directory, "details-reference"),
    { ...fixture, renderMode: "capture" },
  );
  const referenceRuns = referenceCapture.runs;
  const detailsRuns = detailsCapture.runs;
  const oracle = buildOracle(referenceRuns, detailsRuns);
  const candidateRuns = await runBrowser(candidate, 1, {
    ...fixture,
    renderMode: "compare",
    ...oracle,
    detailsRenderIndexes,
    mapRenderIndexes,
  });
  verifyFmdBrowserRuntime(runtime);
  process.stdout.write(
    JSON.stringify({
      candidate: compactRun(candidateRuns[0]),
      references: {
        primary: referenceRuns.map(compactRun),
        details: detailsRuns.map(compactRun),
        retries: {
          primary: referenceCapture.retries.map(({ index, initial, retry }) => ({
            index,
            initial: compactRun(initial),
            retry: compactRun(retry),
          })),
          details: detailsCapture.retries.map(({ index, initial, retry }) => ({
            index,
            initial: compactRun(initial),
            retry: compactRun(retry),
          })),
        },
        fixtureSha256: digest(fixture),
        transitionSha256: createHash("sha256")
          .update(JSON.stringify(oracle.expectedTransitionFrames))
          .digest("hex"),
      },
    }),
  );
}

try {
  await main();
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
