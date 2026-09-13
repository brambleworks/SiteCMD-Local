import { useState, useCallback, useEffect, useRef } from "react";
import {
  cancelScan as cancelScanCommand,
  runScanExecution as runScanExecutionCommand,
} from "@/lib/commands";
import { getCodeScanDetail } from "@/lib/scan-execution-adapters";
import { createScanActionKey } from "@/lib/scan-action-key";
import type { UnlistenFn } from "@tauri-apps/api/event";
import type {
  CheckResult,
  CodeScanResult,
  RunScanExecutionRequest,
  RunScanExecutionResult,
  ScanCategory,
  ScanIssueChanges,
  ScanResult,
  ScanTrigger,
  ScanType,
  ScheduledScanType,
} from "@/lib/types";
import { normalizeCodeScanResult } from "@/lib/code-scan-result-normalize";
import { recordWorkflowHealthEvent } from "@/lib/observability";
import { errorMessage } from "@/lib/error-message";
import { recordPerformanceMetric } from "@/lib/performance-metrics";
import {
  buildCodeScanTelemetryMeta,
  buildScanFailureTelemetryMeta,
  buildWebScanTelemetryMeta,
} from "@/lib/scan-telemetry";
import { safeListen } from "@/lib/tauri-events";
import { useTauriEvent } from "@/hooks/useTauriEvent";
import { asWebScanFocus } from "@/lib/scan-progress-model";
import {
  beginScanRun,
  publishMultiScanProgress,
  publishScanProgress,
  resetScanProgress,
} from "@/lib/scan-progress-store";

// Prevent request ID reuse across webview reloads.
const SCAN_REQUEST_ID_STORAGE_KEY = "sitecmd_scan_request_id_v1";
// Stay below Rust's disjoint server-allocated id range.
const SCAN_REQUEST_ID_CEILING = 4_000_000_000;

// Draw and redraw rather than fold with a modulo. A modulo maps the 294,967,296
// draws above the ceiling back onto the bottom of the range, which would make
// those ids twice as likely as the rest and cluster collisions where two
// webviews are most likely to start at once.
export function randomScanRequestId(): number {
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    if (buffer[0] < SCAN_REQUEST_ID_CEILING) return buffer[0];
  }
}

function readPersistedScanRequestId(): number {
  try {
    const raw = sessionStorage.getItem(SCAN_REQUEST_ID_STORAGE_KEY);
    const parsed = raw === null ? 0 : Number(raw);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
  } catch {
    return randomScanRequestId();
  }
}

let nextScanRequestId = readPersistedScanRequestId();

function mintScanRequestId(): number {
  nextScanRequestId += 1;
  try {
    sessionStorage.setItem(SCAN_REQUEST_ID_STORAGE_KEY, String(nextScanRequestId));
  } catch {
    // The module counter remains monotonic for this load.
  }
  return nextScanRequestId;
}

// Represents cancellation or supersession before native dispatch.
const SCAN_ABANDONED = "Scan cancelled before it started";

const PROGRESS_RENDER_INTERVAL_MS = 100;
const CODE_SCAN_COMPLETION_PAINT_MS = 1_200;
const MIN_CODE_SCAN_DISPLAY_MS = 1_600;

export type ScanState = "idle" | "scanning" | "complete" | "error";
type ScanRunOutcome<T = undefined> = { ok: true; result: T } | { ok: false; error: string };

export interface ScanProgressEvent {
  check_id: string;
  category: ScanCategory;
  status: "running" | "complete" | "skipped" | "error";
  results_count: number;
  checks_done: number;
  checks_total: number;
}

export interface MultiScanProgressEvent {
  page_index: number;
  page_count: number;
  current_url: string;
  page_status: "scanning" | "complete" | "error" | "cancelled";
  session_id: number;
}

export interface MultiScanResult {
  sessionId: number;
  totalPages: number;
  completedPages: number;
  overallScore: number;
  durationMs: number;
  incompleteDetail: string | null;
  /** Active issue groups added, or null without a persisted project scope. */
  newIssueCount: number | null;
  /** Unique active issue groups removed by this session. */
  resolvedIssueCount: number | null;
  pageResults: {
    url: string;
    score: number;
    issuesCount: number;
    issuesCritical: number;
    issuesHigh: number;
    issuesMedium: number;
    issuesLow: number;
    durationMs: number;
    scanId: number;
  }[];
  /** Cross-page findings also persisted as `site_scan` work items. */
  siteIssues: CheckResult[];
}

interface ScanOptions {
  enabledCategories?: string[];
  timeoutSecs?: number;
  axeEnabled?: boolean;
  scanType?: string;
  retention?: number;
  environmentUrl?: string;
  environmentId?: number | null;
  projectId?: number | null;
  trigger?: ScanTrigger;
  idempotencyKey?: string;
}

interface CodeScanOptions {
  preservePreviousResults?: boolean;
  // Maximum persisted runs per project.
  retention?: number;
}

interface UseScanReturn {
  state: ScanState;
  currentScanType: ScheduledScanType | null;
  currentExecutionMode: RunScanExecutionRequest["requestedMode"] | null;
  result: ScanResult | null;
  codeResult: CodeScanResult | null;
  /** Whether the displayed code report came from a background execution. */
  codeResultFromBackground: boolean;
  multiResult: MultiScanResult | null;
  issueChanges: ScanIssueChanges | null;
  executionIncompleteDetail: string | null;
  error: string | null;
  scan: (url: string, options?: ScanOptions) => Promise<ScanRunOutcome<ScanResult>>;
  scanExecution: (
    request: Omit<RunScanExecutionRequest, "scanRequestId">,
  ) => Promise<ScanRunOutcome<RunScanExecutionResult>>;
  scanCode: (
    projectId: number,
    projectPath: string,
    environmentUrl?: string | null,
    options?: CodeScanOptions,
  ) => Promise<ScanRunOutcome<CodeScanResult>>;
  cancelScan: () => Promise<void>;
  reset: () => void;
}

type ProgressThrottle<T> = {
  lastPublishedAt: number;
  lastPublishedKey: string | null;
  pending: T | null;
  timerId: number | null;
};

function createProgressThrottle<T>(): ProgressThrottle<T> {
  return {
    lastPublishedAt: 0,
    lastPublishedKey: null,
    pending: null,
    timerId: null,
  };
}

function scanProgressKey(progress: ScanProgressEvent): string {
  return [
    progress.check_id,
    progress.category,
    progress.status,
    progress.results_count,
    progress.checks_done,
    progress.checks_total,
  ].join(":");
}

function multiProgressKey(progress: MultiScanProgressEvent): string {
  return [
    progress.session_id,
    progress.page_index,
    progress.page_count,
    progress.current_url,
    progress.page_status,
  ].join(":");
}

function sleep(ms: number) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

async function hydratePersistedCodeScanDetail(result: CodeScanResult): Promise<CodeScanResult> {
  if (result.id <= 0 || result.issues.length >= result.issueCount) return result;

  try {
    const persisted = await getCodeScanDetail({
      scanId: result.id,
    });
    if (!persisted) return result;
    return normalizeCodeScanResult(persisted);
  } catch {
    return result;
  }
}

function executionFailureMessage(result: RunScanExecutionResult): string {
  return (
    result.execution.failureSummary ??
    result.execution.webDetail ??
    result.execution.codeDetail ??
    "Scan execution failed"
  );
}

function getExecutionIncompleteDetail(result: RunScanExecutionResult): string | null {
  const { execution } = result;
  if (execution.status !== "partial") return null;

  const componentDetail = (
    label: string,
    status: typeof execution.webStatus,
    detail: string | null,
  ) => {
    if (detail) return `${label}: ${detail}`;
    if (status === "failed" || status === "cancelled") return `${label}: ${status}`;
    return null;
  };
  const details = [
    componentDetail("Web Scan", execution.webStatus, execution.webDetail),
    componentDetail("Code Scan", execution.codeStatus, execution.codeDetail),
  ].filter((detail): detail is string => detail != null);

  return (
    details.join(" ") ||
    execution.failureSummary ||
    "Scan completed without all requested coverage."
  );
}

/** Reset both request-id stores for deterministic tests. */
export function __resetScanRequestIdsForTests() {
  nextScanRequestId = 0;
  try {
    sessionStorage.removeItem(SCAN_REQUEST_ID_STORAGE_KEY);
  } catch {
    // Storage is optional in tests.
  }
}

/** Simulate a fresh module load for tests. */
export function __reloadScanRequestIdSeedForTests() {
  nextScanRequestId = readPersistedScanRequestId();
}

export function useScan(): UseScanReturn {
  const [state, setState] = useState<ScanState>("idle");
  const [currentScanType, setCurrentScanType] = useState<ScheduledScanType | null>(null);
  const [currentExecutionMode, setCurrentExecutionMode] = useState<
    RunScanExecutionRequest["requestedMode"] | null
  >(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [codeResult, setCodeResult] = useState<CodeScanResult | null>(null);
  // Distinguish foreground reports from background refreshes without parallel state.
  const [foregroundCodeRunId, setForegroundCodeRunId] = useState<number | null>(null);
  const [multiResult, setMultiResult] = useState<MultiScanResult | null>(null);
  const [issueChanges, setIssueChanges] = useState<ScanIssueChanges | null>(null);
  const [executionIncompleteDetail, setExecutionIncompleteDetail] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // External progress state avoids repainting the app shell on every tick.
  const unlistenRef = useRef<UnlistenFn | null>(null);
  const unlistenMultiRef = useRef<UnlistenFn | null>(null);
  const scanEpochRef = useRef(0);
  const activeScanRequestIdRef = useRef<number | null>(null);
  const progressThrottleRef = useRef(createProgressThrottle<ScanProgressEvent>());
  const multiProgressThrottleRef = useRef(createProgressThrottle<MultiScanProgressEvent>());

  const clearProgressThrottle = useCallback(<T>(throttle: ProgressThrottle<T>) => {
    if (throttle.timerId != null) {
      window.clearTimeout(throttle.timerId);
    }
    throttle.lastPublishedAt = 0;
    throttle.lastPublishedKey = null;
    throttle.pending = null;
    throttle.timerId = null;
  }, []);

  const publishThrottledProgress = useCallback(
    <T>(
      payload: T,
      throttle: ProgressThrottle<T>,
      keyForPayload: (value: T) => string,
      publish: (value: T) => void,
    ) => {
      const key = keyForPayload(payload);
      if (key === throttle.lastPublishedKey) return;

      const now = performance.now();
      const elapsed = now - throttle.lastPublishedAt;

      const publishNow = (value: T) => {
        if (throttle.timerId != null) {
          window.clearTimeout(throttle.timerId);
        }
        throttle.timerId = null;
        throttle.pending = null;
        throttle.lastPublishedAt = performance.now();
        throttle.lastPublishedKey = keyForPayload(value);
        publish(value);
      };

      if (elapsed >= PROGRESS_RENDER_INTERVAL_MS) {
        publishNow(payload);
        return;
      }

      throttle.pending = payload;
      if (throttle.timerId != null) return;

      throttle.timerId = window.setTimeout(() => {
        const pending = throttle.pending;
        if (pending == null) {
          throttle.timerId = null;
          return;
        }
        publishNow(pending);
      }, PROGRESS_RENDER_INTERVAL_MS - elapsed);
    },
    [],
  );

  const clearProgressTimers = useCallback(() => {
    clearProgressThrottle(progressThrottleRef.current);
    clearProgressThrottle(multiProgressThrottleRef.current);
  }, [clearProgressThrottle]);

  const clearListeners = useCallback(() => {
    if (unlistenRef.current) {
      unlistenRef.current();
      unlistenRef.current = null;
    }
    if (unlistenMultiRef.current) {
      unlistenMultiRef.current();
      unlistenMultiRef.current = null;
    }
    clearProgressTimers();
  }, [clearProgressTimers]);

  useEffect(() => {
    return clearListeners;
  }, [clearListeners]);

  // Keep the background listener subscribed while exposing current state.
  const stateRef = useRef<ScanState>("idle");
  const codeResultRef = useRef<CodeScanResult | null>(null);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);
  useEffect(() => {
    codeResultRef.current = codeResult;
  }, [codeResult]);

  // Refresh project-wide code results after background executions settle.
  useTauriEvent("scan-execution-completed", (payload) => {
    const displayed = codeResultRef.current;
    if (payload.codeRunId == null || payload.projectId == null) return;
    if (stateRef.current === "scanning") return;
    if (!displayed || displayed.projectId !== payload.projectId) return;
    if (displayed.id === payload.codeRunId) return;
    void getCodeScanDetail({
      scanId: payload.codeRunId,
    })
      .then((persisted) => {
        if (!persisted) return;
        if (stateRef.current === "scanning") return;
        if (codeResultRef.current?.projectId !== payload.projectId) return;
        setCodeResult(normalizeCodeScanResult(persisted));
      })
      .catch(() => {
        // Best effort.
      });
  });

  const scan = useCallback(
    async (url: string, options?: ScanOptions) => {
      const epoch = ++scanEpochRef.current;
      const scanRequestId = mintScanRequestId();
      activeScanRequestIdRef.current = scanRequestId;
      setCurrentScanType((options?.scanType as ScanType | undefined) ?? "health");
      setCurrentExecutionMode("web");
      setState("scanning");
      setResult(null);
      setCodeResult(null);
      setMultiResult(null);
      setIssueChanges(null);
      setExecutionIncompleteDetail(null);
      setError(null);
      beginScanRun({ web: asWebScanFocus(options?.scanType), code: false });
      recordWorkflowHealthEvent("run_scan", "started", {
        kind: options?.scanType ?? "health",
        mode: "single",
      });

      try {
        clearListeners();
        unlistenRef.current = await safeListen<ScanProgressEvent>("scan-progress", (event) => {
          if (scanEpochRef.current === epoch) {
            publishThrottledProgress(
              event.payload,
              progressThrottleRef.current,
              scanProgressKey,
              publishScanProgress,
            );
          }
        });
      } catch {
        // Progress reporting is best effort.
      }

      try {
        // Do not dispatch after cancellation or supersession during listener setup.
        if (scanEpochRef.current !== epoch) {
          return { ok: false, error: SCAN_ABANDONED } as const;
        }
        const execution = await runScanExecutionCommand({
          request: {
            projectId: options?.projectId ?? null,
            environmentId: options?.environmentId ?? null,
            environmentUrl: options?.environmentUrl ?? url,
            requestedMode: "web",
            webFocus: (options?.scanType as ScanType | undefined) ?? "health",
            urls: [url],
            enabledCategories: options?.enabledCategories ?? null,
            timeoutSecs: options?.timeoutSecs ?? null,
            axeEnabled: options?.axeEnabled ?? null,
            projectPath: null,
            inspectLocalDatabases: false,
            scanRequestId,
            retention: options?.retention ?? null,
            trigger: options?.trigger ?? "manual",
            idempotencyKey:
              options?.idempotencyKey ?? createScanActionKey(options?.trigger ?? "manual-web"),
          },
        });
        if (!execution.webResult) throw new Error(executionFailureMessage(execution));
        const scanResult = execution.webResult;

        if (scanEpochRef.current === epoch) {
          setResult(scanResult);
          setIssueChanges(execution.issueChanges);
          setExecutionIncompleteDetail(getExecutionIncompleteDetail(execution));
          setState("complete");
        }
        recordPerformanceMetric("scan.duration_ms", scanResult.durationMs, {
          kind: options?.scanType ?? "health",
          mode: "single",
          issueCount: scanResult.issues.length,
        });
        recordWorkflowHealthEvent("run_scan", "succeeded", {
          kind: options?.scanType ?? "health",
          mode: "single",
          durationMs: scanResult.durationMs,
          ...buildWebScanTelemetryMeta(scanResult, options?.scanType ?? "health", "succeeded"),
        });

        return { ok: true, result: scanResult } as const;
      } catch (err) {
        const message = errorMessage(err);
        if (scanEpochRef.current === epoch) {
          setError(message);
          setState("error");
        }
        recordWorkflowHealthEvent("run_scan", "failed", {
          kind: options?.scanType ?? "health",
          mode: "single",
          ...buildScanFailureTelemetryMeta({
            scanMode: "web",
            scanType: options?.scanType ?? "health",
          }),
        });
        return { ok: false, error: message } as const;
      } finally {
        if (activeScanRequestIdRef.current === scanRequestId) {
          activeScanRequestIdRef.current = null;
        }
        if (scanEpochRef.current === epoch) {
          publishScanProgress(null);
          clearListeners();
        }
      }
    },
    [clearListeners, publishThrottledProgress],
  );

  const scanExecution = useCallback(
    async (request: Omit<RunScanExecutionRequest, "scanRequestId">) => {
      const epoch = ++scanEpochRef.current;
      const scanRequestId = mintScanRequestId();
      activeScanRequestIdRef.current = scanRequestId;
      setCurrentScanType(
        request.requestedMode === "web" ? (request.webFocus ?? "health") : request.requestedMode,
      );
      setCurrentExecutionMode(request.requestedMode);
      setState("scanning");
      setResult(null);
      setCodeResult(null);
      setMultiResult(null);
      setIssueChanges(null);
      setExecutionIncompleteDetail(null);
      setError(null);
      beginScanRun({
        web:
          request.requestedMode !== "code" && request.urls.length > 0
            ? asWebScanFocus(request.webFocus)
            : null,
        code: request.requestedMode !== "web" && Boolean(request.projectPath),
        pageCount: request.urls.length,
      });
      clearListeners();
      recordWorkflowHealthEvent("run_scan", "started", {
        kind: request.requestedMode,
        mode: "execution",
      });

      try {
        unlistenRef.current = await safeListen<ScanProgressEvent>("scan-progress", (event) => {
          if (scanEpochRef.current === epoch) {
            publishThrottledProgress(
              event.payload,
              progressThrottleRef.current,
              scanProgressKey,
              publishScanProgress,
            );
          }
        });
        if (request.urls.length > 1) {
          unlistenMultiRef.current = await safeListen<MultiScanProgressEvent>(
            "multi-scan-progress",
            (event) => {
              if (scanEpochRef.current === epoch) {
                publishThrottledProgress(
                  event.payload,
                  multiProgressThrottleRef.current,
                  multiProgressKey,
                  publishMultiScanProgress,
                );
              }
            },
          );
        }
      } catch {
        // Progress reporting is best effort.
      }

      try {
        // Do not dispatch after cancellation or supersession during listener setup.
        if (scanEpochRef.current !== epoch) {
          return { ok: false, error: SCAN_ABANDONED } as const;
        }
        const rawExecution = await runScanExecutionCommand({
          request: { ...request, scanRequestId },
        });
        const nextCodeResult = rawExecution.codeResult
          ? await hydratePersistedCodeScanDetail(normalizeCodeScanResult(rawExecution.codeResult))
          : null;
        const executionResult: RunScanExecutionResult = {
          ...rawExecution,
          codeResult: nextCodeResult,
        };
        const failed =
          executionResult.execution.status === "failed" ||
          executionResult.execution.status === "cancelled";

        if (scanEpochRef.current === epoch) {
          setResult(executionResult.webResult);
          setMultiResult(executionResult.multiResult);
          setCodeResult(nextCodeResult);
          setIssueChanges(executionResult.issueChanges);
          setForegroundCodeRunId(nextCodeResult?.id ?? null);
          setExecutionIncompleteDetail(getExecutionIncompleteDetail(executionResult));
          setError(failed ? executionFailureMessage(executionResult) : null);
          setState(failed ? "error" : "complete");
        }

        recordWorkflowHealthEvent("run_scan", failed ? "failed" : "succeeded", {
          kind: request.requestedMode,
          mode: "execution",
          executionStatus: executionResult.execution.status,
          reused: executionResult.reused,
        });
        if (failed) {
          return { ok: false, error: executionFailureMessage(executionResult) } as const;
        }
        return { ok: true, result: executionResult } as const;
      } catch (err) {
        const message = errorMessage(err);
        if (scanEpochRef.current === epoch) {
          setError(message);
          setState("error");
        }
        recordWorkflowHealthEvent("run_scan", "failed", {
          kind: request.requestedMode,
          mode: "execution",
        });
        return { ok: false, error: message } as const;
      } finally {
        if (activeScanRequestIdRef.current === scanRequestId) {
          activeScanRequestIdRef.current = null;
        }
        if (scanEpochRef.current === epoch) {
          resetScanProgress();
          clearListeners();
        }
      }
    },
    [clearListeners, publishThrottledProgress],
  );

  const scanCode = useCallback(
    async (
      projectId: number,
      projectPath: string,
      environmentUrl?: string | null,
      options?: CodeScanOptions,
    ) => {
      const epoch = ++scanEpochRef.current;
      const scanRequestId = mintScanRequestId();
      activeScanRequestIdRef.current = scanRequestId;
      setCurrentScanType("code");
      setCurrentExecutionMode("code");
      setState("scanning");
      if (!options?.preservePreviousResults) {
        setResult(null);
        setMultiResult(null);
      }
      setCodeResult(null);
      setIssueChanges(null);
      setExecutionIncompleteDetail(null);
      setError(null);
      beginScanRun({ web: null, code: true });
      clearListeners();
      const codeScanStartedAt = performance.now();
      recordWorkflowHealthEvent("run_scan", "started", {
        kind: "code",
        mode: "code",
      });

      try {
        unlistenRef.current = await safeListen<ScanProgressEvent>("scan-progress", (event) => {
          if (scanEpochRef.current === epoch && event.payload.check_id.startsWith("code-scan.")) {
            publishThrottledProgress(
              event.payload,
              progressThrottleRef.current,
              scanProgressKey,
              publishScanProgress,
            );
          }
        });
      } catch {
        // Progress reporting is best effort.
      }

      try {
        // Do not dispatch after cancellation or supersession during listener setup.
        if (scanEpochRef.current !== epoch) {
          return { ok: false, error: SCAN_ABANDONED } as const;
        }
        const execution = await runScanExecutionCommand({
          request: {
            projectId,
            environmentId: null,
            environmentUrl: environmentUrl ?? null,
            requestedMode: "code",
            webFocus: null,
            urls: [],
            enabledCategories: null,
            timeoutSecs: null,
            axeEnabled: null,
            projectPath,
            inspectLocalDatabases: false,
            scanRequestId,
            retention: options?.retention ?? null,
            trigger: "manual",
            idempotencyKey: createScanActionKey("manual-code"),
          },
        });
        if (!execution.codeResult) throw new Error(executionFailureMessage(execution));
        const rawCodeResult = execution.codeResult;
        const nextCodeResult = await hydratePersistedCodeScanDetail(
          normalizeCodeScanResult(rawCodeResult),
        );

        if (scanEpochRef.current === epoch) {
          clearProgressThrottle(progressThrottleRef.current);
          publishScanProgress({
            check_id: "code-scan.complete",
            category: "config",
            status: "complete",
            results_count: nextCodeResult.issueCount,
            checks_done: 100,
            checks_total: 100,
          });
          const elapsedMs = performance.now() - codeScanStartedAt;
          await sleep(
            Math.max(CODE_SCAN_COMPLETION_PAINT_MS, MIN_CODE_SCAN_DISPLAY_MS - elapsedMs),
          );
        }

        if (scanEpochRef.current === epoch) {
          setCodeResult(nextCodeResult);
          setIssueChanges(execution.issueChanges);
          setForegroundCodeRunId(nextCodeResult.id);
          setExecutionIncompleteDetail(getExecutionIncompleteDetail(execution));
          setState("complete");
        }
        recordPerformanceMetric("scan.duration_ms", nextCodeResult.durationMs, {
          kind: "code",
          mode: "code",
          issueCount: nextCodeResult.issueCount,
        });
        recordWorkflowHealthEvent("run_scan", "succeeded", {
          kind: "code",
          mode: "code",
          durationMs: nextCodeResult.durationMs,
          ...buildCodeScanTelemetryMeta(nextCodeResult, "succeeded"),
        });
        return { ok: true, result: nextCodeResult } as const;
      } catch (err) {
        const message = errorMessage(err);
        if (scanEpochRef.current === epoch) {
          setError(message);
          setState("error");
        }
        recordWorkflowHealthEvent("run_scan", "failed", {
          kind: "code",
          mode: "code",
          ...buildScanFailureTelemetryMeta({ scanMode: "code", scanType: "code" }),
        });
        return { ok: false, error: message } as const;
      } finally {
        if (activeScanRequestIdRef.current === scanRequestId) {
          activeScanRequestIdRef.current = null;
        }
        if (scanEpochRef.current === epoch) {
          clearListeners();
        }
      }
    },
    [clearListeners, clearProgressThrottle, publishThrottledProgress],
  );

  const cancelScan = useCallback(async () => {
    const scanRequestId = activeScanRequestIdRef.current;
    // Preserve completed results and errors when no scan is active.
    setState((prev) => (prev === "scanning" ? "idle" : prev));
    if (activeScanRequestIdRef.current == null) {
      return;
    }
    ++scanEpochRef.current;
    activeScanRequestIdRef.current = null;
    setResult(null);
    setCodeResult(null);
    setMultiResult(null);
    setIssueChanges(null);
    setExecutionIncompleteDetail(null);
    setError(null);
    resetScanProgress();
    setCurrentScanType(null);
    setCurrentExecutionMode(null);
    clearListeners();

    try {
      if (scanRequestId != null) {
        await cancelScanCommand({ scanRequestId });
      }
    } catch {
      // The scan may already have finished.
    }
  }, [clearListeners]);

  const reset = useCallback(() => {
    ++scanEpochRef.current;
    activeScanRequestIdRef.current = null;
    setState("idle");
    setResult(null);
    setCodeResult(null);
    setMultiResult(null);
    setIssueChanges(null);
    setExecutionIncompleteDetail(null);
    setError(null);
    resetScanProgress();
    setCurrentScanType(null);
    setCurrentExecutionMode(null);
    clearListeners();
  }, [clearListeners]);

  return {
    state,
    currentScanType,
    currentExecutionMode,
    result,
    codeResult,
    codeResultFromBackground: codeResult !== null && codeResult.id !== foregroundCodeRunId,
    multiResult,
    issueChanges,
    executionIncompleteDetail,
    error,
    scan,
    scanExecution,
    scanCode,
    cancelScan,
    reset,
  };
}
