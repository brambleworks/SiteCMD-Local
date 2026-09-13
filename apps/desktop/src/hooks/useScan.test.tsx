import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { invokeMock, safeListenMock, getCodeScanDetailMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  getCodeScanDetailMock: vi.fn(),
  safeListenMock: vi.fn((_event: string, _handler: (event: { payload: unknown }) => void) =>
    Promise.resolve(() => {}),
  ),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(),
}));

vi.mock("@/lib/tauri-events", () => ({ safeListen: safeListenMock }));
vi.mock("@/lib/scan-execution-adapters", () => ({
  getCodeScanDetail: getCodeScanDetailMock,
}));

import { getScanProgressSnapshot } from "@/lib/scan-progress-store";
import {
  __reloadScanRequestIdSeedForTests,
  __resetScanRequestIdsForTests,
  randomScanRequestId,
  useScan,
} from "@/hooks/useScan";

function codeResult(overrides: Record<string, unknown> = {}) {
  return {
    id: 48,
    projectId: 1,
    environmentUrl: "https://example.com",
    overallScore: 36,
    issueCount: 25,
    criticalCount: 0,
    highCount: 19,
    mediumCount: 6,
    lowCount: 0,
    durationMs: 44834,
    checkedAt: "2026-05-04T17:59:58.616744+00:00",
    framework: "Drupal",
    domainSummaries: [],
    issues: [],
    ...overrides,
  };
}

function executionResult(overrides: Record<string, unknown>) {
  return {
    execution: { id: 17, status: "complete" },
    reused: false,
    webResult: null,
    multiResult: null,
    codeResult: null,
    ...overrides,
  };
}

describe("useScan", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    safeListenMock.mockClear();
    safeListenMock.mockImplementation(() => Promise.resolve(() => {}));
    getCodeScanDetailMock.mockReset();
    // Request ids are module-scoped so they survive a remount; each test still
    // wants a known starting point.
    __resetScanRequestIdsForTests();
    localStorage.clear();
  });

  it("passes scan retention into the web scan command instead of invoking renderer-side pruning", async () => {
    invokeMock.mockResolvedValue(
      executionResult({
        webResult: {
          url: "https://example.com",
          mode: "full",
          scanType: "health",
          overallScore: 92,
          categories: [],
          issues: [],
          detectedStack: null,
          durationMs: 1200,
          timestamp: "2026-05-06T00:00:00Z",
        },
      }),
    );

    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scan("https://example.com", { retention: 25 });
    });

    expect(invokeMock).toHaveBeenCalledWith(
      "run_scan_execution",
      expect.objectContaining({
        request: expect.objectContaining({
          urls: ["https://example.com"],
          retention: 25,
          requestedMode: "web",
        }),
      }),
    );
    expect(invokeMock).not.toHaveBeenCalledWith("auto_prune_url_scans", expect.anything());
  });

  it("retains incomplete execution details with usable web results", async () => {
    invokeMock.mockResolvedValue(
      executionResult({
        execution: {
          id: 17,
          status: "partial",
          webStatus: "complete",
          webDetail: "Browser analysis failed: unavailable",
          codeStatus: null,
          codeDetail: null,
          failureSummary: null,
        },
        webResult: {
          url: "https://example.com",
          mode: "full",
          scanType: "health",
          overallScore: 92,
          categories: [],
          issues: [],
          detectedStack: null,
          durationMs: 1200,
          timestamp: "2026-05-06T00:00:00Z",
        },
      }),
    );

    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scan("https://example.com");
    });

    expect(result.current.state).toBe("complete");
    expect(result.current.currentExecutionMode).toBe("web");
    expect(result.current.executionIncompleteDetail).toBe(
      "Web Scan: Browser analysis failed: unavailable",
    );
  });

  it("a webview reload resumes the id sequence instead of re-minting a used id", async () => {
    invokeMock.mockResolvedValue(executionResult({}));
    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scan("https://example.com", {});
    });
    __reloadScanRequestIdSeedForTests();
    await act(async () => {
      await result.current.scan("https://example.com", {});
    });

    const mintedIds = invokeMock.mock.calls
      .filter(([command]) => command === "run_scan_execution")
      .map(([, args]) => (args as { request: { scanRequestId: number } }).request.scanRequestId);
    expect(mintedIds).toEqual([1, 2]);
  });

  it("a reload with NO storage at all reseeds from the random source, not the clock", async () => {
    // Random fallback seeds avoid deterministic request-id reuse when storage
    // is unavailable across a renderer reload.
    invokeMock.mockResolvedValue(executionResult({}));
    const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });
    const randomValues = vi
      .spyOn(crypto, "getRandomValues")
      .mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
        if (array instanceof Uint32Array) array[0] = 3_735_928_559;
        return array;
      });
    try {
      __reloadScanRequestIdSeedForTests();
      const { result } = renderHook(() => useScan());
      await act(async () => {
        await result.current.scan("https://example.com", {});
      });

      const mintedIds = invokeMock.mock.calls
        .filter(([command]) => command === "run_scan_execution")
        .map(([, args]) => (args as { request: { scanRequestId: number } }).request.scanRequestId);
      expect(mintedIds).toHaveLength(1);
      // Seeded from the random source, not the clock - and below the Rust
      // server allocator's 1 << 32 base.
      expect(mintedIds[0]).toBe((3_735_928_559 % 4_000_000_000) + 1);
      expect(mintedIds[0]).toBeLessThan(2 ** 32);
    } finally {
      getItem.mockRestore();
      setItem.mockRestore();
      randomValues.mockRestore();
    }
  });

  it("passes multi-page retention through one canonical scan execution", async () => {
    invokeMock.mockResolvedValue({
      execution: { id: 17, status: "complete" },
      reused: false,
      webResult: null,
      codeResult: null,
      multiResult: {
        sessionId: 7,
        totalPages: 2,
        completedPages: 2,
        overallScore: 88,
        durationMs: 2400,
        pageResults: [],
        siteIssues: [],
        newIssueCount: 0,
        resolvedIssueCount: 0,
      },
    });

    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scanExecution({
        projectId: 1,
        environmentId: 2,
        environmentUrl: "https://example.com",
        requestedMode: "web",
        webFocus: "health",
        urls: ["https://example.com", "https://example.com/about"],
        enabledCategories: null,
        timeoutSecs: null,
        axeEnabled: false,
        projectPath: null,
        inspectLocalDatabases: false,
        retention: 30,
        trigger: "manual",
        idempotencyKey: "manual:test-multi",
      });
    });

    expect(invokeMock).toHaveBeenCalledWith(
      "run_scan_execution",
      expect.objectContaining({
        request: expect.objectContaining({
          urls: ["https://example.com", "https://example.com/about"],
          environmentUrl: "https://example.com",
          retention: 30,
        }),
      }),
    );
    expect(invokeMock).not.toHaveBeenCalledWith("auto_prune_url_scans", expect.anything());
  });

  it("exposes partial coverage from a unified scan execution", async () => {
    invokeMock.mockResolvedValue(
      executionResult({
        execution: {
          id: 17,
          status: "partial",
          webStatus: "complete",
          webDetail: "2 of 3 selected pages completed.",
          codeStatus: "complete",
          codeDetail: null,
          failureSummary: null,
        },
        multiResult: {
          sessionId: 7,
          totalPages: 3,
          completedPages: 2,
          overallScore: 88,
          durationMs: 2400,
          incompleteDetail: "2 of 3 selected pages completed.",
          pageResults: [],
          siteIssues: [],
          newIssueCount: 0,
          resolvedIssueCount: 0,
        },
      }),
    );

    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scanExecution({
        projectId: 1,
        environmentId: 2,
        environmentUrl: "https://example.com",
        requestedMode: "web",
        webFocus: "health",
        urls: ["https://example.com", "https://example.com/about"],
        enabledCategories: null,
        timeoutSecs: null,
        axeEnabled: false,
        projectPath: null,
        inspectLocalDatabases: false,
        retention: 30,
        trigger: "manual",
        idempotencyKey: "manual:test-partial",
      });
    });

    expect(result.current.executionIncompleteDetail).toBe(
      "Web Scan: 2 of 3 selected pages completed.",
    );
    expect(result.current.currentExecutionMode).toBe("web");
  });

  it("cancels an in-flight unified execution and keeps its late response from reopening", async () => {
    let resolveExecution!: (value: ReturnType<typeof executionResult>) => void;
    const executionPromise = new Promise<ReturnType<typeof executionResult>>((resolve) => {
      resolveExecution = resolve;
    });
    invokeMock.mockImplementation((command: string) => {
      if (command === "run_scan_execution") return executionPromise;
      if (command === "cancel_scan") return Promise.resolve();
      return Promise.resolve(null);
    });

    const { result } = renderHook(() => useScan());
    let runPromise!: ReturnType<typeof result.current.scanExecution>;
    act(() => {
      runPromise = result.current.scanExecution({
        projectId: 1,
        environmentId: 2,
        environmentUrl: "https://example.com",
        requestedMode: "full",
        webFocus: "health",
        urls: ["https://example.com"],
        enabledCategories: null,
        timeoutSecs: null,
        axeEnabled: false,
        projectPath: "/tmp/example",
        inspectLocalDatabases: false,
        retention: 30,
        trigger: "manual",
        idempotencyKey: "manual:test-cancel",
      });
    });

    await waitFor(() => expect(result.current.state).toBe("scanning"));
    await act(async () => {
      await result.current.cancelScan();
    });

    expect(result.current.state).toBe("idle");
    expect(invokeMock).toHaveBeenCalledWith("cancel_scan", { scanRequestId: 1 });

    resolveExecution(executionResult({}));
    await act(async () => {
      await runPromise;
    });
    expect(result.current.state).toBe("idle");
  });

  it("never dispatches a scan the user cancelled while listeners were registering", async () => {
    let releaseListener!: () => void;
    safeListenMock.mockImplementation(
      () =>
        new Promise<() => void>((resolve) => {
          releaseListener = () => resolve(() => {});
        }),
    );
    invokeMock.mockImplementation(() => Promise.resolve(null));

    const { result } = renderHook(() => useScan());
    let runPromise!: ReturnType<typeof result.current.scanExecution>;
    act(() => {
      runPromise = result.current.scanExecution({
        projectId: 1,
        environmentId: 2,
        environmentUrl: "https://example.com",
        requestedMode: "full",
        webFocus: "health",
        urls: ["https://example.com"],
        enabledCategories: null,
        timeoutSecs: null,
        axeEnabled: false,
        projectPath: "/tmp/example",
        inspectLocalDatabases: false,
        retention: 30,
        trigger: "manual",
        idempotencyKey: "manual:test-cancel-before-dispatch",
      });
    });

    await waitFor(() => expect(result.current.state).toBe("scanning"));
    // Cancel lands while listener setup is still pending.
    await act(async () => {
      await result.current.cancelScan();
    });
    releaseListener();

    const outcome = await act(async () => runPromise);
    expect(outcome.ok).toBe(false);
    expect(
      invokeMock.mock.calls.filter(([command]) => command === "run_scan_execution"),
    ).toHaveLength(0);
  });

  it("completes a code scan when the command returns summary fields without issue details", async () => {
    invokeMock.mockResolvedValue(executionResult({ codeResult: codeResult() }));

    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scanCode(1, "/tmp/example-site", "https://example.com");
    });

    expect(result.current.state).toBe("complete");
    expect(result.current.error).toBeNull();
    expect(result.current.codeResult).toMatchObject({
      id: 48,
      projectId: 1,
      overallScore: 36,
      issueCount: 25,
      issues: [],
    });
    expect(getScanProgressSnapshot().progress).toMatchObject({
      check_id: "code-scan.complete",
      checks_done: 100,
      checks_total: 100,
      results_count: 25,
    });
  });

  it("passes scan retention into the code scan command so pruning honors the pref", async () => {
    invokeMock.mockResolvedValue(
      executionResult({
        codeResult: codeResult({ id: 50, overallScore: 90, issueCount: 0, highCount: 0 }),
      }),
    );

    const { result } = renderHook(() => useScan());

    await act(async () => {
      await result.current.scanCode(1, "/tmp/example-site", "https://example.com", {
        retention: 15,
      });
    });

    expect(invokeMock).toHaveBeenCalledWith(
      "run_scan_execution",
      expect.objectContaining({
        request: expect.objectContaining({
          projectId: 1,
          requestedMode: "code",
          retention: 15,
        }),
      }),
    );
  });

  it("hydrates code scan issue details from the persisted DB row before completion", async () => {
    const persisted = codeResult({
      id: 49,
      issueCount: 1,
      highCount: 1,
      mediumCount: 0,
      issues: [
        {
          id: "unsafe-query",
          checkId: "code_scan.unsafe-query",
          category: "security",
          domain: "security",
          severity: "high",
          title: "Unsafe query",
          description: "User input reaches raw SQL.",
          relativePath: "src/db.ts",
          absolutePath: "/tmp/project/src/db.ts",
          line: 12,
          sourceExcerpt: null,
          evidence: null,
          whyNow: null,
          likelyFix: null,
          confidence: "high",
          verifyHint: null,
        },
      ],
    });
    invokeMock.mockResolvedValue(
      executionResult({
        codeResult: codeResult({ id: 49, issueCount: 1, highCount: 1, mediumCount: 0 }),
      }),
    );
    getCodeScanDetailMock.mockResolvedValue(persisted);

    const { result } = renderHook(() => useScan());
    let outcome: Awaited<ReturnType<typeof result.current.scanCode>> | null = null;

    await act(async () => {
      outcome = await result.current.scanCode(1, "/tmp/example-site", "https://example.com");
    });

    expect(getCodeScanDetailMock).toHaveBeenCalledWith({ scanId: 49 });
    expect(result.current.codeResult?.issues).toHaveLength(1);
    expect(outcome).not.toBeNull();
    const completedOutcome = outcome as unknown as
      { ok: true; result: { issues: unknown[] } } | { ok: false; error: string };
    expect(completedOutcome.ok).toBe(true);
    if (completedOutcome.ok) {
      expect(completedOutcome.result.issues).toHaveLength(1);
    }
  });

  it("returns a failed outcome when code scan fails", async () => {
    invokeMock.mockRejectedValue(new Error("Project folder is missing"));

    const { result } = renderHook(() => useScan());
    let outcome: Awaited<ReturnType<typeof result.current.scanCode>> | null = null;

    await act(async () => {
      outcome = await result.current.scanCode(1, "/tmp/missing", "https://example.com");
    });

    expect(outcome).toEqual({ ok: false, error: "Project folder is missing" });
    expect(result.current.state).toBe("error");
    expect(result.current.error).toBe("Project folder is missing");
  });

  it("refreshes the displayed code report when a background scan for the same project completes", async () => {
    const baseScan = {
      projectId: 1,
      environmentUrl: "https://example.com",
      overallScore: 80,
      issueCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      durationMs: 1000,
      checkedAt: "2026-06-12T00:00:00Z",
      framework: null,
      domainSummaries: [],
      issues: [],
    };
    invokeMock.mockResolvedValue(executionResult({ codeResult: { ...baseScan, id: 48 } }));
    getCodeScanDetailMock.mockImplementation(({ scanId }: { scanId: number }) =>
      Promise.resolve(scanId === 49 ? { ...baseScan, id: 49 } : null),
    );

    const { result } = renderHook(() => useScan());
    await act(async () => {
      await result.current.scanCode(1, "/tmp/project", "https://example.com");
    });
    expect(result.current.codeResult?.id).toBe(48);

    const completionListener = safeListenMock.mock.calls.find(
      ([event]) => event === "scan-execution-completed",
    );
    expect(completionListener).toBeTruthy();

    // A background scan for the same project replaces the displayed report.
    await act(async () => {
      completionListener![1]({
        payload: {
          executionId: 99,
          projectId: 1,
          requestedMode: "code",
          status: "complete",
          webStatus: null,
          codeStatus: "complete",
          codeRunId: 49,
        },
      });
    });
    await waitFor(() => expect(result.current.codeResult?.id).toBe(49));

    // A scan for another project leaves the displayed report alone.
    await act(async () => {
      completionListener![1]({
        payload: {
          executionId: 100,
          projectId: 2,
          requestedMode: "code",
          status: "complete",
          webStatus: null,
          codeStatus: "complete",
          codeRunId: 50,
        },
      });
    });
    expect(result.current.codeResult?.id).toBe(49);
    expect(getCodeScanDetailMock).not.toHaveBeenCalledWith({ scanId: 50 });
  });

  it("marks a background-refreshed code report as not foreground-scanned", async () => {
    const baseScan = {
      projectId: 1,
      environmentUrl: "https://example.com",
      overallScore: 80,
      issueCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      durationMs: 1000,
      checkedAt: "2026-06-12T00:00:00Z",
      framework: null,
      domainSummaries: [],
      issues: [],
    };
    invokeMock.mockResolvedValue(executionResult({ codeResult: { ...baseScan, id: 48 } }));
    getCodeScanDetailMock.mockImplementation(({ scanId }: { scanId: number }) =>
      Promise.resolve(scanId === 49 ? { ...baseScan, id: 49 } : null),
    );

    const { result } = renderHook(() => useScan());
    await act(async () => {
      await result.current.scanCode(1, "/tmp/project", "https://example.com");
    });
    // The user ran this one.
    expect(result.current.codeResultFromBackground).toBe(false);

    const completionListener = safeListenMock.mock.calls.find(
      ([event]) => event === "scan-execution-completed",
    );
    await act(async () => {
      completionListener![1]({
        payload: {
          executionId: 99,
          projectId: 1,
          requestedMode: "code",
          status: "complete",
          webStatus: null,
          codeStatus: "complete",
          codeRunId: 49,
        },
      });
    });

    await waitFor(() => expect(result.current.codeResult?.id).toBe(49));
    expect(result.current.codeResultFromBackground).toBe(true);

    // A foreground scan takes ownership of the report back.
    invokeMock.mockResolvedValue(executionResult({ codeResult: { ...baseScan, id: 50 } }));
    await act(async () => {
      await result.current.scanCode(1, "/tmp/project", "https://example.com");
    });
    expect(result.current.codeResult?.id).toBe(50);
    expect(result.current.codeResultFromBackground).toBe(false);
  });
});

describe("randomScanRequestId", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // A modulo folds every draw above the ceiling back onto the bottom of the
  // range. Hand it one out-of-range draw and the folded version answers with
  // 294_967_295 instead of asking the generator again.
  it("redraws past the ceiling rather than folding the draw", () => {
    const draws = [4_294_967_295, 1_234];
    const getRandomValues = vi.fn((array: Uint32Array) => {
      array[0] = draws.shift() ?? 0;
      return array;
    });
    vi.stubGlobal("crypto", { getRandomValues });

    expect(randomScanRequestId()).toBe(1_234);
    expect(getRandomValues).toHaveBeenCalledTimes(2);
  });

  it("stays inside the range Rust leaves to the webview", () => {
    for (let index = 0; index < 500; index += 1) {
      const id = randomScanRequestId();
      expect(id).toBeGreaterThanOrEqual(0);
      expect(id).toBeLessThan(4_000_000_000);
    }
  });
});
