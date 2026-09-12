import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { MultiScanProgressEvent, ScanProgressEvent } from "@/hooks/useScan";
import {
  beginScanRun,
  publishMultiScanProgress,
  publishScanProgress,
  resetScanProgress,
} from "@/lib/scan-progress-store";
import { ScanOverlay } from "./ScanOverlay";

// The percent comes from the progress store's run model, not from props, so
// tests that read it feed the store the same event they render.
function progressOf(event: ScanProgressEvent): ScanProgressEvent {
  publishScanProgress(event);
  return event;
}

function pagesOf(event: MultiScanProgressEvent): MultiScanProgressEvent {
  publishMultiScanProgress(event);
  return event;
}

const CODE_SCAN_STAGE_LABELS = [
  "Project Files",
  "Source Code",
  "Dependencies",
  "Release Setup",
  "Saving Results",
  "Summary",
];

function visiblePercent() {
  return Number.parseInt(screen.getByTestId("scan-progress-percent").textContent ?? "0", 10);
}

function stageState(label: string) {
  const stage = Array.from(
    screen.getByTestId("scan-stages").querySelectorAll("[data-stage-state]"),
  ).find((node) => node.textContent === label);
  return stage?.getAttribute("data-stage-state");
}

describe("ScanOverlay", () => {
  afterEach(() => {
    vi.useRealTimers();
    resetScanProgress();
  });

  it("renders code scans as a full phased scan instead of a generic spinner", () => {
    render(<ScanOverlay progress={null} scanType="code" url="https://example.com" />);

    expect(screen.getByText("Code Scan")).toBeInTheDocument();
    expect(screen.getByText("Scanning code for example.com")).toBeInTheDocument();
    expect(screen.getByText("Checking")).toBeInTheDocument();
    expect(
      screen.getByText("Finding source files and project config that belong in the audit."),
    ).toBeInTheDocument();
    expect(screen.getByText("0% complete · Project Files")).toBeInTheDocument();

    for (const label of CODE_SCAN_STAGE_LABELS) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
  });

  it("keeps the code scan stages in the backend progress order", () => {
    render(<ScanOverlay progress={null} scanType="code" url="https://example.com" />);

    const stageLabels = Array.from(
      screen.getByTestId("scan-stages").querySelectorAll("[data-stage-label]"),
    ).map((node) => node.textContent);

    expect(stageLabels).toEqual(CODE_SCAN_STAGE_LABELS);
  });

  it("uses backend code scan progress instead of timer-based fake progress", () => {
    render(
      <ScanOverlay
        progress={progressOf({
          check_id: "code-scan.analyze-source",
          category: "config",
          status: "running",
          results_count: 12,
          checks_done: 44,
          checks_total: 100,
        })}
        scanType="code"
        url="https://example.com"
      />,
    );

    expect(screen.getByText("44")).toBeInTheDocument();
    expect(screen.getByText("44% complete · Source Code")).toBeInTheDocument();
    expect(screen.getByText("12 issues")).toBeInTheDocument();
  });

  it("smooths sudden backend progress jumps after the overlay has started", () => {
    vi.useFakeTimers();
    beginScanRun({ web: null, code: true });
    const { rerender } = render(
      <ScanOverlay progress={null} scanType="code" url="https://example.com" />,
    );

    expect(visiblePercent()).toBe(0);

    rerender(
      <ScanOverlay
        progress={progressOf({
          check_id: "code-scan.analyze-source",
          category: "config",
          status: "running",
          results_count: 3,
          checks_done: 80,
          checks_total: 100,
        })}
        scanType="code"
        url="https://example.com"
      />,
    );

    expect(visiblePercent()).toBeLessThan(80);

    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(visiblePercent()).toBeGreaterThan(5);
    expect(visiblePercent()).toBeLessThan(80);

    act(() => {
      vi.advanceTimersByTime(3_000);
    });
    expect(visiblePercent()).toBe(80);
  });

  it("moves code scan to the final visible phase when completion arrives", () => {
    vi.useFakeTimers();
    const { rerender } = render(
      <ScanOverlay progress={null} scanType="code" url="https://example.com" />,
    );

    expect(stageState("Project Files")).toBe("active");

    rerender(
      <ScanOverlay
        progress={{
          check_id: "code-scan.complete",
          category: "config",
          status: "complete",
          results_count: 4,
          checks_done: 100,
          checks_total: 100,
        }}
        scanType="code"
        url="https://example.com"
      />,
    );

    expect(stageState("Summary")).toBe("active");
  });

  it("shows web scan stages in scan-pipeline order", () => {
    render(
      <ScanOverlay
        progress={{
          check_id: "fetch",
          category: "security",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 10,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    const stageLabels = Array.from(
      screen.getByTestId("scan-stages").querySelectorAll("[data-stage-label]"),
    ).map((node) => node.textContent);

    expect(stageLabels).toEqual([
      "Fetch",
      "Security",
      "SEO",
      "Performance",
      "Accessibility",
      "Privacy",
      "Polish",
      "Browser",
    ]);
  });

  it("keeps multi-page progress monotonic without replaying the category stage grid", () => {
    vi.useFakeTimers();
    beginScanRun({ web: "health", code: false, pageCount: 2 });
    const { rerender } = render(
      <ScanOverlay
        progress={progressOf({
          check_id: "browser-analysis",
          category: "performance",
          status: "complete",
          results_count: 2,
          checks_done: 0,
          checks_total: 0,
        })}
        multiProgress={pagesOf({
          page_index: 0,
          page_count: 2,
          current_url: "https://example.com",
          page_status: "complete",
          session_id: 9,
        })}
        scanType="health"
        url="https://example.com"
      />,
    );

    const firstPagePercent = visiblePercent();
    expect(firstPagePercent).toBe(50);
    expect(screen.queryByTestId("scan-stages")).not.toBeInTheDocument();

    rerender(
      <ScanOverlay
        multiProgress={pagesOf({
          page_index: 1,
          page_count: 2,
          current_url: "https://example.com/about",
          page_status: "scanning",
          session_id: 9,
        })}
        progress={progressOf({
          check_id: "fetch",
          category: "security",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        })}
        scanType="health"
        url="https://example.com"
      />,
    );

    // The second page starts from the first page's half, never below it.
    expect(visiblePercent()).toBeGreaterThanOrEqual(firstPagePercent);
    expect(visiblePercent()).toBeLessThanOrEqual(52);
    expect(screen.queryByTestId("scan-stages")).not.toBeInTheDocument();
  });

  it("sits above persistent shell surfaces while active", () => {
    render(<ScanOverlay progress={null} scanType="code" url="https://example.com" />);

    // A native <dialog> opened with showModal() renders in the top layer, above
    // every other surface, without needing a stacking-context class of its own.
    const dialog = screen.getByRole("dialog", { name: "Scan in progress" });
    expect(dialog.tagName).toBe("DIALOG");
    expect(dialog).toHaveClass("dialog--blur");
  });

  it("keeps the whole overlay reachable when the window is short", () => {
    render(<ScanOverlay progress={null} scanType="health" url="https://example.com" />);

    const dialog = screen.getByRole("dialog", { name: "Scan in progress" });
    expect(dialog.firstElementChild).toHaveClass("scan-overlay-content");
  });

  it("wires the background and cancel controls without making the backdrop actionable", () => {
    const onMinimize = vi.fn();
    const onCancel = vi.fn();
    render(
      <ScanOverlay
        progress={null}
        scanType="health"
        url="https://example.com"
        onMinimize={onMinimize}
        onCancel={onCancel}
      />,
    );

    fireEvent.click(screen.getByRole("dialog", { name: "Scan in progress" }));
    expect(onMinimize).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /continue in background/i }));
    expect(onMinimize).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: /cancel scan/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("shows the overall full-scan step when a scan run includes web and code", () => {
    render(
      <ScanOverlay
        progress={null}
        scanType="code"
        url="https://example.com"
        scanRunStep={{
          mode: "full",
          stepIndex: 2,
          stepCount: 2,
          label: "Code Scan",
        }}
      />,
    );

    expect(screen.getByText("Scanning code for example.com")).toBeInTheDocument();
    expect(screen.getByTestId("scan-run-context")).toHaveTextContent(
      /^Full Scan · Step 2 of 2 · Code Scan$/,
    );
  });

  it("fills the web ring, then starts a fresh ring for the code step of a full scan", () => {
    vi.useFakeTimers();
    beginScanRun({ web: "health", code: true });
    const { rerender } = render(
      <ScanOverlay
        progress={progressOf({
          check_id: "browser-analysis",
          category: "performance",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        })}
        scanType="full"
        url="https://example.com"
        scanRunStep={{
          mode: "full",
          stepIndex: 1,
          stepCount: 2,
          label: "Web Scan",
        }}
      />,
    );

    // The browser pass owns the last third of the web ring and drifts toward its end.
    expect(visiblePercent()).toBe(68);
    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    const beforeHandoff = visiblePercent();
    expect(beforeHandoff).toBeGreaterThan(95);
    expect(beforeHandoff).toBeLessThanOrEqual(100);

    rerender(
      <ScanOverlay
        progress={progressOf({
          check_id: "code-scan.collect-files",
          category: "config",
          status: "running",
          results_count: 0,
          checks_done: 5,
          checks_total: 100,
        })}
        scanType="full"
        url="https://example.com"
        scanRunStep={{
          mode: "full",
          stepIndex: 1,
          stepCount: 2,
          label: "Web Scan",
        }}
      />,
    );

    // The code step is its own ring: it snaps to the code scan's start
    // instead of gliding down from the web ring's 100.
    act(() => {
      vi.advanceTimersByTime(100);
    });
    expect(visiblePercent()).toBeGreaterThanOrEqual(5);
    expect(visiblePercent()).toBeLessThan(15);
    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(visiblePercent()).toBeGreaterThan(5);
    expect(visiblePercent()).toBeLessThan(15);
    expect(screen.getByText("Scanning code for example.com")).toBeInTheDocument();
    expect(screen.getByTestId("scan-run-context")).toHaveTextContent(
      /^Full Scan · Step 2 of 2 · Code Scan$/,
    );

    rerender(
      <ScanOverlay
        progress={null}
        scanType="full"
        url="https://example.com"
        scanRunStep={{
          mode: "full",
          stepIndex: 1,
          stepCount: 2,
          label: "Web Scan",
        }}
      />,
    );

    expect(screen.getByText("Scanning code for example.com")).toBeInTheDocument();
    expect(screen.queryByText("Scanning example.com")).not.toBeInTheDocument();
  });

  it("keeps web scan header copy stable while showing full-scan state in the meta line", () => {
    render(
      <ScanOverlay
        progress={{
          check_id: "headers",
          category: "security",
          status: "running",
          results_count: 0,
          checks_done: 1,
          checks_total: 10,
        }}
        scanType="health"
        url="https://example.com"
        scanRunStep={{
          mode: "full",
          stepIndex: 1,
          stepCount: 2,
          label: "Web Scan",
        }}
      />,
    );

    expect(screen.getByText("Scanning example.com")).toBeInTheDocument();
    expect(screen.getByText("Web Scan")).toBeInTheDocument();
    expect(screen.getByTestId("scan-run-context")).toHaveTextContent(
      /^Full Scan · Step 1 of 2 · Web Scan$/,
    );
  });

  it("shows web scan phase progress instead of resetting to zero for uncounted phases", () => {
    render(
      <ScanOverlay
        progress={progressOf({
          check_id: "polish-css",
          category: "polish",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        })}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(screen.getAllByText("Polish").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Fetching styles").length).toBeGreaterThan(0);
    expect(visiblePercent()).toBeGreaterThanOrEqual(60);
    expect(visiblePercent()).toBeLessThanOrEqual(68);
  });

  it("paces visible web scan phase changes instead of skipping straight to the latest event", () => {
    vi.useFakeTimers();
    const { rerender } = render(
      <ScanOverlay
        progress={{
          check_id: "fetch",
          category: "security",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 10,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(stageState("Fetch")).toBe("active");

    rerender(
      <ScanOverlay
        progress={{
          check_id: "polish-css",
          category: "polish",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(stageState("Fetch")).toBe("active");

    act(() => {
      vi.advanceTimersByTime(700);
    });
    expect(stageState("Security")).toBe("active");

    for (let i = 0; i < 5; i += 1) {
      act(() => {
        vi.advanceTimersByTime(700);
      });
    }
    expect(stageState("Polish")).toBe("active");
  });

  it("shows actual web scan progress events in the activity feed", () => {
    render(
      <ScanOverlay
        progress={{
          check_id: "security.ssl",
          category: "security",
          status: "complete",
          results_count: 1,
          checks_done: 2,
          checks_total: 10,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(screen.getByText("Live Scan Events")).toBeInTheDocument();
    expect(screen.queryByText("cmd")).not.toBeInTheDocument();
    expect(screen.getByTestId("scan-terminal")).toHaveClass("scan-terminal");
    expect(screen.getByText("Done")).toBeInTheDocument();
    expect(screen.getAllByText(/Security/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Security SSL/)).toBeInTheDocument();
    expect(screen.getByText("1 issue")).toBeInTheDocument();
  });

  it("shows failed browser analysis as failed instead of done", () => {
    render(
      <ScanOverlay
        progress={{
          check_id: "browser-analysis",
          category: "performance",
          status: "error",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    const failed = screen.getByText("Failed");
    expect(failed).toHaveClass("scan-terminal-status-error");
    expect(screen.queryByText("Done")).not.toBeInTheDocument();
  });

  it("keeps the current web scan phase in the status block between checks instead of flashing the preparing state", () => {
    const securityDetail = "Checking HTTPS, headers, redirects, cookies, and exposed files.";
    const { rerender } = render(
      <ScanOverlay
        progress={{
          check_id: "headers",
          category: "security",
          status: "running",
          results_count: 0,
          checks_done: 1,
          checks_total: 10,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(screen.getByText(securityDetail)).toBeInTheDocument();
    expect(screen.queryByText(/Preparing/)).not.toBeInTheDocument();

    rerender(
      <ScanOverlay
        progress={{
          check_id: "headers",
          category: "security",
          status: "complete",
          results_count: 0,
          checks_done: 2,
          checks_total: 10,
        }}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(screen.getByText(securityDetail)).toBeInTheDocument();
    expect(screen.queryByText(/Preparing/)).not.toBeInTheDocument();
  });

  it("still shows the preparing state before the first web scan progress event", () => {
    render(<ScanOverlay progress={null} scanType="health" url="https://example.com" />);

    expect(screen.getByText("Preparing")).toBeInTheDocument();
    expect(screen.getByText("scan")).toBeInTheDocument();
  });

  it("gives browser analysis the last third and keeps it moving until it lands", () => {
    vi.useFakeTimers();
    beginScanRun({ web: "health", code: false });
    const { rerender } = render(
      <ScanOverlay
        progress={progressOf({
          check_id: "browser-analysis",
          category: "performance",
          status: "running",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        })}
        scanType="health"
        url="https://example.com"
      />,
    );

    expect(visiblePercent()).toBe(68);
    const seen: number[] = [];
    for (let tick = 0; tick < 22; tick += 1) {
      act(() => {
        vi.advanceTimersByTime(500);
      });
      seen.push(visiblePercent());
    }
    // Eleven seconds without an event: still climbing, never at 100.
    for (let index = 1; index < seen.length; index += 1) {
      expect(seen[index]).toBeGreaterThanOrEqual(seen[index - 1]);
    }
    expect(seen[seen.length - 1]).toBeGreaterThanOrEqual(95);
    expect(seen[seen.length - 1]).toBeLessThan(100);
    expect(new Set(seen).size).toBeGreaterThan(8);

    rerender(
      <ScanOverlay
        progress={progressOf({
          check_id: "browser-analysis",
          category: "performance",
          status: "complete",
          results_count: 0,
          checks_done: 0,
          checks_total: 0,
        })}
        scanType="health"
        url="https://example.com"
      />,
    );

    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(visiblePercent()).toBe(100);
  });

  it("keeps the number moving through the origin-check wait instead of freezing", () => {
    vi.useFakeTimers();
    beginScanRun({ web: "health", code: false });
    render(
      <ScanOverlay
        progress={progressOf({
          check_id: "config.www_redirect",
          category: "config",
          status: "running",
          results_count: 0,
          checks_done: 90,
          checks_total: 127,
        })}
        scanType="health"
        url="https://example.com"
      />,
    );

    const seen: number[] = [];
    for (let tick = 0; tick < 12; tick += 1) {
      act(() => {
        vi.advanceTimersByTime(1_000);
      });
      seen.push(visiblePercent());
    }
    for (let index = 1; index < seen.length; index += 1) {
      expect(seen[index]).toBeGreaterThanOrEqual(seen[index - 1]);
    }
    expect(seen[0]).toBeGreaterThan(45);
    expect(seen[seen.length - 1]).toBeGreaterThan(seen[0]);
    expect(seen[seen.length - 1]).toBeLessThan(60);
  });
});
