import { describe, expect, it } from "vitest";
import { SCAN_LABELS } from "@/lib/scan-labels";
import { getScanStartLabel } from "./scan-config-overlay-model";

describe("getScanStartLabel", () => {
  it("names a code scan and a full scan without a page count", () => {
    expect(getScanStartLabel({ hasPages: true, scanType: "code", selectedCount: 4 })).toBe(
      `Run ${SCAN_LABELS.code}`,
    );
    expect(getScanStartLabel({ hasPages: true, scanType: "full", selectedCount: 4 })).toBe(
      "Run Scan",
    );
  });

  it("counts pages only once more than one is selected", () => {
    expect(getScanStartLabel({ hasPages: true, scanType: "web", selectedCount: 2 })).toBe(
      "Scan 2 pages",
    );
    expect(getScanStartLabel({ hasPages: true, scanType: "web", selectedCount: 1 })).toBe(
      `Run ${SCAN_LABELS.web}`,
    );
    expect(getScanStartLabel({ hasPages: false, scanType: "web", selectedCount: 5 })).toBe(
      `Run ${SCAN_LABELS.web}`,
    );
  });
});
