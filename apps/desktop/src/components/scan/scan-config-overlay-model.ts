import { normalizeAppUrlForKey } from "@/lib/app-targets";
import { SCAN_LABELS } from "@/lib/scan-labels";

export interface PageRecord {
  id: number;
  siteId: number;
  url: string;
  path: string;
  title: string | null;
  lastSeenAt: string;
  source: string;
}

export type ScanMode = "full" | "web" | "code";

export interface ScanConfig {
  urls: string[];
  axeEnabled: boolean;
  inspectLocalDatabases?: boolean;
  scanType: ScanMode;
}

export type ScanConfigPreset = Partial<Pick<ScanConfig, "scanType" | "axeEnabled">>;

export function getTimeEstimate(
  pageCount: number,
  axeEnabled: boolean,
  scanType: ScanMode = "web",
  includeCodeScan = true,
): string {
  if (scanType === "code") {
    return "About 30 seconds";
  }
  // Estimates include the accessibility and code-scan overhead.
  const perPage = axeEnabled ? 20 : 5;
  const webSecs = pageCount * perPage;
  const totalSecs = scanType === "full" && includeCodeScan ? webSecs + 30 : webSecs;

  if (totalSecs < 60) return `About ${totalSecs} seconds`;
  if (totalSecs < 3600) {
    const mins = Math.round(totalSecs / 60);
    return `About ${mins} minute${mins === 1 ? "" : "s"}`;
  }
  const hours = (totalSecs / 3600).toFixed(1);
  return `About ${hours} hours`;
}

export function getDefaultPageUrl(pages: PageRecord[], siteUrl: string): string {
  const normalizedSiteUrl = normalizeComparableUrl(siteUrl);
  const homepage =
    pages.find((page) => page.path === "/" || page.path === "") ??
    pages.find((page) => normalizeComparableUrl(page.url) === normalizedSiteUrl) ??
    pages[0];
  return homepage?.url ?? siteUrl;
}

function normalizeComparableUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const normalizedPath = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/$/, "");
    return `${parsed.origin}${normalizedPath}`;
  } catch {
    return normalizeAppUrlForKey(url);
  }
}

/** Turn "/guides/installation/setting-ring-doorbell" into "Setting Ring Doorbell" */
export function humanizePath(path: string): string {
  if (!path || path === "/") return "Homepage";
  const last = path.split("/").filter(Boolean).pop() || path;
  return last.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function getScanStartLabel({
  hasPages,
  scanType,
  selectedCount,
}: {
  canUseCodeScan?: boolean;
  hasPages: boolean;
  scanType: ScanMode;
  selectedCount: number;
}): string {
  if (scanType === "code") return `Run ${SCAN_LABELS.code}`;
  if (scanType === "full") return "Run Scan";
  // Only a web scan remains. A count earns a place in the label once more than
  // one page is selected, so the plural is the only form it can take.
  return hasPages && selectedCount > 1 ? `Scan ${selectedCount} pages` : `Run ${SCAN_LABELS.web}`;
}

/** Return the page's route relative to its site. */
export function routeOf(pageUrl: string, siteUrl: string): string {
  try {
    return new URL(pageUrl, siteUrl).pathname || "/";
  } catch {
    return pageUrl.startsWith("/") ? pageUrl : `/${pageUrl}`;
  }
}

/** Resolve stored routes without dropping undiscovered pages from scope. */
export function scopeSelection(routes: string[], siteUrl: string, pages: PageRecord[]): string[] {
  return routes.map((route) => {
    const match = pages.find((page) => routeOf(page.url, siteUrl) === route);
    if (match) return match.url;
    try {
      return new URL(route, siteUrl).href;
    } catch {
      return route;
    }
  });
}

/** Include scoped routes absent from the current page list. */
export function pagesWithScopeRoutes(
  pages: PageRecord[],
  routes: string[],
  siteUrl: string,
): PageRecord[] {
  const missing = routes.filter(
    (route) => !pages.some((page) => routeOf(page.url, siteUrl) === route),
  );
  return [
    ...pages,
    ...missing.map((route, index) => ({
      // Negative ids cannot collide with a database row's.
      id: -(index + 1),
      siteId: pages[0]?.siteId ?? 0,
      url: (() => {
        try {
          return new URL(route, siteUrl).href;
        } catch {
          return route;
        }
      })(),
      path: route,
      title: null,
      lastSeenAt: "",
      source: "scope",
    })),
  ];
}
