import { describe, expect, it } from "vitest";
import { getEffortLabel, getFixGuide, normalizeFixGuideKey } from "./fix-guides";

describe("getFixGuide", () => {
  it("covers server errors, wildcard blocks, and HTML robots responses", () => {
    const guide = getFixGuide("seo.robots_txt");
    expect(guide?.lead).toBe(
      "Your robots.txt has a problem that affects how search engines crawl your site.",
    );
    expect(guide?.steps.join(" ")).toBe(
      [
        "Open your site's deployed /robots.txt and check which of these applies.",
        "If it answers a server error (a 5xx status): Make /robots.txt answer HTTP 200 with the file, or 404 if the site has no crawl rules. Check the server, CDN or framework route that serves it.",
        "If its `User-agent: *` group has `Disallow: /`: Confirm the block is intentional. If the site should be crawled, remove it or narrow it to the paths that should not be crawled. robots.txt is not access control.",
        "If it is served as text/html: Serve robots.txt with a Content-Type header of text/plain.",
      ].join(" "),
    );
  });

  it("returns null for an unknown check ID", () => {
    expect(getFixGuide("nonexistent.check")).toBeNull();
  });

  it("returns the baseline with its effort metadata", () => {
    const guide = getFixGuide("security.csp");
    expect(guide).not.toBeNull();
    expect(guide!.effort).toBe("involved");
    expect(guide!.effortMinutes).toBe(30);
    expect(guide!.steps.length).toBeGreaterThan(0);
  });

  it("resolves dynamic sub-IDs through the dot-prefix fallback", () => {
    const parent = getFixGuide("security.cookies");
    const sub = getFixGuide("security.cookies.session");
    expect(parent).not.toBeNull();
    expect(sub).not.toBeNull();
    expect(sub!.steps).toEqual(parent!.steps);
  });

  it("returns guides for raw Web Scan IDs before canonicalization", () => {
    const checks = [
      "security.headers.csp",
      "security.headers.hsts",
      "security.headers.x_frame_options",
      "security.headers.x_content_type_options",
      "security.headers.referrer_policy",
      "security.headers.permissions_policy",
      "security.https_enforcement",
      "security.ssl.expiry",
      "security.ssl.hostname",
      "security.ssl.chain",
      "security.ssl.protocol",
      "security.server_info.server_header",
      "security.server_info.x_powered_by",
      "seo.duplicate_title",
      "seo.duplicate_description",
      "seo.duplicate_title_across_pages",
      "seo.duplicate_description_across_pages",
      "performance.images",
    ];
    for (const check of checks) {
      expect(getFixGuide(check), `missing guide for ${check}`).not.toBeNull();
    }
  });

  it("returns guides for emitted polish issue IDs", () => {
    const checks = [
      "polish.ai-buzzword-dictionary",
      "polish.div-soup-ratio",
      "polish.glassmorphism",
      "polish.source-maps-production",
    ];
    for (const check of checks) {
      expect(getFixGuide(check), `missing guide for ${check}`).not.toBeNull();
    }
  });
});

describe("normalizeFixGuideKey", () => {
  it("maps emitted ids to the keys the corpus and the catalog pack use", () => {
    expect(normalizeFixGuideKey("security.headers.csp")).toBe("security.csp");
    expect(normalizeFixGuideKey("polish.em-dash-density")).toBe("em-dash-density");
    expect(normalizeFixGuideKey("seo.duplicate_title")).toBe("seo.duplicate_meta");
    expect(normalizeFixGuideKey("seo.duplicate_title_across_pages")).toBe("seo.duplicate_meta");
    expect(normalizeFixGuideKey("security.csp")).toBe("security.csp");
  });
});

describe("getEffortLabel", () => {
  it("maps effort levels to user-facing labels", () => {
    expect(getEffortLabel("quick")).toBe("~5 min fix");
    expect(getEffortLabel("moderate")).toBe("~15 min fix");
    expect(getEffortLabel("involved")).toBe("30+ min fix");
  });
});
