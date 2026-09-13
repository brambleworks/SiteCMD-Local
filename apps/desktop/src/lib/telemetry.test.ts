import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  __hydrateTelemetryConsentForTests,
  __resetTelemetryForTests,
  __setDiagnosticSenderForTests,
  __setTelemetryConsentAuthorityForTests,
  __setTelemetryConfigForTests,
  __setTelemetryDeleteProofForTests,
  __setTelemetryTransportForTests,
  buildTelemetryPreview,
  flushTelemetryQueue,
  parseDsnHost,
  requestUploadedTelemetryDeletion,
  resetTelemetrySubject,
  SENTRY_INGEST_HOST,
  sanitizeTelemetryProperties,
  sanitizeTelemetryText,
  setTelemetryConsent,
  setTelemetryTier,
  trackDiagnosticEvent,
  trackUsageEvent,
} from "./telemetry";

const diagnosticSenderMock = vi.fn();
const PROOF = "a".repeat(64);
const deleteProofMock = {
  get: vi.fn<() => Promise<string>>(),
  clear: vi.fn<() => Promise<void>>(),
};
let backendConsent = {
  usageAnalytics: false,
  crashReports: false,
  consentVersion: 1,
  updatedAt: null as string | null,
};

describe("telemetry", () => {
  beforeEach(() => {
    localStorage.clear();
    diagnosticSenderMock.mockReset();
    diagnosticSenderMock.mockResolvedValue({ status: 200, body: "", headers: {} });
    backendConsent = {
      usageAnalytics: false,
      crashReports: false,
      consentVersion: 1,
      updatedAt: null,
    };
    __resetTelemetryForTests();
    __setTelemetryConsentAuthorityForTests({
      get: async () => backendConsent,
      set: async ({ args }) => {
        backendConsent = {
          ...backendConsent,
          ...args,
          updatedAt: new Date().toISOString(),
        };
        return backendConsent;
      },
    });
    __setDiagnosticSenderForTests(diagnosticSenderMock);
    deleteProofMock.get.mockReset();
    deleteProofMock.get.mockResolvedValue(PROOF);
    deleteProofMock.clear.mockReset();
    deleteProofMock.clear.mockResolvedValue(undefined);
    __setTelemetryDeleteProofForTests(deleteProofMock);
  });

  it("does not send usage events before usage consent is enabled", async () => {
    const transport = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })));
    __setTelemetryConfigForTests({ telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events" });
    __setTelemetryTransportForTests(transport);

    trackUsageEvent("workflow_event", { workflowName: "run_scan", workflowStatus: "started" });
    await flushTelemetryQueue();

    expect(transport).not.toHaveBeenCalled();
  });

  it("sends usage analytics without sending a crash report", async () => {
    const transport = vi.fn((endpoint: string) =>
      Promise.resolve(
        endpoint.endsWith("/v1/register")
          ? Response.json({
              ok: true,
              token: "server-issued-token",
              expiresAt: "2099-01-01T00:00:00.000Z",
            })
          : new Response(null, { status: 200 }),
      ),
    );
    __setTelemetryConfigForTests({
      telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events",
      sentryDsn: "https://public@sentry.example/1",
    });
    __setTelemetryTransportForTests(transport);

    await setTelemetryConsent({ usageAnalytics: true, crashReports: false });
    trackUsageEvent("workflow_event", {
      workflowName: "run_scan",
      workflowStatus: "succeeded",
      fullUrl: "https://example.com/reset?token=abc",
    });
    await flushTelemetryQueue();

    expect(transport).toHaveBeenCalled();
    expect(diagnosticSenderMock).not.toHaveBeenCalled();
    const calls = transport.mock.calls as unknown as Array<[string, string, RequestInit?]>;
    expect(calls[0]?.[0]).toBe("https://telemetry.sitecmd.com/v1/register");
    expect(calls.at(-1)?.[2]?.headers).toMatchObject({
      Authorization: "Bearer server-issued-token",
    });
    const body = JSON.parse(calls.at(-1)?.[1] ?? "{}") as {
      events: Array<{ properties: Record<string, unknown> }>;
    };
    expect(body.events.at(-1)?.properties).toMatchObject({
      workflowName: "run_scan",
      workflowStatus: "succeeded",
    });
    expect(body.events.at(-1)?.properties).not.toHaveProperty("fullUrl");
  });

  it("delivers each event exactly once no matter how many flushes overlap", async () => {
    const batches: Array<Array<{ id: string }>> = [];
    let hold: Promise<void> | null = null;
    const transport = vi.fn(async (endpoint: string, body: string) => {
      if (endpoint.endsWith("/v1/register")) {
        return Response.json({ ok: true, token: "t", expiresAt: "2099-01-01T00:00:00.000Z" });
      }
      batches.push((JSON.parse(body) as { events: Array<{ id: string }> }).events);
      if (hold) await hold;
      return new Response(null, { status: 200 });
    });
    __setTelemetryConfigForTests({ telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events" });
    __setTelemetryTransportForTests(transport);
    await setTelemetryConsent({ usageAnalytics: true, crashReports: false });
    // Opting in enqueues its own event; drain it so the queue starts empty.
    await flushTelemetryQueue();
    batches.length = 0;

    // Keep the release callback callable before the promise assigns it.
    let release: () => void = () => {};
    hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    trackUsageEvent("telemetry_preview_opened", {});
    const first = flushTelemetryQueue();
    const second = flushTelemetryQueue();
    const third = flushTelemetryQueue();
    release();
    await Promise.all([first, second, third]);

    const ids = batches.flat().map((event) => event.id);
    expect(ids).toHaveLength(1);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("carries a stable id so the ingest can recognize a redelivery", async () => {
    const bodies: string[] = [];
    let failing = false;
    const transport = vi.fn(async (endpoint: string, body: string) => {
      if (endpoint.endsWith("/v1/register")) {
        return Response.json({ ok: true, token: "t", expiresAt: "2099-01-01T00:00:00.000Z" });
      }
      if (!failing) return new Response(null, { status: 200 });
      bodies.push(body);
      // A lost response: the server committed, the client never learned it.
      return new Response(null, { status: 500 });
    });
    __setTelemetryConfigForTests({ telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events" });
    __setTelemetryTransportForTests(transport);
    await setTelemetryConsent({ usageAnalytics: true, crashReports: false });
    await flushTelemetryQueue();

    failing = true;
    trackUsageEvent("telemetry_preview_opened", {});
    await flushTelemetryQueue();
    await flushTelemetryQueue();

    expect(bodies).toHaveLength(2);
    const idsOf = (body: string) =>
      (JSON.parse(body) as { events: Array<{ id: string }> }).events.map((event) => event.id);
    // The retry presents the same id, which is the only thing that lets the
    // ingest tell it apart from a second occurrence.
    expect(idsOf(bodies[0] ?? "")).toEqual(idsOf(bodies[1] ?? ""));
  });

  it("does not reject when the network is unreachable", async () => {
    const transport = vi.fn(async (endpoint: string) => {
      if (endpoint.endsWith("/v1/register")) {
        return Response.json({ ok: true, token: "t", expiresAt: "2099-01-01T00:00:00.000Z" });
      }
      throw new TypeError("Failed to fetch");
    });
    __setTelemetryConfigForTests({ telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events" });
    __setTelemetryTransportForTests(transport);
    await setTelemetryConsent({ usageAnalytics: true, crashReports: false });

    trackUsageEvent("telemetry_preview_opened", {});
    await expect(flushTelemetryQueue()).resolves.toBeUndefined();
    // And the events are still queued, so the next attempt carries them.
    expect(buildTelemetryPreview()).toContain("Unsent usage events: 2");
  });

  it("keeps an event enqueued while a flush was already in flight", async () => {
    const sent: string[][] = [];
    // Callable initializer, same reason as the overlap test above.
    let release: () => void = () => {};
    let hold: Promise<void> | null = null;
    const transport = vi.fn(async (endpoint: string, body: string) => {
      if (endpoint.endsWith("/v1/register")) {
        return Response.json({ ok: true, token: "t", expiresAt: "2099-01-01T00:00:00.000Z" });
      }
      sent.push(
        (JSON.parse(body) as { events: Array<{ name: string }> }).events.map((e) => e.name),
      );
      if (hold) await hold;
      return new Response(null, { status: 200 });
    });
    __setTelemetryConfigForTests({ telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events" });
    __setTelemetryTransportForTests(transport);
    await setTelemetryConsent({ usageAnalytics: true, crashReports: false });
    await flushTelemetryQueue();
    sent.length = 0;

    hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    trackUsageEvent("telemetry_preview_opened", {});
    const inFlight = flushTelemetryQueue();
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    // Enqueued after the in-flight batch was already captured.
    trackUsageEvent("telemetry_uploaded_deletion_requested", {});
    hold = null;
    release();
    await inFlight;

    expect(sent[0]).toEqual(["telemetry_preview_opened"]);
    // The straggler went out on the drain loop's next pass, exactly once.
    expect(sent[1]).toEqual(["telemetry_uploaded_deletion_requested"]);
    expect(buildTelemetryPreview()).toContain("Unsent usage events: 0");
  });

  it("reports the license tier the app is actually on", async () => {
    const bodies: string[] = [];
    const transport = vi.fn(async (endpoint: string, body: string) => {
      if (endpoint.endsWith("/v1/register")) {
        return Response.json({ ok: true, token: "t", expiresAt: "2099-01-01T00:00:00.000Z" });
      }
      bodies.push(body);
      return new Response(null, { status: 200 });
    });
    __setTelemetryConfigForTests({ telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events" });
    __setTelemetryTransportForTests(transport);
    await setTelemetryConsent({ usageAnalytics: true, crashReports: false });

    setTelemetryTier("pro");
    trackUsageEvent("telemetry_preview_opened", {});
    await flushTelemetryQueue();

    const events = (JSON.parse(bodies.at(-1) ?? "{}") as { events: Array<{ tier: string }> })
      .events;
    expect(events.at(-1)?.tier).toBe("pro");

    // An unrecognized tier is not reported verbatim: the dimension is a
    // low-cardinality index server-side.
    setTelemetryTier("enterprise-preview");
    trackUsageEvent("telemetry_preview_opened", {});
    await flushTelemetryQueue();
    const later = (JSON.parse(bodies.at(-1) ?? "{}") as { events: Array<{ tier: string }> }).events;
    expect(later.at(-1)?.tier).toBe("unknown");
  });

  it("sends only a typed, sanitized native diagnostic report", async () => {
    __setTelemetryConfigForTests({
      sentryDsn: `https://public@${SENTRY_INGEST_HOST}/1`,
    });

    await setTelemetryConsent({ usageAnalytics: false, crashReports: true });
    trackDiagnosticEvent("frontend_error", new Error("Failed https://example.com/?token=abc"), {
      page: "dashboard",
      sourceCode: "const secret = true",
    });

    expect(diagnosticSenderMock).toHaveBeenCalledWith({
      args: {
        kind: "crashReport",
        report: expect.objectContaining({
          name: "frontend_error",
          message: "Failed [url]",
          properties: { page: "dashboard" },
          appVersion: expect.any(String),
          buildChannel: expect.any(String),
        }),
      },
    });
    const serialized = JSON.stringify(diagnosticSenderMock.mock.calls[0]?.[0]);
    expect(serialized).not.toContain("token=abc");
    expect(serialized).not.toContain("const secret");
  });

  it("keeps a fresh opt-out when stale durable consent finishes hydrating later", async () => {
    let resolveHydration: ((value: unknown) => void) | undefined;
    const storedConsent = new Promise<unknown>((resolve) => {
      resolveHydration = resolve;
    });

    const hydration = __hydrateTelemetryConsentForTests(storedConsent);
    await setTelemetryConsent({
      usageAnalytics: false,
      crashReports: false,
      promptStatus: "saved",
    });
    resolveHydration?.({
      usageAnalytics: true,
      crashReports: true,
      promptStatus: "saved",
      subjectId: "scmd_stale_subject",
      consentVersion: 1,
      updatedAt: "2026-01-01T00:00:00.000Z",
    });
    await hydration;

    expect(JSON.parse(localStorage.getItem("sitecmd_telemetry_consent_v1") ?? "{}")).toMatchObject({
      usageAnalytics: false,
      crashReports: false,
    });
    expect(diagnosticSenderMock).not.toHaveBeenCalled();
  });

  it("keeps both channels disabled when local storage says yes but the backend says no", async () => {
    const staleLocalConsent = {
      usageAnalytics: true,
      crashReports: true,
      promptStatus: "saved",
      subjectId: "scmd_stale_subject",
      consentVersion: 1,
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    localStorage.setItem("sitecmd_telemetry_consent_v1", JSON.stringify(staleLocalConsent));

    await __hydrateTelemetryConsentForTests(Promise.resolve(staleLocalConsent));

    expect(JSON.parse(localStorage.getItem("sitecmd_telemetry_consent_v1") ?? "{}")).toMatchObject({
      usageAnalytics: false,
      crashReports: false,
    });
    expect(buildTelemetryPreview()).toContain("Usage analytics: off");
    expect(buildTelemetryPreview()).toContain("Crash and error reports: off");
  });

  it("fails closed when the native consent authority throws before returning a promise", async () => {
    __setTelemetryConsentAuthorityForTests({
      get: () => {
        throw new Error("native bridge unavailable");
      },
      set: async ({ args }) => ({ ...backendConsent, ...args }),
    });

    await __hydrateTelemetryConsentForTests(
      Promise.resolve({ usageAnalytics: true, crashReports: true, promptStatus: "saved" }),
    );

    expect(buildTelemetryPreview()).toContain("Usage analytics: off");
    expect(buildTelemetryPreview()).toContain("Crash and error reports: off");
  });

  it("sanitizes sensitive telemetry text and drops forbidden properties", () => {
    expect(
      sanitizeTelemetryText(
        "See https://example.com/reset?token=abc /Users/dev/project hi@example.com license_key=abc123",
      ),
    ).toBe("See [url] [path] [email] [secret]");
    expect(
      sanitizeTelemetryProperties({
        page: "dashboard",
        path: "/Users/dev/project",
        token: "abc",
        executionId: 42,
        issueCount: 3,
      }),
    ).toEqual({ page: "dashboard", issueCount: 3 });
  });

  it("builds a user-facing preview that states what is never collected", () => {
    const preview = buildTelemetryPreview();
    expect(preview).toContain("SiteCMD Telemetry Preview");
    expect(preview).toContain("Never included");
    expect(preview).toContain("scan URLs");
    expect(preview).toContain("source code");
  });

  it("drops queued usage events after the server acceptance window", () => {
    localStorage.setItem(
      "sitecmd_telemetry_queue_v1",
      JSON.stringify([
        {
          id: "event_stale",
          name: "workflow_event",
          occurredAt: "2000-01-01T00:00:00.000Z",
          properties: {
            workflowName: "run_scan",
            workflowStatus: "succeeded",
          },
        },
      ]),
    );

    expect(buildTelemetryPreview()).toContain("Unsent usage events: 0");
  });

  it("caps an oversized queue on read without pruning valid within-window events", () => {
    const recent = new Date().toISOString();
    const seeded = Array.from({ length: 60 }, (_, index) => ({
      id: `event_${index}`,
      name: "workflow_event",
      occurredAt: recent,
      properties: {
        workflowName: "run_scan",
        workflowStatus: "succeeded",
      },
    }));
    localStorage.setItem("sitecmd_telemetry_queue_v1", JSON.stringify(seeded));

    expect(buildTelemetryPreview()).toContain("Unsent usage events: 50");

    const stored = JSON.parse(localStorage.getItem("sitecmd_telemetry_queue_v1") ?? "[]");
    expect(stored).toHaveLength(60);
  });

  describe("deletion secret", () => {
    function registeringTransport() {
      return vi.fn((endpoint: string) =>
        Promise.resolve(
          endpoint.endsWith("/v1/register")
            ? Response.json({ ok: true, token: "t", expiresAt: "2099-01-01T00:00:00.000Z" })
            : new Response(null, { status: 200 }),
        ),
      );
    }

    it("registers and stamps events with the keychain-derived proof", async () => {
      const transport = registeringTransport();
      __setTelemetryConfigForTests({
        telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events",
      });
      __setTelemetryTransportForTests(transport);

      await setTelemetryConsent({ usageAnalytics: true, crashReports: false });
      trackUsageEvent("workflow_event", { workflowName: "run_scan", workflowStatus: "started" });
      await flushTelemetryQueue();

      const calls = transport.mock.calls as unknown as Array<[string, string]>;
      const registration = JSON.parse(calls[0]?.[1] ?? "{}") as Record<string, unknown>;
      expect(registration.deleteProofHash).toBe(PROOF);
      const batch = JSON.parse(calls.at(-1)?.[1] ?? "{}") as {
        events: Array<Record<string, unknown>>;
      };
      expect(batch.events[0]?.deleteProofHash).toBe(PROOF);
      // One keychain read serves both the registration and the batch.
      expect(deleteProofMock.get).toHaveBeenCalledTimes(1);
    });

    it("keeps the secret out of every renderer store", async () => {
      await setTelemetryConsent({ usageAnalytics: true, crashReports: false });

      const persisted = localStorage.getItem("sitecmd_telemetry_consent_v1") ?? "";
      expect(persisted).toContain("subjectId");
      expect(persisted).not.toContain("deleteSecret");
      expect(persisted).not.toContain("delete_");
    });

    it("asks for erasure by subject only and leaves the secret to the keychain", async () => {
      const transport = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })));
      __setTelemetryConfigForTests({
        telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events",
      });
      __setTelemetryTransportForTests(transport);
      await setTelemetryConsent({ usageAnalytics: true, crashReports: false });

      await expect(requestUploadedTelemetryDeletion()).resolves.toBe("sent");

      const calls = transport.mock.calls as unknown as Array<[string, string]>;
      expect(calls.at(-1)?.[0]).toBe("https://telemetry.sitecmd.com/v1/delete");
      expect(Object.keys(JSON.parse(calls.at(-1)?.[1] ?? "{}"))).toEqual(["subjectId"]);
    });

    it("rotates the keychain secret with the subject and re-reads the proof", async () => {
      const transport = registeringTransport();
      __setTelemetryConfigForTests({
        telemetryEndpoint: "https://telemetry.sitecmd.com/v1/events",
      });
      __setTelemetryTransportForTests(transport);
      await setTelemetryConsent({ usageAnalytics: true, crashReports: false });
      trackUsageEvent("workflow_event", { workflowName: "run_scan", workflowStatus: "started" });
      await flushTelemetryQueue();
      deleteProofMock.get.mockResolvedValue("b".repeat(64));

      await resetTelemetrySubject();
      trackUsageEvent("workflow_event", { workflowName: "run_scan", workflowStatus: "started" });
      await flushTelemetryQueue();

      expect(deleteProofMock.clear).toHaveBeenCalledTimes(1);
      const calls = transport.mock.calls as unknown as Array<[string, string]>;
      const registrations = calls
        .filter(([endpoint]) => endpoint.endsWith("/v1/register"))
        .map(([, body]) => (JSON.parse(body) as Record<string, unknown>).deleteProofHash);
      expect(registrations).toEqual([PROOF, "b".repeat(64)]);
    });
  });

  describe("Sentry ingest host", () => {
    it("parseDsnHost extracts the host from a DSN and rejects bad input", () => {
      expect(parseDsnHost("https://public@o447951.ingest.sentry.io/123")).toBe(
        "o447951.ingest.sentry.io",
      );
      expect(parseDsnHost("")).toBeNull();
      expect(parseDsnHost("not a url")).toBeNull();
    });

    it("documents the crash-report ingest host as a sentry.io host", () => {
      expect(SENTRY_INGEST_HOST).toMatch(/\.sentry\.io$/);
    });

    it("does not send when the configured DSN points at a different ingest host", async () => {
      __setTelemetryConfigForTests({ sentryDsn: "https://public@o999999.ingest.sentry.io/1" });

      await setTelemetryConsent({ usageAnalytics: false, crashReports: true });
      trackDiagnosticEvent("frontend_error", new Error("boom"), { page: "dashboard" });

      expect(diagnosticSenderMock).not.toHaveBeenCalled();
    });

    it("sends when the configured DSN matches the documented host", async () => {
      __setTelemetryConfigForTests({ sentryDsn: `https://public@${SENTRY_INGEST_HOST}/1` });

      await setTelemetryConsent({ usageAnalytics: false, crashReports: true });
      trackDiagnosticEvent("frontend_error", new Error("boom"), { page: "dashboard" });

      expect(diagnosticSenderMock).toHaveBeenCalledTimes(1);
    });
  });
});
