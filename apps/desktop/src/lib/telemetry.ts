import { useSyncExternalStore } from "react";
import {
  getTelemetryConsent,
  sendTelemetryRequest,
  setBackendTelemetryConsent,
  type BackendTelemetryConsent,
  type TelemetryRequest,
} from "@/lib/commands";
import { storeGet, storeSet } from "@/lib/store";
import { isJsonRecord } from "@/lib/json-record";
import { MS_PER_DAY } from "@/lib/format";
import { tauriTelemetryTransport, type TelemetryTransport } from "./telemetry-transport";
import {
  detectArchitecture,
  detectOsFamily,
  hashTelemetryText,
  randomId,
  sanitizeTelemetryProperties,
  sanitizeTelemetryText,
  type PrimitiveTelemetryValue,
} from "./telemetry-scrub";

// Keep the telemetry boundary on one import path.
export { sanitizeTelemetryProperties, sanitizeTelemetryText } from "./telemetry-scrub";

type TelemetryKind = "usage" | "diagnostic";
type TelemetryPromptStatus = "unseen" | "saved";

export type UsageTelemetryEventName =
  | "workflow_event"
  | "telemetry_consent_saved"
  | "telemetry_preview_opened"
  | "telemetry_uploaded_deletion_requested";

export type DiagnosticTelemetryEventName =
  "frontend_error" | "tauri_command_failed" | "startup_error";

export interface TelemetryConsentState {
  usageAnalytics: boolean;
  crashReports: boolean;
  promptStatus: TelemetryPromptStatus;
  subjectId: string | null;
  deleteSecret: string | null;
  consentVersion: number;
  updatedAt: string | null;
}

interface PendingUsageEvent {
  id: string;
  name: UsageTelemetryEventName;
  occurredAt: string;
  properties: Record<string, PrimitiveTelemetryValue>;
}

interface TelemetryEnvelope {
  schemaVersion: 1;
  /** Stable id used by ingest to deduplicate retries. */
  id: string;
  kind: TelemetryKind;
  name: UsageTelemetryEventName;
  occurredAt: string;
  appVersion: string;
  buildChannel: string;
  osFamily: string;
  architecture: string;
  tier: string;
  anonymousSubjectId: string;
  deleteProofHash: string;
  consentVersion: number;
  properties: Record<string, PrimitiveTelemetryValue>;
}

interface CachedIngestToken {
  token: string;
  expiresAt: string;
  subjectId: string;
}

const CONSENT_VERSION = 1;
const CONSENT_STORAGE_KEY = "sitecmd_telemetry_consent_v1";
const CONSENT_STORE_KEY = "telemetry-consent-v1";
const QUEUE_STORAGE_KEY = "sitecmd_telemetry_queue_v1";
const MAX_QUEUE_EVENTS = 50;
// Must match the ingest request cap.
const MAX_EVENTS_PER_REQUEST = 20;
const MAX_QUEUED_EVENT_AGE_MS = 7 * MS_PER_DAY;
const MAX_QUEUED_EVENT_FUTURE_SKEW_MS = 10 * 60 * 1000;
const DEFAULT_TELEMETRY_ENDPOINT = import.meta.env.VITE_SITECMD_TELEMETRY_ENDPOINT ?? "";
const DEFAULT_SENTRY_DSN = import.meta.env.VITE_SITECMD_SENTRY_DSN ?? "";

// Public privacy disclosures and the build-time DSN must match this host.
export const SENTRY_INGEST_HOST = "o4511662343127040.ingest.us.sentry.io";

/** Host portion of a Sentry DSN, or null when empty or unparseable. */
export function parseDsnHost(dsn: string): string | null {
  if (!dsn) return null;
  try {
    return new URL(dsn).host || null;
  } catch {
    return null;
  }
}
// The impossible release version exposes missing Vite configuration while remaining valid semver.
const APP_VERSION = import.meta.env.VITE_APP_VERSION ?? "0.0.0";
const BUILD_CHANNEL = import.meta.env.MODE === "production" ? "production" : import.meta.env.MODE;
const USAGE_EVENT_NAMES: UsageTelemetryEventName[] = [
  "workflow_event",
  "telemetry_consent_saved",
  "telemetry_preview_opened",
  "telemetry_uploaded_deletion_requested",
];
// Keep the aggregate tier dimension low-cardinality.
const KNOWN_TELEMETRY_TIERS = new Set(["free", "core", "pro"]);
const DIAGNOSTIC_EVENT_NAMES: DiagnosticTelemetryEventName[] = [
  "frontend_error",
  "tauri_command_failed",
  "startup_error",
];
// Both upload channels are opt-in.
const DEFAULT_CONSENT: TelemetryConsentState = {
  usageAnalytics: false,
  crashReports: false,
  promptStatus: "unseen",
  subjectId: null,
  deleteSecret: null,
  consentVersion: CONSENT_VERSION,
  updatedAt: null,
};

let runtimeConfig = {
  telemetryEndpoint: DEFAULT_TELEMETRY_ENDPOINT,
  sentryDsn: DEFAULT_SENTRY_DSN,
};
const localConsentAtStartup = loadConsentFromLocalStorage();
let consent: TelemetryConsentState = {
  ...localConsentAtStartup,
  usageAnalytics: false,
  crashReports: false,
};
let consentRevision = 0;
let telemetryTransport: TelemetryTransport = tauriTelemetryTransport;
// The ingest token is a short-lived bearer credential the service re-mints on
// demand, so it lives in memory for the life of the window and never lands in
// webview storage. Persisting it would trade a request per launch for a
// credential sitting in clear text on disk, which is the wrong side of that
// trade for a token that costs one round trip to replace.
let ingestToken: CachedIngestToken | null = null;
let ingestTokenPromise: Promise<CachedIngestToken | null> | null = null;
let flushInFlight: Promise<void> | null = null;
// The tier provider updates this after license state resolves.
let reportedTier = "unknown";
const listeners = new Set<() => void>();

interface TelemetryConsentAuthority {
  get: () => Promise<BackendTelemetryConsent>;
  set: (args: {
    args: { usageAnalytics: boolean; crashReports: boolean };
  }) => Promise<BackendTelemetryConsent>;
}

let telemetryConsentAuthority: TelemetryConsentAuthority = {
  get: getTelemetryConsent,
  set: setBackendTelemetryConsent,
};
let diagnosticSender = sendTelemetryRequest;
let consentHydrationPromise: Promise<void> | null = null;

export async function initializeTelemetryFromStoredConsent() {
  if (!consentHydrationPromise) {
    consentHydrationPromise = hydrateTelemetryConsent(storeGet<unknown>(CONSENT_STORE_KEY, null));
  }
  await consentHydrationPromise;
}

export function useTelemetryConsent() {
  return useSyncExternalStore(subscribeConsent, getConsentSnapshot, getConsentSnapshot);
}

export async function setTelemetryConsent(next: {
  usageAnalytics: boolean;
  crashReports: boolean;
  promptStatus?: TelemetryPromptStatus;
}) {
  consentRevision += 1;
  const authoritative = await telemetryConsentAuthority.set({
    args: {
      usageAnalytics: next.usageAnalytics,
      crashReports: next.crashReports,
    },
  });
  const needsSubject = authoritative.usageAnalytics || authoritative.crashReports;
  consent = {
    ...consent,
    usageAnalytics: authoritative.usageAnalytics,
    crashReports: authoritative.crashReports,
    promptStatus: next.promptStatus ?? "saved",
    subjectId: needsSubject ? (consent.subjectId ?? randomId("scmd")) : consent.subjectId,
    deleteSecret: needsSubject
      ? (consent.deleteSecret ?? randomId("delete"))
      : consent.deleteSecret,
    consentVersion: CONSENT_VERSION,
    updatedAt: new Date().toISOString(),
  };
  await persistConsent();
  publishConsent();

  if (!authoritative.usageAnalytics) {
    deleteQueuedTelemetry();
    clearIngestToken();
  }

  if (authoritative.usageAnalytics) {
    trackUsageEvent("telemetry_consent_saved", {
      usageAnalytics: authoritative.usageAnalytics,
      crashReports: authoritative.crashReports,
    });
  }
}

/** Set the low-cardinality tier dimension for future envelopes. */
export function setTelemetryTier(tier: string) {
  const normalized = tier.trim().toLowerCase();
  reportedTier = KNOWN_TELEMETRY_TIERS.has(normalized) ? normalized : "unknown";
}

export function trackUsageEvent(
  name: UsageTelemetryEventName,
  properties?: Record<string, unknown>,
) {
  if (!consent.usageAnalytics || !USAGE_EVENT_NAMES.includes(name) || !consent.subjectId) return;
  const event: PendingUsageEvent = {
    id: randomId("event"),
    name,
    occurredAt: new Date().toISOString(),
    properties: sanitizeTelemetryProperties(properties),
  };
  writeQueuedUsageEvents([...readQueuedUsageEvents(), event].slice(-MAX_QUEUE_EVENTS));
  void flushTelemetryQueue();
}

export function trackDiagnosticEvent(
  name: DiagnosticTelemetryEventName,
  error: unknown,
  properties?: Record<string, unknown>,
) {
  if (
    !consent.crashReports ||
    !DIAGNOSTIC_EVENT_NAMES.includes(name) ||
    parseDsnHost(runtimeConfig.sentryDsn) !== SENTRY_INGEST_HOST
  ) {
    return;
  }
  const safeMessage =
    error instanceof Error
      ? sanitizeTelemetryText(error.message)
      : sanitizeTelemetryText(String(error ?? "Unknown diagnostic event"));
  const report: Extract<TelemetryRequest, { kind: "crashReport" }> = {
    kind: "crashReport",
    report: {
      name,
      message: safeMessage,
      stack: error instanceof Error && error.stack ? sanitizeDiagnosticStack(error.stack) : null,
      properties: sanitizeTelemetryProperties(properties),
      appVersion: APP_VERSION,
      buildChannel: BUILD_CHANNEL,
    },
  };
  void diagnosticSender({ args: report }).catch(() => {
    // Diagnostics are best effort and must never create a second app error.
  });
}

function sanitizeDiagnosticStack(stack: string): string {
  return stack
    .split("\n")
    .slice(0, 40)
    .map((line) => sanitizeTelemetryText(line))
    .filter(Boolean)
    .join("\n");
}

export function buildTelemetryPreview() {
  const exampleUsage = {
    schemaVersion: 1,
    kind: "usage",
    name: "workflow_event",
    appVersion: APP_VERSION,
    buildChannel: BUILD_CHANNEL,
    osFamily: detectOsFamily(),
    architecture: detectArchitecture(),
    tier: "free",
    anonymousSubjectId: consent.subjectId ?? "generated-after-opt-in",
    properties: {
      workflowName: "run_scan",
      workflowStatus: "succeeded",
      scanMode: "full",
      durationBucket: "10s-30s",
      criticalIssues: 0,
      highIssues: 2,
    },
  };
  const exampleDiagnostic = {
    tool: "Sentry",
    mode: "typed native SiteCMD report only",
    replay: "disabled",
    tracing: "disabled",
    pii: "disabled",
    event: {
      name: "frontend_error",
      message: sanitizeTelemetryText("Example error at https://example.com/path?token=abc"),
      metadata: {
        page: "dashboard",
        command: "get_dashboard_snapshot",
      },
    },
  };

  return [
    "SiteCMD Telemetry Preview",
    "",
    `Usage analytics: ${consent.usageAnalytics ? "on" : "off"}`,
    `Crash and error reports: ${consent.crashReports ? "on" : "off"}`,
    `Unsent usage events: ${readQueuedUsageEvents().length}`,
    "",
    "Example usage event:",
    JSON.stringify(exampleUsage, null, 2),
    "",
    "Example diagnostic event:",
    JSON.stringify(exampleDiagnostic, null, 2),
    "",
    "Never included: scan URLs, project names, source code, local file paths, credentials, license keys, raw logs, request bodies, or page content.",
  ].join("\n");
}

export function deleteQueuedTelemetry() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(QUEUE_STORAGE_KEY);
  } catch {
    // best effort
  }
}

export async function resetTelemetrySubject() {
  consent = {
    ...consent,
    subjectId: consent.usageAnalytics || consent.crashReports ? randomId("scmd") : null,
    deleteSecret: consent.usageAnalytics || consent.crashReports ? randomId("delete") : null,
    updatedAt: new Date().toISOString(),
  };
  deleteQueuedTelemetry();
  clearIngestToken();
  persistConsent();
  publishConsent();
}

export async function requestUploadedTelemetryDeletion(): Promise<"sent" | "not_configured"> {
  if (!runtimeConfig.telemetryEndpoint || !consent.subjectId || !consent.deleteSecret) {
    return "not_configured";
  }
  const response = await telemetryTransport(
    runtimeConfig.telemetryEndpoint.replace(/\/v1\/events\/?$/, "/v1/delete"),
    JSON.stringify({
      subjectId: consent.subjectId,
      deleteSecret: consent.deleteSecret,
    }),
  );
  if (!response.ok) {
    throw new Error(`Telemetry deletion failed with HTTP ${response.status}`);
  }
  clearIngestToken();
  return "sent";
}

/** Flush queued usage events through one non-rejecting flight. */
export async function flushTelemetryQueue(): Promise<void> {
  if (flushInFlight) return flushInFlight;
  flushInFlight = sendQueuedUsageEvents().finally(() => {
    flushInFlight = null;
  });
  return flushInFlight;
}

/** Drain server-sized batches, including events queued during an open request. */
async function sendQueuedUsageEvents(): Promise<void> {
  const endpoint = runtimeConfig.telemetryEndpoint;
  if (!endpoint || !consent.usageAnalytics || !consent.subjectId) return;

  for (;;) {
    const queued = readQueuedUsageEvents();
    if (queued.length === 0) return;
    const batch = queued.slice(0, MAX_EVENTS_PER_REQUEST);
    const delivered = await sendUsageEventBatch(endpoint, batch);
    // Preserve the queue after the first failed delivery.
    if (!delivered) return;
  }
}

/** One batch. Resolves true only when the server took it. */
async function sendUsageEventBatch(
  endpoint: string,
  events: PendingUsageEvent[],
): Promise<boolean> {
  try {
    const token = await ensureIngestToken(endpoint);
    if (!token) return false;
    const envelopes = await Promise.all(events.map(buildEnvelope));
    const response = await telemetryTransport(endpoint, JSON.stringify({ events: envelopes }), {
      headers: { Authorization: `Bearer ${token.token}` },
    });
    if (response.ok) {
      // Preserve events queued while this request was open.
      const sent = new Set(events.map((event) => event.id));
      writeQueuedUsageEvents(readQueuedUsageEvents().filter((event) => !sent.has(event.id)));
      return true;
    }
    if (response.status === 401 || response.status === 403) {
      clearIngestToken();
    }
    return false;
  } catch {
    // Offline delivery is expected; retain the batch for a later attempt.
    return false;
  }
}

export function __resetTelemetryForTests() {
  consentRevision += 1;
  consent = DEFAULT_CONSENT;
  runtimeConfig = {
    telemetryEndpoint: DEFAULT_TELEMETRY_ENDPOINT,
    sentryDsn: DEFAULT_SENTRY_DSN,
  };
  telemetryTransport = tauriTelemetryTransport;
  telemetryConsentAuthority = {
    get: getTelemetryConsent,
    set: setBackendTelemetryConsent,
  };
  diagnosticSender = sendTelemetryRequest;
  consentHydrationPromise = null;
  ingestToken = null;
  ingestTokenPromise = null;
  flushInFlight = null;
  reportedTier = "unknown";
  deleteQueuedTelemetry();
  clearIngestToken();
  void persistConsent();
  publishConsent();
}

export function __hydrateTelemetryConsentForTests(stored: Promise<unknown>) {
  return hydrateTelemetryConsent(stored);
}

export function __setTelemetryConfigForTests(config: {
  telemetryEndpoint?: string;
  sentryDsn?: string;
}) {
  runtimeConfig = {
    telemetryEndpoint: config.telemetryEndpoint ?? runtimeConfig.telemetryEndpoint,
    sentryDsn: config.sentryDsn ?? runtimeConfig.sentryDsn,
  };
}

export function __setTelemetryTransportForTests(transport: TelemetryTransport) {
  telemetryTransport = transport;
}

export function __setTelemetryConsentAuthorityForTests(authority: TelemetryConsentAuthority) {
  telemetryConsentAuthority = authority;
}

export function __setDiagnosticSenderForTests(sender: typeof sendTelemetryRequest) {
  diagnosticSender = sender;
}

function subscribeConsent(callback: () => void) {
  listeners.add(callback);
  return () => listeners.delete(callback);
}

function getConsentSnapshot() {
  return consent;
}

function publishConsent() {
  for (const listener of listeners) listener();
}

async function persistConsent() {
  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(consent));
    } catch {
      // best effort
    }
  }
  await storeSet(CONSENT_STORE_KEY, consent);
}

function loadConsentFromLocalStorage(): TelemetryConsentState {
  if (typeof window === "undefined") return DEFAULT_CONSENT;
  try {
    const raw = window.localStorage.getItem(CONSENT_STORAGE_KEY);
    if (!raw) return DEFAULT_CONSENT;
    return parseConsent(JSON.parse(raw) as unknown) ?? DEFAULT_CONSENT;
  } catch {
    return DEFAULT_CONSENT;
  }
}

async function hydrateTelemetryConsent(storedPromise: Promise<unknown>): Promise<void> {
  const revisionAtStart = consentRevision;
  const [storedValue, authoritative] = await Promise.all([
    storedPromise,
    readAuthoritativeConsent(),
  ]);
  // Only native consent authorizes uploads; local state owns display metadata.
  const stored = parseConsent(storedValue) ?? loadConsentFromLocalStorage();
  if (consentRevision !== revisionAtStart) return;

  const usageAnalytics = authoritative?.usageAnalytics ?? false;
  const crashReports = authoritative?.crashReports ?? false;
  const needsSubject = usageAnalytics || crashReports;
  consent = {
    ...stored,
    usageAnalytics,
    crashReports,
    subjectId: needsSubject ? (stored.subjectId ?? randomId("scmd")) : stored.subjectId,
    deleteSecret: needsSubject ? (stored.deleteSecret ?? randomId("delete")) : stored.deleteSecret,
    consentVersion: authoritative?.consentVersion ?? CONSENT_VERSION,
    updatedAt: authoritative?.updatedAt ?? stored.updatedAt,
  };
  await persistConsent();
  publishConsent();
}

async function readAuthoritativeConsent(): Promise<BackendTelemetryConsent | null> {
  try {
    return await telemetryConsentAuthority.get();
  } catch {
    return null;
  }
}

function parseConsent(value: unknown): TelemetryConsentState | null {
  if (!isJsonRecord(value)) return null;
  return {
    usageAnalytics: typeof value.usageAnalytics === "boolean" ? value.usageAnalytics : false,
    crashReports: typeof value.crashReports === "boolean" ? value.crashReports : false,
    promptStatus: value.promptStatus === "saved" ? "saved" : "unseen",
    subjectId: typeof value.subjectId === "string" && value.subjectId ? value.subjectId : null,
    deleteSecret:
      typeof value.deleteSecret === "string" && value.deleteSecret ? value.deleteSecret : null,
    consentVersion:
      typeof value.consentVersion === "number" ? value.consentVersion : CONSENT_VERSION,
    updatedAt: typeof value.updatedAt === "string" ? value.updatedAt : null,
  };
}

function readQueuedUsageEvents(): PendingUsageEvent[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(QUEUE_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const valid = parsed
      .flatMap((value) => parsePendingUsageEvent(value) ?? [])
      .filter((event) => queuedEventIsWithinAcceptanceWindow(event.occurredAt));
    const events = valid.slice(-MAX_QUEUE_EVENTS);
    // Persist only when validation removed stored entries.
    if (valid.length !== parsed.length) {
      writeQueuedUsageEvents(events);
    }
    return events;
  } catch {
    return [];
  }
}

function queuedEventIsWithinAcceptanceWindow(occurredAt: string): boolean {
  const timestamp = Date.parse(occurredAt);
  if (!Number.isFinite(timestamp)) return false;
  const now = Date.now();
  return (
    timestamp >= now - MAX_QUEUED_EVENT_AGE_MS && timestamp <= now + MAX_QUEUED_EVENT_FUTURE_SKEW_MS
  );
}

function parsePendingUsageEvent(value: unknown): PendingUsageEvent | null {
  if (
    !isJsonRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.occurredAt !== "string" ||
    !USAGE_EVENT_NAMES.includes(value.name as UsageTelemetryEventName) ||
    !isJsonRecord(value.properties)
  ) {
    return null;
  }
  return {
    id: value.id,
    name: value.name as UsageTelemetryEventName,
    occurredAt: value.occurredAt,
    properties: sanitizeTelemetryProperties(value.properties),
  };
}

function writeQueuedUsageEvents(events: PendingUsageEvent[]) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(QUEUE_STORAGE_KEY, JSON.stringify(events.slice(-MAX_QUEUE_EVENTS)));
  } catch {
    // best effort
  }
}

async function ensureIngestToken(endpoint: string): Promise<CachedIngestToken | null> {
  if (
    ingestToken &&
    ingestToken.subjectId === consent.subjectId &&
    Date.parse(ingestToken.expiresAt) > Date.now() + 60_000
  ) {
    return ingestToken;
  }
  if (!consent.subjectId || !consent.deleteSecret) return null;
  if (ingestTokenPromise) return ingestTokenPromise;

  ingestTokenPromise = (async () => {
    const deleteProofHash = await hashTelemetryText(consent.deleteSecret ?? "");
    const response = await telemetryTransport(
      endpoint.replace(/\/v1\/events\/?$/, "/v1/register"),
      JSON.stringify({
        subjectId: consent.subjectId,
        deleteProofHash,
      }),
    );
    if (!response.ok) return null;
    const body = (await response.json()) as unknown;
    if (
      !isJsonRecord(body) ||
      typeof body.token !== "string" ||
      typeof body.expiresAt !== "string"
    ) {
      return null;
    }
    const cached: CachedIngestToken = {
      token: body.token,
      expiresAt: body.expiresAt,
      subjectId: consent.subjectId ?? "",
    };
    if (!cached.subjectId || !Number.isFinite(Date.parse(cached.expiresAt))) return null;
    ingestToken = cached;
    return cached;
  })().finally(() => {
    ingestTokenPromise = null;
  });
  return ingestTokenPromise;
}

function clearIngestToken() {
  ingestToken = null;
  ingestTokenPromise = null;
}

async function buildEnvelope(event: PendingUsageEvent): Promise<TelemetryEnvelope> {
  const deleteProofHash = await hashTelemetryText(consent.deleteSecret ?? "");
  return {
    schemaVersion: 1,
    id: event.id,
    kind: "usage",
    name: event.name,
    occurredAt: event.occurredAt,
    appVersion: APP_VERSION,
    buildChannel: BUILD_CHANNEL,
    osFamily: detectOsFamily(),
    architecture: detectArchitecture(),
    tier: reportedTier,
    anonymousSubjectId: consent.subjectId ?? "missing",
    deleteProofHash,
    consentVersion: consent.consentVersion,
    properties: event.properties,
  };
}
