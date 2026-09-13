// Shared redaction boundary for usage telemetry and diagnostics.

export type PrimitiveTelemetryValue = string | number | boolean | null;

const MAX_META_KEYS = 16;
const MAX_TEXT_CHARS = 240;

const FORBIDDEN_PROPERTY_KEY_RE =
  /(?:url|uri|path|email|token|secret|password|license|api[_-]?key|webhook|source|code|body|payload|project[_-]?name|site[_-]?name|id$)/i;
const SECRET_TEXT_RE =
  /\b(?:authorization\s*:\s*bearer\s+|api[_-]?key\s*[:=]\s*|token\s*[:=]\s*|secret\s*[:=]\s*|license[_-]?key\s*[:=]\s*)["']?[^"',;\s]+/gi;

export function sanitizeTelemetryText(value: string): string {
  return value
    .replace(SECRET_TEXT_RE, "[secret]")
    .replace(/\b(?:ghp|github_pat|sk|rk|pk|xox[baprs]|AIza)[A-Za-z0-9_:-]{8,}\b/g, "[secret]")
    .replace(/https?:\/\/[^\s)]+/gi, "[url]")
    .replace(/\b(?:localhost|127\.0\.0\.1)(?::\d+)?\b/gi, "[local-url]")
    .replace(/\/(?:Users|home|var|tmp|private|Volumes)\/[^\s)]+/g, "[path]")
    .replace(/[A-Z]:\\[^\s)]+/g, "[path]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_TEXT_CHARS);
}

export function sanitizeTelemetryProperties(
  properties?: Record<string, unknown>,
): Record<string, PrimitiveTelemetryValue> {
  if (!properties) return {};
  const entries: Array<[string, PrimitiveTelemetryValue]> = [];
  for (const [key, value] of Object.entries(properties)) {
    if (FORBIDDEN_PROPERTY_KEY_RE.test(key)) continue;
    const sanitized = sanitizeTelemetryValue(value);
    if (sanitized === undefined) continue;
    entries.push([key, sanitized]);
    if (entries.length >= MAX_META_KEYS) break;
  }
  return Object.fromEntries(entries);
}

function sanitizeTelemetryValue(value: unknown): PrimitiveTelemetryValue | undefined {
  if (value == null) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "string") {
    const sanitized = sanitizeTelemetryText(value);
    return sanitized.length > 0 ? sanitized : null;
  }
  return undefined;
}

export async function hashTelemetryText(value: string): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }
  return sanitizeTelemetryText(value).slice(0, 32);
}

// deleteSecret is the only proof a client holds when it asks the ingest service
// to erase its telemetry, so a guessable id hands that erasure to whoever
// guesses it. Every branch draws from the platform CSPRNG and none falls back to
// arithmetic randomness, because a fallback is the branch an attacker picks.
export function randomId(prefix: string): string {
  const source: Crypto | undefined = typeof crypto === "undefined" ? undefined : crypto;
  if (!source) {
    throw new Error("randomId requires a Web Crypto implementation");
  }
  if (typeof source.randomUUID === "function") return `${prefix}_${source.randomUUID()}`;
  const bytes = source.getRandomValues(new Uint8Array(16));
  return `${prefix}_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function detectOsFamily(): string {
  if (typeof navigator === "undefined") return "unknown";
  const platform = navigator.platform.toLowerCase();
  if (platform.includes("mac")) return "macos";
  if (platform.includes("win")) return "windows";
  if (platform.includes("linux")) return "linux";
  return "unknown";
}

export function detectArchitecture(): string {
  if (typeof navigator === "undefined") return "unknown";
  return navigator.userAgent.includes("arm64") || navigator.userAgent.includes("aarch64")
    ? "arm64"
    : "unknown";
}
