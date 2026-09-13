import { afterEach, describe, expect, it, vi } from "vitest";
import { randomId } from "./telemetry-scrub";

const UUID_ID = /^scmd_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("randomId", () => {
  it("draws from randomUUID when the platform offers it", () => {
    expect(randomId("scmd")).toMatch(UUID_ID);
  });

  // The delete secret is the only proof a client holds when it asks the ingest
  // service to erase its telemetry, so the branch taken when randomUUID is
  // missing has to be a CSPRNG too. A webview without randomUUID is exactly the
  // environment an attacker would rather we fell back to arithmetic in.
  it("falls back to getRandomValues rather than arithmetic randomness", () => {
    const getRandomValues = vi.fn((array: Uint8Array) => {
      array.fill(0xab);
      return array;
    });
    vi.stubGlobal("crypto", { getRandomValues });

    expect(randomId("delete")).toBe(`delete_${"ab".repeat(16)}`);
    expect(getRandomValues).toHaveBeenCalledTimes(1);
  });

  it("refuses to mint an id when no Web Crypto implementation exists", () => {
    vi.stubGlobal("crypto", undefined);

    expect(() => randomId("delete")).toThrow(/Web Crypto/);
  });

  it("never repeats an id across a batch", () => {
    const ids = new Set(Array.from({ length: 256 }, () => randomId("scmd")));

    expect(ids.size).toBe(256);
  });
});
