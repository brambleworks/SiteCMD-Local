import { expect, it, vi } from "vitest";
import { workerCount } from "./lib/test-workers.mjs";

it("uses VITEST_MAX_WORKERS on CI", () => {
  expect(workerCount({ env: { CI: "1", VITEST_MAX_WORKERS: "2" } })).toBe(2);
});

it.each(["abc", "0", "2.5", undefined])(
  "falls back to 2 on CI for a missing or invalid count (%s)",
  (value) => {
    const env = value === undefined ? { CI: "1" } : { CI: "1", VITEST_MAX_WORKERS: value };
    expect(workerCount({ env })).toBe(2);
  },
);

it("leaves one core and the current load free locally", () => {
  expect(workerCount({ env: {}, cores: 8, load: 2.4 })).toBe(4);
  expect(workerCount({ env: {}, cores: 8, load: 5.1 })).toBe(2);
});

it("never drops below one worker under heavy load", () => {
  expect(workerCount({ env: {}, cores: 8, load: 27 })).toBe(1);
});

it("lets a local VITEST_MAX_WORKERS win", () => {
  expect(workerCount({ env: { VITEST_MAX_WORKERS: "6" }, cores: 8, load: 27 })).toBe(6);
});

it("rewrites an invalid process override and preserves an equivalent valid value", () => {
  vi.stubEnv("CI", undefined);
  vi.stubEnv("VITEST_MAX_WORKERS", "abc");
  try {
    const machine = { cores: 8, load: 5.1 };
    expect(workerCount(machine)).toBe(2);
    expect(process.env.VITEST_MAX_WORKERS).toBe("2");

    vi.stubEnv("VITEST_MAX_WORKERS", "02");
    expect(workerCount(machine)).toBe(2);
    expect(process.env.VITEST_MAX_WORKERS).toBe("02");
  } finally {
    vi.unstubAllEnvs();
  }
});
