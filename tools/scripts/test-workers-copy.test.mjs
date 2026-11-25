import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

it.each([
  ["lib/test-workers.mjs", "df0046dc42763ad93a95b7a581e33a0d204cf1f0045388ca38ee84c9cd905b4b"],
  ["lib/test-workers.d.mts", "99844b330b3e4d0215488e0a37d8e9658c4f1294ac558b5fd7c6077d2ddc2989"],
  ["test-workers.test.mjs", "bbb7edbcc10741dffb98e0f07557543de6430266127c1552bbecb2ee118c2c66"],
])("keeps the SiteCMD-Connect copy of %s byte for byte", (file, expected) => {
  const source = readFileSync(new URL(file, import.meta.url));
  expect(createHash("sha256").update(source).digest("hex")).toBe(expected);
});
