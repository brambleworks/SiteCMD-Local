import fs from "node:fs";
import { expect, it } from "vitest";

it("supplies notary credentials and retains evidence even when platform signing fails", () => {
  const workflow = fs.readFileSync(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  const step = (name) => {
    const start = workflow.indexOf(`      - name: ${name}\n`);
    expect(start, name).toBeGreaterThan(-1);
    return workflow.slice(start, workflow.indexOf("\n      - ", start + 1));
  };
  const signer = step("Sign and package the CLI");
  expect(signer).toContain("APPLE_API_KEY_ID:");
  expect(signer).toContain("secrets.APPLE_API_KEY_ID");
  expect(signer).toContain("APPLE_API_ISSUER:");
  expect(signer).toContain("secrets.APPLE_API_ISSUER");
  const evidence = step("Preserve CLI notarization evidence");
  expect(evidence).toContain("always()");
  expect(evidence).toContain("startsWith(matrix.target, 'darwin')");
  expect(evidence).toContain("uses: actions/upload-artifact@");
  for (const name of ["submission.json", "submission-id.txt", "notary-log.json"]) {
    expect(evidence).toContain(`cli-notarization/${name}`);
  }
  expect(evidence).not.toContain("asc_api_key.p8");
});
