import assert from "node:assert/strict";
import { test } from "node:test";
import { candidateAdapterProfile } from "../guest/candidate-sandbox.mjs";

test("replacement graders always use the Node adapter with frozen support files", () => {
  const profile = candidateAdapterProfile({
    id: "bigflow-deploy-tls-verification",
    replacementAdapter: true,
    runtime: "python",
  });
  assert.equal(profile.node, true);
  assert.equal(profile.replacement, true);
  assert.equal(profile.adapter, "replacement-node-candidate.mjs");
  assert.deepEqual(profile.supportFiles, [
    "replacement-cases.mjs",
    "replacement-dom.mjs",
    "replacement-redirect-python.py",
    "replacement-redirect.mjs",
    "replacement-tls-python.py",
    "replacement-tls.mjs",
    "replacement-unsafe-html.mjs",
  ]);
});

test("replacement adapter selection does not alter existing runtime selection", () => {
  assert.equal(
    candidateAdapterProfile({ id: "ordinary-python", runtime: "python" }).adapter,
    "python-candidate.py",
  );
  assert.equal(
    candidateAdapterProfile({ id: "ordinary-node", runtime: "node" }).adapter,
    "node-candidate.mjs",
  );
  assert.equal(
    candidateAdapterProfile({ id: "tornado-static-redirect", runtime: "python" }).adapter,
    "tornado-candidate.py",
  );
});

test("OneKey uses a root judge with only its private candidate support files", () => {
  const profile = candidateAdapterProfile({
    id: "onekey-http-client-tls-verification",
    onekeyAdapter: true,
    runtime: "python",
  });
  assert.equal(profile.node, false);
  assert.equal(profile.onekey, true);
  assert.equal(profile.adapter, "replacement-onekey-probe.py");
  assert.deepEqual(profile.supportFiles, [
    "replacement-onekey-candidate.py",
    "replacement-onekey-fixtures.py",
  ]);
});

test("FMD delegates to its privileged browser controller", () => {
  const profile = candidateAdapterProfile({
    id: "fmd-device-text",
    fmdAdapter: true,
    runtime: "node",
  });
  assert.equal(profile.fmd, true);
  assert.equal(profile.node, true);
  assert.equal(profile.adapter, "replacement-fmd-controller.mjs");
  assert.deepEqual(profile.supportFiles, []);
});
