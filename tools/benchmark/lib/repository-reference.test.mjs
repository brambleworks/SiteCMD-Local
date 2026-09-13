import assert from "node:assert/strict";
import { test } from "node:test";
import { deriveRepositoryReference, validateRepositoryReference } from "./repository-reference.mjs";
import { digest } from "./workflow-plan.mjs";

function source(commit, contents) {
  const data = {
    schemaVersion: 1,
    commit: commit.repeat(40),
    tree: commit.repeat(40),
    files: Object.entries(contents).map(([name, text]) => ({
      name,
      mode: name === "run.sh" ? "100755" : "100644",
      base64: Buffer.from(text).toString("base64"),
    })),
  };
  return { ...data, sha256: digest(data) };
}

test("Derived references retain baseline tests, licenses and modes without claiming an upstream tree", () => {
  const baseline = source("a", {
    "app.py": "unsafe",
    "test_app.py": "original test",
    LICENSE: "original license",
    "run.sh": "run",
  });
  const upstream = source("b", {
    "app.py": "safe",
    "test_app.py": "new test",
    LICENSE: "changed license",
    "run.sh": "run",
  });
  const reference = deriveRepositoryReference(baseline, upstream, ["app.py"]);
  assert.equal(reference.kind, "implementation-only");
  assert.equal(reference.commit, undefined);
  assert.equal(reference.tree, undefined);
  assert.equal(reference.baselineSha256, baseline.sha256);
  assert.equal(reference.upstreamSha256, upstream.sha256);
  assert.deepEqual(reference.files, [upstream.files[0], ...baseline.files.slice(1)]);
  const { sha256, ...content } = reference;
  assert.equal(sha256, digest(content));
});

test("Derived references reject missing, duplicate, empty or mode-changing edit scopes", () => {
  const baseline = source("a", { "app.py": "unsafe", "run.sh": "run" });
  const upstream = source("b", { "app.py": "safe", "new.py": "new" });
  for (const files of [[], ["absent"], ["new.py"], ["app.py", "app.py"], ["run.sh"]])
    assert.throws(() => deriveRepositoryReference(baseline, upstream, files), /scope/);
  const changedMode = source("c", { "app.py": "safe", "run.sh": "run" });
  changedMode.files[0].mode = "100755";
  const { sha256: _sha256, ...data } = changedMode;
  changedMode.sha256 = digest(data);
  assert.throws(() => deriveRepositoryReference(baseline, changedMode, ["app.py"]), /mode/);
});

test("Derived references copy only declared upstream regions", () => {
  const baseline = source("a", {
    "app.py": "import one\nimport three\n\nSTART\nunsafe\nEND\nunrelated baseline\n",
    LICENSE: "license",
  });
  const upstream = source("b", {
    "app.py": "import one\nimport two\nimport three\n\nSTART\nsafe\nEND\nunrelated upstream\n",
    LICENSE: "changed license",
  });
  const regions = [
    { file: "app.py", start: "import one\n", end: "import three\n" },
    { file: "app.py", start: "START\n", end: "END\n" },
  ];
  const reference = deriveRepositoryReference(baseline, upstream, ["app.py"], regions);
  assert.equal(reference.kind, "implementation-regions");
  assert.deepEqual(reference.regions, regions);
  assert.equal(
    Buffer.from(reference.files[0].base64, "base64").toString(),
    "import one\nimport two\nimport three\n\nSTART\nsafe\nEND\nunrelated baseline\n",
  );
  assert.deepEqual(reference.files[1], baseline.files[1]);
});

test("Reference validation rejects changed identities and malformed scopes", () => {
  const baseline = source("a", { "app.py": "unsafe", LICENSE: "license" });
  const upstream = source("b", { "app.py": "safe", LICENSE: "license" });
  const reference = deriveRepositoryReference(baseline, upstream, ["app.py"]);
  assert.equal(validateRepositoryReference(reference), reference);

  assert.throws(
    () => validateRepositoryReference({ ...reference, sha256: digest("changed") }),
    /identity/i,
  );
  const malformed = { ...reference, kind: "implementation-regions", regions: [] };
  const { sha256: _sha256, ...content } = malformed;
  malformed.sha256 = digest(content);
  assert.throws(() => validateRepositoryReference(malformed), /regions/i);
});
