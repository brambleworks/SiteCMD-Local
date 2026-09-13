import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const adapter = fileURLToPath(new URL("../guest/confirmatory-node-candidate.mjs", import.meta.url));

function probe(t, implementation) {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-owned-dom-fixture-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(
    path.join(root, "extension.ts"),
    `
    export class ExtensionComponent {
      extensionService = {};
      loadExtension(name) {
        const holder = this.customElementHolder.nativeElement;
        ${implementation}
      }
      ngOnChanges() { this.loadExtension(this.extension); }
    }
  `,
  );
  const result = spawnSync(process.execPath, [adapter], {
    input: JSON.stringify({
      operation: "yamcs-extension-element-construction",
      entry: "extension.ts",
    }),
    encoding: "utf8",
    timeout: 5000,
    env: {
      SITECMD_BENCHMARK_WORK_ROOT: root,
      SITECMD_BENCHMARK_TYPESCRIPT: require.resolve("typescript"),
    },
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("the extension grader accepts several valid DOM repair implementations", (t) => {
  for (const [clear, create, insert] of [
    ["holder.replaceChildren();", "document", "holder.appendChild(element);"],
    ["holder.textContent = '';", "holder.ownerDocument", "holder.replaceChildren(element);"],
    [
      "while (holder.firstChild) holder.removeChild(holder.firstChild);",
      "document",
      "holder.append(element);",
    ],
  ]) {
    const result = probe(
      t,
      `
      ${clear}
      if (!/^[a-z][a-z0-9]*-[a-z0-9-]+$/.test(name)) return;
      const element = ${create}.createElement(name);
      element.subroute = this.subroute;
      element.extensionService = this.extensionService;
      ${insert}
    `,
    );
    assert.deepEqual(result, {
      malformedNameRejected: true,
      markupInjectionPrevented: true,
      validElementCreated: true,
      extensionPropertiesPreserved: true,
      reloadBehaviorPreserved: true,
    });
  }
});

test("the extension grader rejects an unsafe repair and a broken valid-name path", (t) => {
  const unsafe = probe(t, "holder.innerHTML = '<' + name + '></' + name + '>';");
  assert.equal(unsafe.markupInjectionPrevented, false);
  const broken = probe(t, "holder.replaceChildren();");
  assert.equal(broken.markupInjectionPrevented, true);
  assert.equal(broken.validElementCreated, false);
});
