import assert from "node:assert/strict";
import { test } from "node:test";
import { extensionHolder } from "../guest/confirmatory-dom.mjs";

const setup = () => {
  const state = { active: false, innerHtmlWrites: [] };
  const document = { createElement: (tagName) => ({ tagName }) };
  return { state, document, holder: extensionHolder(state, document) };
};

test("extension probes support equivalent DOM clearing and insertion APIs", () => {
  for (const clear of [
    (holder) => holder.replaceChildren(),
    (holder) => {
      holder.textContent = "";
    },
    (holder) => {
      while (holder.firstChild) holder.removeChild(holder.firstChild);
    },
  ]) {
    const { holder, document } = setup();
    holder.append(document.createElement("old-widget"));
    clear(holder);
    const element = holder.ownerDocument.createElement("sample-widget");
    holder.appendChild(element);
    assert.equal(holder.children.length, 1);
    assert.equal(holder.childNodes.length, 1);
    assert.equal(holder.childNodes.item(0), element);
    assert.equal(holder.firstChild, element);
    assert.equal(holder.childNodes.item(1), null);
  }
});

test("replacing children retains properties without creating markup", () => {
  const { holder, state } = setup();
  const element = { tagName: "sample-widget", subroute: "details", extensionService: {} };
  holder.replaceChildren(element);
  assert.equal(holder.firstChild, element);
  holder.replaceChildren("<img onerror=probe>");
  assert.equal(holder.firstChild.nodeType, 3);
  assert.equal(state.active, false);
  assert.deepEqual(state.innerHtmlWrites, []);
});

test("the extension probe still detects unsafe markup insertion", () => {
  const { holder, state } = setup();
  holder.innerHTML = "<sample-widget></sample-widget><img onerror=probe>";
  assert.equal(state.active, true);
  assert.equal(state.innerHtmlWrites.length, 1);
});
