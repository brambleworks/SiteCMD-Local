import assert from "node:assert/strict";
import { test } from "node:test";
import { DocumentFixture, DOMParserFixture } from "../guest/replacement-dom.mjs";

test("rendered fixture text preserves literals and decodes one entity layer", () => {
  const document = new DocumentFixture();
  const element = document.createElement("div");
  element.innerHTML = "Before &amp;lt; <br>middle < 5<p>after</p>";
  assert.equal(element.textContent, "Before &lt; \nmiddle < 5after\n");
});

test("parsed fixture documents omit excluded element content", () => {
  const document = new DOMParserFixture().parseFromString(
    "<p>safe</p><script>first<style>nested</style>last</script><div>kept < 5</div>",
  );
  assert.equal(document.querySelectorAll("script").length, 0);
  assert.equal(document.querySelectorAll("style").length, 0);
  assert.equal(document.body.textContent, "safekept < 5");
});
